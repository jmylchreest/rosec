/*
 * pam_rosec.c — PAM module for unlocking rosec providers on login/screen-unlock.
 *
 * This module stashes the user's password during the `auth` phase and
 * replays it to `rosec-pam-unlock` during the `session` phase.  This
 * allows rosec vaults to be unlocked at initial login (where the session
 * bus becomes available between the two phases) and at screen unlock.
 *
 * The module follows the same pattern as pam_gnome_keyring.so:
 *   auth     phase: capture password via pam_get_item(PAM_AUTHTOK), stash it
 *   session  phase: retrieve stash, fork/exec the unlock helper with password
 *                   on stdin, wait for exit
 *   password phase: on password change, pass old+new passwords to the helper
 *                   in --chauthtok mode to update vault wrapping entries
 *
 * SAFETY PROPERTIES:
 *
 *   1. CANNOT block login:
 *      - All entry points return PAM_SUCCESS or PAM_IGNORE on any failure.
 *      - Never returns PAM_AUTH_ERR, PAM_SERVICE_ERR, or any error that
 *        would cause a login/unlock failure.
 *      - The PAM config line uses `optional`, providing defence-in-depth.
 *
 *   2. Password security:
 *      - Password is zeroized with explicit_bzero() + volatile barrier
 *        before free() in the cleanup callback.
 *      - Password never logged to syslog (only opaque status messages).
 *      - Password passed to helper via pipe stdin, never argv or env.
 *      - Pipe write-end closed immediately after write, signalling EOF.
 *
 *   3. Fork/exec safety:
 *      - Child closes all fds > STDERR before exec.
 *      - Child uses _exit() on error (not exit()) to avoid running atexit
 *        handlers from the parent.
 *      - SIGPIPE ignored during the fork/write/wait window.
 *      - SIGCHLD set to SIG_DFL so waitpid() works correctly.
 *      - Parent waits for child to prevent zombies.
 *
 *   4. Memory safety:
 *      - No unbounded allocations — only one strdup of the password.
 *      - All pipe fds tracked and closed on every exit path.
 *      - No buffer overflows — strlen-bounded operations only.
 *
 * Build:
 *   cc -shared -fPIC -O2 -Wall -Wextra -o pam_rosec.so pam_rosec.c -lpam
 *
 * Install:
 *   install -m755 pam_rosec.so /usr/lib/security/
 *
 * PAM config (/etc/pam.d/system-local-login or screen locker):
 *   auth      optional  pam_rosec.so
 *   session   optional  pam_rosec.so
 *   password  optional  pam_rosec.so
 *
 * Copyright (c) 2025 rosec contributors.  MIT license.
 */

#define _GNU_SOURCE  /* for explicit_bzero */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <grp.h>
#include <pwd.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* ── Configuration ────────────────────────────────────────────────── */

/*
 * Path to the rosec-pam-unlock binary.  This binary reads a password
 * from stdin (null-terminated), connects to rosecd over D-Bus, and
 * attempts to unlock all locked providers via pipe fd-passing.
 *
 * Override at compile time:
 *   cc -DROSEC_PAM_UNLOCK_PATH='"/custom/path"' ...
 */
#ifndef ROSEC_PAM_UNLOCK_PATH
#define ROSEC_PAM_UNLOCK_PATH "/usr/lib/rosec/rosec-pam-unlock"
#endif

/* Key for pam_set_data / pam_get_data stash */
#define STASH_KEY "rosec_pam_authtok"

/* Timeout for the helper process (seconds).  The helper self-exits
 * after this long to avoid lingering if rosecd is unresponsive. */
#define HELPER_TIMEOUT_SECS 30

/* ── Password zeroization ─────────────────────────────────────────── */

/*
 * Zeroize and free a password string.  Uses explicit_bzero (which the
 * compiler cannot elide) plus a volatile read barrier for defence in
 * depth against aggressive LTO.
 */
static void
zeroize_free(char *password)
{
    size_t len;
    volatile char *vp;

    if (!password)
        return;

    len = strlen(password);

    /* Primary: compiler-guaranteed zeroing */
    explicit_bzero(password, len);

    /* Secondary: volatile read barrier defeats any residual
     * optimisation that might skip the bzero. */
    vp = (volatile char *)password;
    while (len--)
        (void)*vp++;

    free(password);
}

/*
 * pam_set_data cleanup callback.  PAM calls this when the stash is
 * overwritten or when pam_end() runs (end of PAM transaction).
 */
static void
cleanup_stash(pam_handle_t *ph, void *data, int pam_end_status)
{
    (void)ph;
    (void)pam_end_status;
    zeroize_free((char *)data);
}

/* ── Pipe helper ──────────────────────────────────────────────────── */

static void
close_safe(int fd)
{
    if (fd >= 0)
        close(fd);
}

/*
 * Write `data` (with a trailing NUL, matching pam_exec expose_authtok
 * protocol) to the write end of a pipe and close it.  Returns 0 on
 * success, -1 on failure (write-end is always closed regardless).
 */
static int
write_password_to_pipe(int write_fd, const char *password)
{
    size_t len = strlen(password);
    const char nul = '\0';
    ssize_t written;

    /* Write the password bytes */
    while (len > 0) {
        written = write(write_fd, password, len);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(write_fd);
            return -1;
        }
        password += written;
        len -= (size_t)written;
    }

    /* Write trailing NUL (pam_exec convention) */
    while ((written = write(write_fd, &nul, 1)) < 0 && errno == EINTR)
        ;

    close(write_fd);
    return (written == 1) ? 0 : -1;
}

/* The forked child has a private fd table. Use kernel interfaces here
 * so a multithreaded PAM caller cannot leave a libc directory lock held. */
static int
close_inherited_fds(void)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, (unsigned int)STDERR_FILENO + 1, UINT_MAX, 0) == 0)
        return 0;
#endif

#ifdef SYS_getdents64
    /* Older kernels or filters can reject close_range. Enumerate the actual
     * descriptors, including ones above a subsequently lowered RLIMIT_NOFILE. */
    struct fd_dirent {
        uint64_t inode;
        int64_t offset;
        unsigned short reclen;
        unsigned char type;
        char name[];
    };
    _Alignas(struct fd_dirent) char buf[4096];
    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0)
        return -1;

    long count;
    do {
        count = syscall(SYS_getdents64, dir, buf, sizeof(buf));
        for (long pos = 0; pos < count;) {
            const struct fd_dirent *entry = (const void *)(buf + pos);
            int fd = 0;
            const char *digit = entry->name;
            for (; *digit >= '0' && *digit <= '9'; digit++) {
                if (fd > (INT_MAX - (*digit - '0')) / 10)
                    break;
                fd = fd * 10 + (*digit - '0');
            }
            if (*digit == '\0' && fd > STDERR_FILENO && fd != dir)
                close(fd);
            pos += entry->reclen;
        }
    } while (count > 0 || (count < 0 && errno == EINTR));

    close(dir);
    return count == 0 ? 0 : -1;
#else
    return -1;
#endif
}

/* ── Fork/exec the unlock helper (fire-and-forget) ────────────────── */

/*
 * Fork rosec-pam-unlock, pass the password on its stdin via pipe,
 * and return immediately without waiting.  The helper runs in the
 * background and unlocks providers asynchronously — the PAM caller
 * is never blocked.
 *
 * The child is double-forked so the intermediate process exits
 * immediately, allowing the PAM caller to reap it.  The grandchild
 * (the actual helper) is reparented to init/systemd and will not
 * become a zombie.
 */
static void
run_unlock_helper(const char *password, const char *username)
{
    int pipe_fds[2] = { -1, -1 };
    pid_t pid;
    struct sigaction sa_ign, sa_old_pipe;

    if (pipe(pipe_fds) < 0)
        return;

    /*
     * Ignore SIGPIPE so writing to a broken pipe doesn't kill the
     * login process.
     */
    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    sigaction(SIGPIPE, &sa_ign, &sa_old_pipe);

    pid = fork();

    if (pid < 0) {
        /* Fork failed */
        close_safe(pipe_fds[0]);
        close_safe(pipe_fds[1]);
        sigaction(SIGPIPE, &sa_old_pipe, NULL);
        return;
    }

    if (pid == 0) {
        /* ── Intermediate child — double-fork and exit ──────────── */

        pid_t grandchild = fork();
        if (grandchild < 0)
            _exit(1);

        if (grandchild > 0) {
            /* Intermediate exits immediately — grandchild is
             * reparented to init, no zombie possible. */
            _exit(0);
        }

        /* ── Grandchild — becomes the actual helper ─────────────── */

        /* Start a new session so we're fully detached from the
         * PAM caller's process group and terminal. */
        setsid();

        /* Restore default signal handlers */
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        /* Redirect pipe read-end to stdin */
        if (dup2(pipe_fds[0], STDIN_FILENO) < 0)
            _exit(1);

        /* Close all fds above stderr.  This prevents leaking parent
         * fds (D-Bus sockets, log files, etc.) into the helper. */
        if (close_inherited_fds() < 0)
            _exit(1);

        /* Redirect stdout/stderr to /dev/null.  The helper should
         * never produce visible output — all communication is via
         * exit code and D-Bus. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }

        /* Drop privileges before exec — display managers run PAM as root
         * and dbus-broker rejects root connections to user session buses. */
        if (getuid() == 0 && username) {
            struct passwd *pw = getpwnam(username);
            if (pw == NULL)
                _exit(1);
            if (initgroups(username, pw->pw_gid) < 0 ||
                setgid(pw->pw_gid) < 0 ||
                setuid(pw->pw_uid) < 0)
                _exit(1);
        }

        /*
         * Set PAM_USER in the child's environment so the helper can
         * derive the user's UID and locate the D-Bus session bus.
         * GDM's session worker runs as root and may not have
         * DBUS_SESSION_BUS_ADDRESS or XDG_RUNTIME_DIR set.
         */
        if (username)
            setenv("PAM_USER", username, 1);

        /*
         * Exec the helper.  argv[0] is the binary name, no other args.
         * Environment is inherited from the PAM caller, augmented with
         * PAM_USER above.
         */
        execl(ROSEC_PAM_UNLOCK_PATH, "rosec-pam-unlock", (char *)NULL);

        /* exec failed — _exit (not exit) to avoid atexit handlers */
        _exit(127);
    }

    /* ── Parent process (fire-and-forget) ───────────────────────── */

    /* Close the read end — only the grandchild reads from the pipe */
    close_safe(pipe_fds[0]);
    pipe_fds[0] = -1;

    /* Write the password and close the write end */
    write_password_to_pipe(pipe_fds[1], password);
    pipe_fds[1] = -1;  /* already closed by write_password_to_pipe */

    /* Reap the intermediate child (it exits immediately) */
    waitpid(pid, NULL, 0);

    /* Restore original signal handlers */
    sigaction(SIGPIPE, &sa_old_pipe, NULL);
}

/* ── PAM entry points ─────────────────────────────────────────────── */

/*
 * pam_sm_authenticate — `auth` phase.
 *
 * Capture the password from PAM_AUTHTOK (set by pam_unix or prior
 * modules).  We attempt to unlock immediately (for screen lockers that
 * never call pam_open_session), AND stash a copy for the session phase
 * as a fallback (for display managers like GDM that do call session).
 *
 * The helper is designed to fail silently if D-Bus isn't available yet
 * (e.g. during initial login), so trying here is always safe.
 *
 * ALWAYS returns PAM_SUCCESS or PAM_IGNORE — never blocks login.
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    const char *password = NULL;
    const char *username = NULL;
    char *stash = NULL;
    int ret;

    (void)flags;
    (void)argc;
    (void)argv;

    /* Get the password that was set by an earlier auth module
     * (typically pam_unix).  If no password is available, that's fine
     * — we just won't be able to unlock anything. */
    ret = pam_get_item(ph, PAM_AUTHTOK, (const void **)&password);
    if (ret != PAM_SUCCESS || password == NULL || password[0] == '\0')
        return PAM_SUCCESS;

    /* Get username for the helper */
    pam_get_item(ph, PAM_USER, (const void **)&username);

    /*
     * Fire-and-forget: launch the unlock helper in the background.
     * This handles screen lockers (hyprlock, swaylock, etc.) that
     * authenticate but never open a session.  The helper runs
     * asynchronously — PAM returns immediately and login is never
     * delayed.
     *
     * The helper will fail silently if D-Bus / rosecd aren't
     * available yet (initial login), which is fine.
     */
    run_unlock_helper(password, username);

    /*
     * Also stash a copy for the session phase.  Since the helper
     * runs asynchronously we cannot know if it succeeded, and for
     * initial login (GDM) the auth-phase helper may fail because
     * the session bus isn't up yet.  The session phase retries.
     */
    stash = strdup(password);
    if (!stash)
        return PAM_SUCCESS;  /* still don't block login */

    ret = pam_set_data(ph, STASH_KEY, stash, cleanup_stash);
    if (ret != PAM_SUCCESS) {
        zeroize_free(stash);
        return PAM_SUCCESS;
    }

    return PAM_SUCCESS;
}

/*
 * pam_sm_setcred — required by PAM but we have nothing to do.
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    (void)ph;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

/*
 * pam_sm_open_session — `session` phase.
 *
 * Retrieve the stashed password and pass it to rosec-pam-unlock.
 * By the time the session phase runs, the D-Bus session bus is
 * available (pam_systemd has set it up) and rosecd can be reached.
 *
 * ALWAYS returns PAM_SUCCESS or PAM_IGNORE — never blocks login.
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    const char *password = NULL;
    int ret;

    (void)flags;
    (void)argc;
    (void)argv;

    syslog(LOG_DEBUG, "pam_rosec: session phase entered");

    /* Retrieve the stashed password from the auth phase */
    ret = pam_get_data(ph, STASH_KEY, (const void **)&password);
    if (ret != PAM_SUCCESS || password == NULL || password[0] == '\0') {
        syslog(LOG_DEBUG, "pam_rosec: session phase — no stashed password (ret=%d, null=%d)",
               ret, password == NULL);
        return PAM_SUCCESS;
    }

    /* Get the username for the helper to derive the D-Bus bus path */
    const char *username = NULL;
    pam_get_item(ph, PAM_USER, (const void **)&username);

    syslog(LOG_DEBUG, "pam_rosec: session phase — got stashed password, launching helper for user=%s",
           username ? username : "(null)");

    /* Fire-and-forget: launch the unlock helper in the background.
     * The helper runs asynchronously — session setup is never delayed. */
    run_unlock_helper(password, username);

    /*
     * Clear the stash.  The cleanup callback zeroizes the old copy.
     * Passing NULL data with NULL cleanup removes the entry.
     */
    pam_set_data(ph, STASH_KEY, NULL, NULL);

    return PAM_SUCCESS;
}

/*
 * pam_sm_close_session — required by PAM but nothing to do.
 */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    (void)ph;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

/* ── Password change ─────────────────────────────────────────────── */

/*
 * Write two NUL-terminated password strings to a pipe fd, then close it.
 *
 * The helper reads: <old_password>\0<new_password>\0<EOF>.
 * Returns 0 on success, -1 on failure.  The fd is always closed.
 */
static int
write_two_passwords_to_pipe(int write_fd, const char *old_pw, const char *new_pw)
{
    /* Write old password + NUL */
    size_t old_len = strlen(old_pw);
    const char nul = '\0';
    ssize_t written;

    while (old_len > 0) {
        written = write(write_fd, old_pw, old_len);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(write_fd);
            return -1;
        }
        old_pw += written;
        old_len -= (size_t)written;
    }
    while ((written = write(write_fd, &nul, 1)) < 0 && errno == EINTR)
        ;
    if (written != 1) {
        close(write_fd);
        return -1;
    }

    /* Write new password + NUL */
    size_t new_len = strlen(new_pw);
    while (new_len > 0) {
        written = write(write_fd, new_pw, new_len);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(write_fd);
            return -1;
        }
        new_pw += written;
        new_len -= (size_t)written;
    }
    while ((written = write(write_fd, &nul, 1)) < 0 && errno == EINTR)
        ;

    close(write_fd);
    return (written == 1) ? 0 : -1;
}

/*
 * Fork rosec-pam-unlock in --chauthtok mode, passing old and new
 * passwords on stdin as two NUL-terminated strings.
 *
 * Protocol: the helper reads <old_password>\0<new_password>\0<EOF>.
 */
static void
run_chauthtok_helper(const char *old_password, const char *new_password,
                     const char *username)
{
    int pipe_fds[2] = { -1, -1 };
    pid_t pid;
    struct sigaction sa_ign, sa_old_pipe;

    if (pipe(pipe_fds) < 0)
        return;

    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    sigaction(SIGPIPE, &sa_ign, &sa_old_pipe);

    pid = fork();

    if (pid < 0) {
        close_safe(pipe_fds[0]);
        close_safe(pipe_fds[1]);
        sigaction(SIGPIPE, &sa_old_pipe, NULL);
        return;
    }

    if (pid == 0) {
        /* ── Intermediate child — double-fork and exit ──────────── */
        pid_t grandchild = fork();
        if (grandchild < 0)
            _exit(1);

        if (grandchild > 0)
            _exit(0);

        /* ── Grandchild — becomes the actual helper ─────────────── */
        setsid();
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        if (dup2(pipe_fds[0], STDIN_FILENO) < 0)
            _exit(1);

        if (close_inherited_fds() < 0)
            _exit(1);

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }

        /* Drop privileges (same reasoning as run_unlock_helper). */
        if (getuid() == 0 && username) {
            struct passwd *pw = getpwnam(username);
            if (pw == NULL)
                _exit(1);
            if (initgroups(username, pw->pw_gid) < 0 ||
                setgid(pw->pw_gid) < 0 ||
                setuid(pw->pw_uid) < 0)
                _exit(1);
        }

        if (username)
            setenv("PAM_USER", username, 1);

        execl(ROSEC_PAM_UNLOCK_PATH, "rosec-pam-unlock",
              "--chauthtok", (char *)NULL);
        _exit(127);
    }

    /* ── Parent process ────────────────────────────────────────── */
    close_safe(pipe_fds[0]);
    pipe_fds[0] = -1;

    write_two_passwords_to_pipe(pipe_fds[1], old_password, new_password);
    pipe_fds[1] = -1;  /* already closed */

    waitpid(pid, NULL, 0);
    sigaction(SIGPIPE, &sa_old_pipe, NULL);
}

/*
 * pam_sm_chauthtok — `password` phase (password change).
 *
 * Called when the user changes their login password (e.g. via `passwd`).
 * PAM calls this twice:
 *   1. PAM_PRELIM_CHECK — validate the old password (we skip this).
 *   2. PAM_UPDATE_AUTHTOK — perform the actual change.
 *
 * On PAM_UPDATE_AUTHTOK we retrieve both old and new passwords and
 * pass them to the rosec-pam-unlock helper in --chauthtok mode, which
 * calls ChangeProviderPassword on the daemon.  This updates the
 * wrapping entry in local vaults so the new login password can unlock
 * them.
 *
 * ALWAYS returns PAM_SUCCESS — never blocks password changes.
 */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    const char *old_password = NULL;
    const char *new_password = NULL;
    const char *username = NULL;

    (void)argc;
    (void)argv;

    /* Only act on the update phase, not the preliminary check. */
    if (flags & PAM_PRELIM_CHECK)
        return PAM_SUCCESS;

    /* Get the old password (PAM_OLDAUTHTOK) and new password (PAM_AUTHTOK). */
    if (pam_get_item(ph, PAM_OLDAUTHTOK, (const void **)&old_password) != PAM_SUCCESS
        || old_password == NULL || old_password[0] == '\0')
        return PAM_SUCCESS;

    if (pam_get_item(ph, PAM_AUTHTOK, (const void **)&new_password) != PAM_SUCCESS
        || new_password == NULL || new_password[0] == '\0')
        return PAM_SUCCESS;

    pam_get_item(ph, PAM_USER, (const void **)&username);

    syslog(LOG_DEBUG, "pam_rosec: chauthtok — launching helper for user=%s",
           username ? username : "(null)");

    run_chauthtok_helper(old_password, new_password, username);

    return PAM_SUCCESS;
}
