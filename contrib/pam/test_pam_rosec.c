/*
 * test_pam_rosec.c — Test harness for pam_rosec.so.
 *
 * Uses the real libpam API (pam_start, pam_authenticate, pam_open_session)
 * against fixture PAM configs that chain our mock auth module with
 * pam_rosec.so.  A mock unlock helper (mock_unlock_helper) stands in
 * for rosec-pam-unlock and writes the received password to a file for
 * verification.
 *
 * Tests:
 *   1. auth_stashes_password     — auth phase captures PAM_AUTHTOK
 *   2. session_sends_password    — session forks helper, password arrives
 *   3. session_without_auth      — session without prior auth is harmless
 *   4. auth_never_blocks         — auth always returns PAM_SUCCESS
 *   5. session_never_blocks      — session always returns PAM_SUCCESS
 *   6. stash_cleared_after_use   — password stash removed after session
 *
 * Build (from contrib/pam/):
 *   make test
 *
 * The test creates temporary PAM config files in a scratch directory
 * and points PAM at them via the service name.  Requires running as a
 * user who can write to /etc/pam.d/ (or use PAM_CONFDIR if available).
 *
 * For CI: run as root in a container, or use pam_wrapper (cwrap.org).
 */

#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <security/pam_appl.h>

/* ── Test infrastructure ──────────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name)                                          \
    do {                                                    \
        tests_run++;                                        \
        printf("  %-40s ", #name);                          \
        fflush(stdout);                                     \
        if (test_##name()) {                                \
            tests_passed++;                                 \
            printf("PASS\n");                               \
        } else {                                            \
            tests_failed++;                                 \
            printf("FAIL\n");                               \
        }                                                   \
    } while (0)

/* ── Globals set up by setup() ────────────────────────────────────── */

static char g_build_dir[1024];      /* directory containing .so and helper */
static char g_scratch_dir[256];     /* temp directory for PAM configs */
static char g_pam_conf_dir[256];    /* PAM config directory (= scratch_dir) */
static char g_mock_output[512];     /* path for mock helper output */
static const char *g_test_password = "correct-horse-battery-staple";

/* ── PAM conversation function ────────────────────────────────────── */

/*
 * Programmatic conversation callback.  Responds to PAM_PROMPT_ECHO_OFF
 * with our test password.  This simulates the user typing their password.
 */
static int
conv_func(int num_msg, const struct pam_message **msg,
          struct pam_response **resp, void *appdata_ptr)
{
    const char *password = (const char *)appdata_ptr;
    struct pam_response *reply;
    int i;

    reply = calloc((size_t)num_msg, sizeof(struct pam_response));
    if (!reply)
        return PAM_BUF_ERR;

    for (i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
            msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            reply[i].resp = strdup(password);
            if (!reply[i].resp) {
                free(reply);
                return PAM_BUF_ERR;
            }
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
}

/* ── Setup / teardown ─────────────────────────────────────────────── */

/*
 * Write a PAM service config file into our scratch directory.
 * The config chains: mock_auth -> pam_rosec.
 */
static int
write_pam_config(const char *service_name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_pam_conf_dir, service_name);

    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("fopen pam config");
        return -1;
    }

    fprintf(fp,
        "#%%PAM-1.0\n"
        "auth     required  %s/pam_mock_auth.so\n"
        "auth     optional  %s/pam_rosec.so\n"
        "session  optional  %s/pam_rosec.so\n",
        g_build_dir, g_build_dir, g_build_dir);

    fclose(fp);
    return 0;
}

static int
setup(void)
{
    /* Determine build directory (where the .so files are) */
    if (getcwd(g_build_dir, sizeof(g_build_dir)) == NULL) {
        perror("getcwd");
        return -1;
    }

    /* Create scratch directory for PAM configs */
    snprintf(g_scratch_dir, sizeof(g_scratch_dir),
             "/tmp/pam_rosec_test.%d", getpid());
    if (mkdir(g_scratch_dir, 0755) != 0) {
        perror("mkdir scratch");
        return -1;
    }

    /* PAM config directory — we use pam_start_confdir() to point at this */
    snprintf(g_pam_conf_dir, sizeof(g_pam_conf_dir), "%s", g_scratch_dir);

    /* Mock output file for the helper */
    snprintf(g_mock_output, sizeof(g_mock_output),
             "%s/helper_output", g_scratch_dir);
    setenv("MOCK_OUTPUT_FILE", g_mock_output, 1);

    /* Write PAM configs */
    if (write_pam_config("rosec-test") != 0)
        return -1;

    return 0;
}

static void
cleanup(void)
{
    /* Remove scratch directory contents.  g_scratch_dir is under /tmp
     * and we control its name, so this is safe. */
    char path[512];

    /* Remove files we know we created */
    snprintf(path, sizeof(path), "%s/rosec-test", g_scratch_dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/helper_output", g_scratch_dir);
    unlink(path);

    rmdir(g_scratch_dir);
}

/* ── Helper: read file contents ───────────────────────────────────── */

static char *
read_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return NULL;

    char *buf = calloc(1, 4096);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t n = fread(buf, 1, 4095, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

/* ── Helper: run a PAM transaction ────────────────────────────────── */

typedef struct {
    int auth_ret;
    int session_ret;
} pam_result_t;

static pam_result_t
run_pam_transaction(const char *service, const char *user,
                    const char *password, int do_auth, int do_session)
{
    pam_result_t result = { PAM_SUCCESS, PAM_SUCCESS };
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {
        .conv = conv_func,
        .appdata_ptr = (void *)password,
    };

    int ret = pam_start_confdir(service, user, &conv, g_pam_conf_dir, &pamh);
    if (ret != PAM_SUCCESS) {
        result.auth_ret = ret;
        result.session_ret = ret;
        return result;
    }

    if (do_auth)
        result.auth_ret = pam_authenticate(pamh, 0);

    if (do_session)
        result.session_ret = pam_open_session(pamh, 0);

    pam_end(pamh, 0);
    return result;
}

/* ── Tests ────────────────────────────────────────────────────────── */

/*
 * Test 1: auth phase returns PAM_SUCCESS.
 * pam_rosec should capture the password and return PAM_SUCCESS.
 */
static int
test_auth_returns_success(void)
{
    pam_result_t r = run_pam_transaction(
        "rosec-test", "nobody", g_test_password, 1, 0);
    return r.auth_ret == PAM_SUCCESS;
}

/*
 * Test 2: session phase sends password to helper, helper receives it.
 */
static int
test_session_sends_password(void)
{
    /* Remove old output file */
    unlink(g_mock_output);

    int initial = open("/dev/null", O_RDONLY);
    if (initial < 0)
        return 0;
    int high_fd = fcntl(initial, F_DUPFD, 1024);
    close(initial);
    if (high_fd < 0)
        return 0;

    char fd_text[32];
    snprintf(fd_text, sizeof(fd_text), "%d", high_fd);
    if (setenv("MOCK_CLOSED_FD", fd_text, 1) < 0) {
        close(high_fd);
        return 0;
    }

    pam_result_t r = run_pam_transaction(
        "rosec-test", "nobody", g_test_password, 1, 1);

    unsetenv("MOCK_CLOSED_FD");
    close(high_fd);

    if (r.auth_ret != PAM_SUCCESS || r.session_ret != PAM_SUCCESS)
        return 0;

    /* Give helper a moment to finish writing */
    usleep(200000);

    char *content = read_file(g_mock_output);
    if (!content)
        return 0;

    int ok = (strcmp(content, g_test_password) == 0);
    free(content);
    return ok;
}

/*
 * Test 3: session without prior auth does not crash or error.
 */
static int
test_session_without_auth(void)
{
    unlink(g_mock_output);

    pam_result_t r = run_pam_transaction(
        "rosec-test", "nobody", g_test_password, 0, 1);

    /* Session should succeed (PAM_SUCCESS) even without auth */
    if (r.session_ret != PAM_SUCCESS)
        return 0;

    /* Helper should NOT have been called (no stashed password) */
    char *content = read_file(g_mock_output);
    int ok = (content == NULL);  /* file should not exist */
    free(content);
    return ok;
}

/*
 * Test 4: auth always returns PAM_SUCCESS, never an error.
 */
static int
test_auth_never_blocks(void)
{
    /* Even with empty password, pam_rosec auth should return PAM_SUCCESS.
     * (The mock_auth module may fail, but pam_rosec is optional and
     * should always succeed.) */
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {
        .conv = conv_func,
        .appdata_ptr = (void *)g_test_password,
    };

    int ret = pam_start_confdir("rosec-test", "nobody", &conv, g_pam_conf_dir, &pamh);
    if (ret != PAM_SUCCESS)
        return 0;

    /* Call authenticate — mock_auth sets AUTHTOK, pam_rosec stashes it.
     * Both should succeed. */
    ret = pam_authenticate(pamh, 0);
    pam_end(pamh, 0);

    return (ret == PAM_SUCCESS);
}

/*
 * Test 5: session always returns PAM_SUCCESS.
 */
static int
test_session_never_blocks(void)
{
    /* Full transaction with auth + session */
    pam_result_t r = run_pam_transaction(
        "rosec-test", "nobody", g_test_password, 1, 1);
    return (r.session_ret == PAM_SUCCESS);
}

/*
 * Test 6: after session, the stash is cleared.
 * We verify by checking that a second session call (without re-auth)
 * does not invoke the helper.
 */
static int
test_stash_cleared_after_session(void)
{
    unlink(g_mock_output);

    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {
        .conv = conv_func,
        .appdata_ptr = (void *)g_test_password,
    };

    int ret = pam_start_confdir("rosec-test", "nobody", &conv, g_pam_conf_dir, &pamh);
    if (ret != PAM_SUCCESS)
        return 0;

    /* Auth + first session (should invoke helper) */
    ret = pam_authenticate(pamh, 0);
    if (ret != PAM_SUCCESS) {
        pam_end(pamh, 0);
        return 0;
    }

    ret = pam_open_session(pamh, 0);
    if (ret != PAM_SUCCESS) {
        pam_end(pamh, 0);
        return 0;
    }

    usleep(200000);

    /* Verify helper was called */
    char *content = read_file(g_mock_output);
    if (!content || strcmp(content, g_test_password) != 0) {
        free(content);
        pam_end(pamh, 0);
        return 0;
    }
    free(content);

    /* Remove output and do second session (stash should be cleared) */
    unlink(g_mock_output);

    ret = pam_open_session(pamh, 0);
    if (ret != PAM_SUCCESS) {
        pam_end(pamh, 0);
        return 0;
    }

    usleep(200000);

    /* Helper should NOT have been called again */
    content = read_file(g_mock_output);
    int ok = (content == NULL);
    free(content);

    pam_end(pamh, 0);
    return ok;
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void)
{
    printf("pam_rosec test suite\n");
    printf("====================\n\n");

    if (setup() != 0) {
        fprintf(stderr, "setup failed\n");
        cleanup();
        return 1;
    }

    /* Verify build artifacts exist */
    if (access("pam_rosec.so", F_OK) != 0) {
        fprintf(stderr, "pam_rosec.so not found — run 'make' first\n");
        cleanup();
        return 1;
    }
    if (access("pam_mock_auth.so", F_OK) != 0) {
        fprintf(stderr, "pam_mock_auth.so not found — run 'make test' to build\n");
        cleanup();
        return 1;
    }
    if (access("mock_unlock_helper", F_OK) != 0) {
        fprintf(stderr, "mock_unlock_helper not found — run 'make test' to build\n");
        cleanup();
        return 1;
    }

    printf("Build dir:    %s\n", g_build_dir);
    printf("Scratch dir:  %s\n", g_scratch_dir);
    printf("PAM confdir:  %s\n", g_pam_conf_dir);
    printf("\n");

    TEST(auth_returns_success);
    TEST(session_sends_password);
    TEST(session_without_auth);
    TEST(auth_never_blocks);
    TEST(session_never_blocks);
    TEST(stash_cleared_after_session);

    printf("\n%d tests: %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);

    cleanup();
    return tests_failed > 0 ? 1 : 0;
}
