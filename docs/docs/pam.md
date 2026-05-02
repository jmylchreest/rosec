# PAM Auto-Unlock

rosec ships a native PAM module (`pam_rosec.so`) that captures your login
password during the `auth` phase, then passes it to `rosec-pam-unlock` during
the `session` phase (when the D-Bus session bus is available). This means
your providers unlock automatically at both **initial login** and
**screen unlock** — just like gnome-keyring does.

The module also handles **password changes** (`passwd`): when the `password`
PAM phase fires, it sends the old and new passwords to the daemon, which
updates local vault wrapping entries automatically.

## Setup

**1.** Install the PAM module and helper:

```bash
# From the AUR package (installed automatically):
#   /usr/lib/security/pam_rosec.so
#   /usr/lib/rosec/rosec-pam-unlock
#   /etc/pam.d/rosec

# Or build manually:
cd contrib/pam && make && sudo make install
```

**2.** If your login password differs from your vault master password, add it
as a wrapping entry:

```bash
rosec provider add-password <vault-id> --label pam
```

Enter your **login password** when prompted. If it matches your vault master
password, skip this step.

**3.** Add rosec to your PAM config. A drop-in snippet is installed at
`/etc/pam.d/rosec` — include it from whichever PAM service you use.

### Login + screen lock (recommended)

```
# /etc/pam.d/system-local-login — add at the end:
auth      include   rosec
session   include   rosec
password  include   rosec
```

This covers GDM, SDDM, console login, and screen lockers that include the
`login` chain (hyprlock, swaylock, etc.). Do **not** add rosec to
`/etc/pam.d/system-login` — that file is also used by SSH and other remote
services where there is no D-Bus session bus.

### Screen locker only

Most screen lockers include `system-local-login` under the hood, so the above
is usually sufficient. If yours doesn't, add rosec directly:

```
# /etc/pam.d/<locker> — add after the existing auth line:
auth     include   rosec
session  include   rosec
```

| Screen locker | PAM config |
|---|---|
| hyprlock | `/etc/pam.d/hyprlock` |
| swaylock | `/etc/pam.d/swaylock` |
| i3lock | `/etc/pam.d/i3lock` |
| GDM | `/etc/pam.d/gdm-password` |
| SDDM | `/etc/pam.d/sddm` |

### Fallback: pam_exec (no native module)

If you prefer not to install `pam_rosec.so`, the helper works standalone
via `pam_exec`. This only works for **screen unlock** (not initial login,
because the session bus doesn't exist yet during the `auth` phase):

```
# /etc/pam.d/hyprlock — after auth:
auth  optional  pam_exec.so  expose_authtok quiet /usr/lib/rosec/rosec-pam-unlock
```

## Security

- **Cannot block login:** `pam_rosec.so` returns `PAM_SUCCESS` on every
  error path — stash failure, fork failure, helper timeout, helper crash.
  The PAM config line uses `optional` as defence-in-depth.
- **Password zeroization:** The stashed password is zeroized with
  `explicit_bzero()` + volatile barrier on cleanup (PAM transaction end,
  stash overwrite, or explicit clear after use).
- **Password sent via pipe:** Never appears as a D-Bus message, argv
  argument, or environment variable. `rosec-pam-unlock` reads from stdin,
  passes to `rosecd` via pipe fd (SCM_RIGHTS).
- **Fire-and-forget:** The helper runs in the background (double-forked).
  Login and screen unlock are never delayed.
- **Minimal attack surface:** The `.so` is 17 KB of C with no runtime
  dependencies beyond libc and libpam. All crypto and D-Bus logic lives
  in the separate `rosec-pam-unlock` binary.
- **Process isolation:** All fds above stderr are closed in the child
  before exec. stdout/stderr are redirected to `/dev/null`.
