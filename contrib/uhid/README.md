# rosec virtual authenticator (uhid) — deployment

The `rosec-uhid` is the **privileged, disposable** half of rosec's
virtual FIDO2 authenticator. It exists so the unprivileged rosec daemon can
present a CTAP2 security key over `/dev/uhid` without ever running as root.
See [`design/fido2-uhid.md`](../../design/fido2-uhid.md) for the full design,
and [the user guide](../../docs/docs/fido2-passkeys.md) for setup and usage.

## Why a system service (not the rosecd user unit)

`/dev/uhid` is `0600 root:root` on purpose — unrestricted uhid access can
create virtual keyboards (an input-injection primitive). Creating the device
therefore needs root, but nothing else does. The broker is a **system**
service that runs only long enough to:

1. accept a connection and read the caller's uid via `SO_PEERCRED`
   (never from the message body),
2. open `/dev/uhid` and create a device with a **hard-coded** FIDO
   usage-page descriptor — it cannot be asked to create a keyboard,
3. chown the resulting `/dev/hidrawN` to the caller at `0600`,
4. pass the device fd back over `SCM_RIGHTS`, and exit.

The rosecd user unit is unsuitable: it runs as the user and cannot open
`/dev/uhid`.

## Install

On Arch, prefer the `rosec-uhid-bin` AUR package, which installs all of this.
By hand:

```sh
install -Dm755 rosec-uhid            /usr/bin/rosec-uhid
install -Dm644 rosec-uhid.socket     /usr/lib/systemd/system/rosec-uhid.socket
install -Dm644 rosec-uhid.service    /usr/lib/systemd/system/rosec-uhid.service
install -Dm644 modules-load.conf     /usr/lib/modules-load.d/rosec-uhid.conf
install -Dm644 69-rosec-uhid.rules   /usr/lib/udev/rules.d/69-rosec-uhid.rules
systemctl enable --now rosec-uhid.socket
```

`/dev/uhid` only exists once the `uhid` module is loaded. The `modules-load.d`
file loads it at boot; the broker cannot load it itself (its unit sets
`ProtectKernelModules=yes`). To use it immediately: `modprobe uhid`.

## hidraw ownership

The broker chowns the created node to the requesting uid at `0600`, so only
that user can reach their authenticator.

That chown is **not sufficient on its own**, and the shipped
`69-rosec-uhid.rules` is required alongside it. The device advertises the FIDO
usage page by design, so the stock `60-fido-id.rules` sets
`ID_SECURITY_TOKEN=1` and `70-uaccess.rules` then tags it `uaccess` — which
makes systemd-logind attach a POSIX ACL granting the **active-seat** user
read/write, *in addition to* the owner. On a multi-user or fast-user-switching
host that hands another local user access to the node, and logind re-applies
it on every session change, so a one-time `chmod` cannot hold it off.

`69-rosec-uhid.rules` (installed to `/usr/lib/udev/rules.d/`) clears
`ID_SECURITY_TOKEN` for rosec's device before `70-uaccess.rules` runs, so the
ACL is never applied. It is matched by rosec's fixed HID vendor:product
(`0003:1209:0053`), which only the root broker can create. Verify a granted
node has no extra ACL entry:

```sh
getfacl /dev/hidrawN   # should show only the owner, no named-user uaccess entry
```
