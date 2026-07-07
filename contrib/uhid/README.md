# rosec virtual authenticator (uhid) — deployment

The `rosec-uhid` is the **privileged, disposable** half of rosec's
virtual FIDO2 authenticator. It exists so the unprivileged rosec daemon can
present a CTAP2 security key over `/dev/uhid` without ever running as root.
See [`docs/developers/fido2-passkeys.md`](../../docs/docs/developers/fido2-passkeys.md)
for the full design.

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

```sh
install -Dm755 rosec-uhid            /usr/bin/rosec-uhid
install -Dm644 rosec-uhid.socket     /usr/lib/systemd/system/rosec-uhid.socket
install -Dm644 rosec-uhid.service    /usr/lib/systemd/system/rosec-uhid.service
systemctl enable --now rosec-uhid.socket
```

## hidraw ownership

The broker chowns the created node to the requesting uid at `0600`. This is
deliberately **not** left to the stock `fido_id` + `uaccess` rule, which
grants the node to the active *seat* session — wrong for a seatless virtual
device on a multi-user host (another logged-in user could enumerate it).

If you prefer a udev rule over the broker's own chown (e.g. for auditing),
key it on rosec's vendor/product rather than the generic FIDO usage page, so
it only ever matches rosec's own device:

```udev
# /etc/udev/rules.d/70-rosec-uhid.rules
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="0053", \
    TAG+="uaccess"
```

Note the udev rule cannot know the *requesting* uid, so the broker's
per-uid chown is the more precise mechanism on multi-user systems; the udev
rule falls back to seat-scoped `uaccess`.
