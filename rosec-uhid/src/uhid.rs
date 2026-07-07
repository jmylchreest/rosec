//! Minimal `/dev/uhid` codec — just the events a FIDO authenticator needs.
//!
//! We encode the events by hand rather than depend on a third-party uhid
//! crate because the device this creates is security-sensitive: the HID
//! report descriptor is hard-coded to the FIDO usage page so the broker can
//! never be coerced into creating a keyboard or other input device. Keeping
//! the bytes here, unit-tested, makes that property auditable.
//!
//! Protocol (see `linux/uhid.h`): userspace writes `uhid_event` structs to
//! the fd to create the device and to send input reports (`UHID_INPUT2`);
//! the kernel writes events back (`UHID_OUTPUT` carries a report the host
//! sent us). Every event begins with a little-endian `u32` type tag.

/// `HID_MAX_DESCRIPTOR_SIZE` / report data size from `linux/uhid.h`.
const RD_DATA_MAX: usize = 4096;
const NAME_MAX: usize = 128;
const PHYS_MAX: usize = 64;
const UNIQ_MAX: usize = 64;

// uhid event type tags (`enum uhid_event_type`).
const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;

const BUS_USB: u16 = 0x03;

/// FIDO HID report descriptor: usage page `0xF1D0` (FIDO Alliance), usage
/// `0x01` (U2F/CTAP authenticator), one 64-byte Input report and one 64-byte
/// Output report — the CTAPHID transport. This is the *entire* device
/// capability; there is no keyboard/pointer usage here, by construction.
///
/// Bytes are the canonical CTAPHID descriptor from the CTAP spec.
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01, // Usage (U2F HID Authenticator Device)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Var, Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Var, Abs)
    0xC0, // End Collection
];

/// Vendor/product identifying a rosec virtual authenticator. Not a real
/// USB-IF allocation; used only for display and log correlation.
pub const ROSEC_VENDOR: u32 = 0x1209; // pid.codes (community/prototype VID)
pub const ROSEC_PRODUCT: u32 = 0x0053; // "S" — rosec
pub const ROSEC_DEVICE_NAME: &str = "rosec virtual authenticator";

fn copy_fixed(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
}

/// Encode a `UHID_CREATE2` event with the hard-coded FIDO descriptor. The
/// resulting bytes are written to `/dev/uhid` to materialise the device.
pub fn create2_event() -> Vec<u8> {
    // Layout of `struct uhid_create2_req` (packed), prefixed by the u32 type.
    let mut buf = Vec::with_capacity(4 + NAME_MAX + PHYS_MAX + UNIQ_MAX + 20 + RD_DATA_MAX);
    buf.extend_from_slice(&UHID_CREATE2.to_ne_bytes());

    let mut name = [0u8; NAME_MAX];
    copy_fixed(&mut name, ROSEC_DEVICE_NAME.as_bytes());
    buf.extend_from_slice(&name);
    buf.extend_from_slice(&[0u8; PHYS_MAX]);
    buf.extend_from_slice(&[0u8; UNIQ_MAX]);

    buf.extend_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_ne_bytes()); // rd_size
    buf.extend_from_slice(&BUS_USB.to_ne_bytes()); // bus
    buf.extend_from_slice(&ROSEC_VENDOR.to_ne_bytes()); // vendor
    buf.extend_from_slice(&ROSEC_PRODUCT.to_ne_bytes()); // product
    buf.extend_from_slice(&1u32.to_ne_bytes()); // version
    buf.extend_from_slice(&0u32.to_ne_bytes()); // country

    let mut rd = [0u8; RD_DATA_MAX];
    copy_fixed(&mut rd, FIDO_REPORT_DESCRIPTOR);
    buf.extend_from_slice(&rd);
    buf
}

/// Encode a `UHID_DESTROY` event (tears the device down; closing the fd does
/// this implicitly, so this is only for a clean explicit shutdown).
pub fn destroy_event() -> Vec<u8> {
    UHID_DESTROY.to_ne_bytes().to_vec()
}

/// Encode a `UHID_INPUT2` event carrying a device→host report (one CTAPHID
/// 64-byte frame). Layout: `u32 type` + `u16 size` + `data[size]`.
pub fn input2_event(report: &[u8]) -> Vec<u8> {
    let size = report.len().min(RD_DATA_MAX);
    let mut buf = Vec::with_capacity(4 + 2 + size);
    buf.extend_from_slice(&UHID_INPUT2.to_ne_bytes());
    buf.extend_from_slice(&(size as u16).to_ne_bytes());
    buf.extend_from_slice(&report[..size]);
    buf
}

/// A parsed inbound uhid event (kernel→userspace) that the frontend cares
/// about. Housekeeping events collapse to [`Event::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The host sent us a report (a CTAPHID frame) — `UHID_OUTPUT`.
    Output(Vec<u8>),
    /// The host opened the device (a client is listening).
    Open,
    /// The host closed the device.
    Close,
    /// Start/stop/other lifecycle events we acknowledge but don't act on.
    Other(u32),
}

/// Decode one inbound event from a buffer read off the uhid fd. Returns
/// `None` if the buffer is too short to carry a type tag.
pub fn parse_event(buf: &[u8]) -> Option<Event> {
    if buf.len() < 4 {
        return None;
    }
    let ty = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    match ty {
        UHID_OUTPUT => {
            // `struct uhid_output_req { __u8 data[4096]; __u16 size; __u8 rtype; }`
            // The size field sits AFTER the data array in the packed struct.
            let data_start = 4;
            let size_at = data_start + RD_DATA_MAX;
            if buf.len() < size_at + 2 {
                return Some(Event::Output(Vec::new()));
            }
            let size = u16::from_ne_bytes([buf[size_at], buf[size_at + 1]]) as usize;
            let n = size.min(RD_DATA_MAX);
            Some(Event::Output(buf[data_start..data_start + n].to_vec()))
        }
        UHID_OPEN => Some(Event::Open),
        UHID_CLOSE => Some(Event::Close),
        UHID_START | UHID_STOP => Some(Event::Other(ty)),
        other => Some(Event::Other(other)),
    }
}

/// Size of the fixed inbound event buffer to read from the uhid fd — large
/// enough for the biggest event (`UHID_OUTPUT`).
pub const EVENT_BUF_SIZE: usize = 4 + RD_DATA_MAX + 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_fido_usage_page_only() {
        // Usage Page must be FIDO (0xF1D0) and there must be no keyboard
        // (0x07) or generic-desktop-pointer (0x01 as a *usage page*) marker.
        assert_eq!(&FIDO_REPORT_DESCRIPTOR[0..3], &[0x06, 0xD0, 0xF1]);
        // Exactly one Input(0x81) and one Output(0x91) report item.
        let inputs = FIDO_REPORT_DESCRIPTOR
            .windows(2)
            .filter(|w| w == b"\x81\x02")
            .count();
        let outputs = FIDO_REPORT_DESCRIPTOR
            .windows(2)
            .filter(|w| w == b"\x91\x02")
            .count();
        assert_eq!(inputs, 1);
        assert_eq!(outputs, 1);
    }

    #[test]
    fn create2_event_layout() {
        let ev = create2_event();
        // type tag
        assert_eq!(&ev[0..4], &UHID_CREATE2.to_ne_bytes());
        // name is at offset 4
        assert!(ev[4..].starts_with(ROSEC_DEVICE_NAME.as_bytes()));
        // rd_size field sits right after name+phys+uniq
        let rd_size_at = 4 + NAME_MAX + PHYS_MAX + UNIQ_MAX;
        let rd_size = u16::from_ne_bytes([ev[rd_size_at], ev[rd_size_at + 1]]);
        assert_eq!(rd_size as usize, FIDO_REPORT_DESCRIPTOR.len());
        // full struct length: type(4) + name + phys + uniq +
        // rd_size(2)+bus(2)+vendor(4)+product(4)+version(4)+country(4)=20 + rd_data
        assert_eq!(
            ev.len(),
            4 + NAME_MAX + PHYS_MAX + UNIQ_MAX + 20 + RD_DATA_MAX
        );
    }

    #[test]
    fn input2_roundtrips_report() {
        let report = vec![0xAAu8; 64];
        let ev = input2_event(&report);
        assert_eq!(&ev[0..4], &UHID_INPUT2.to_ne_bytes());
        let size = u16::from_ne_bytes([ev[4], ev[5]]);
        assert_eq!(size, 64);
        assert_eq!(&ev[6..6 + 64], &report[..]);
    }

    #[test]
    fn parse_output_event_extracts_report() {
        // Build a synthetic UHID_OUTPUT: type + data[4096] + size + rtype.
        let mut buf = Vec::new();
        buf.extend_from_slice(&UHID_OUTPUT.to_ne_bytes());
        let mut data = vec![0u8; RD_DATA_MAX];
        data[..4].copy_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(&data);
        buf.extend_from_slice(&4u16.to_ne_bytes()); // size
        buf.push(2); // rtype
        match parse_event(&buf) {
            Some(Event::Output(r)) => assert_eq!(r, vec![1, 2, 3, 4]),
            other => panic!("expected Output, got {other:?}"),
        }
    }

    #[test]
    fn parse_lifecycle_events() {
        assert_eq!(parse_event(&UHID_OPEN.to_ne_bytes()), Some(Event::Open));
        assert_eq!(parse_event(&UHID_CLOSE.to_ne_bytes()), Some(Event::Close));
        assert_eq!(parse_event(&[0, 1]), None);
    }
}
