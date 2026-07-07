//! CTAPHID transport framing — the layer between raw 64-byte HID reports and
//! CTAP2 CBOR messages.
//!
//! A CTAPHID *message* (a command + payload) is split across 64-byte HID
//! *reports*: one initialization packet then zero or more continuation
//! packets. This module assembles inbound reports into messages and splits
//! outbound messages into reports. It is pure byte manipulation — no I/O, no
//! device — so it is fully unit-tested here; the daemon feeds it the reports
//! the broker's fd delivers.
//!
//! Frame layout (report size 64):
//! - Init packet:  `CID(4) | CMD|0x80 (1) | BCNTH (1) | BCNTL (1) | data(57)`
//! - Cont packet:  `CID(4) | SEQ (1) | data(59)`
//!
//! See the CTAP spec, "USB HID transport".

/// HID report size for CTAPHID (fixed by the descriptor).
pub const REPORT_SIZE: usize = 64;
const INIT_DATA: usize = REPORT_SIZE - 7;
const CONT_DATA: usize = REPORT_SIZE - 5;

/// The broadcast channel used before a channel is allocated.
pub const CID_BROADCAST: u32 = 0xFFFF_FFFF;

/// Maximum message payload we will assemble. CTAP messages are small; cap to
/// bound memory against a malformed BCNT.
pub const MAX_MESSAGE_LEN: usize = 7609; // CTAPHID spec maximum

// CTAPHID command bytes (high bit set on the wire for init packets).
pub const CTAPHID_PING: u8 = 0x01;
pub const CTAPHID_MSG: u8 = 0x03;
pub const CTAPHID_INIT: u8 = 0x06;
pub const CTAPHID_CBOR: u8 = 0x10;
pub const CTAPHID_CANCEL: u8 = 0x11;
pub const CTAPHID_KEEPALIVE: u8 = 0x3B;
pub const CTAPHID_ERROR: u8 = 0x3F;

/// CTAPHID error codes (payload of a `CTAPHID_ERROR` frame).
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_OTHER: u8 = 0x7F;

/// KEEPALIVE status byte sent while a user prompt is pending, so the browser
/// waits instead of timing out.
pub const KEEPALIVE_UPNEEDED: u8 = 0x02;

/// A fully-assembled inbound CTAPHID message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub cid: u32,
    pub cmd: u8,
    pub data: Vec<u8>,
}

/// Split a message into 64-byte reports for transmission to the host. The
/// caller writes each returned report as one `UHID_INPUT2` event.
pub fn split_message(msg: &Message) -> Vec<[u8; REPORT_SIZE]> {
    let mut reports = Vec::new();
    let total = msg.data.len();

    let mut init = [0u8; REPORT_SIZE];
    init[0..4].copy_from_slice(&msg.cid.to_be_bytes());
    init[4] = msg.cmd | 0x80;
    init[5] = (total >> 8) as u8;
    init[6] = (total & 0xff) as u8;
    let first = total.min(INIT_DATA);
    init[7..7 + first].copy_from_slice(&msg.data[..first]);
    reports.push(init);

    let mut offset = first;
    let mut seq = 0u8;
    while offset < total {
        let mut cont = [0u8; REPORT_SIZE];
        cont[0..4].copy_from_slice(&msg.cid.to_be_bytes());
        cont[4] = seq & 0x7f;
        let n = (total - offset).min(CONT_DATA);
        cont[5..5 + n].copy_from_slice(&msg.data[offset..offset + n]);
        reports.push(cont);
        offset += n;
        seq = seq.wrapping_add(1);
    }
    reports
}

/// CTAPHID capability flags (INIT response).
pub const CAPABILITY_CBOR: u8 = 0x04; // speaks CTAP2 CBOR
pub const CAPABILITY_NMSG: u8 = 0x08; // does NOT speak CTAP1/U2F

/// Build the `CTAPHID_INIT` response for a request that arrived on `req_cid`
/// carrying `nonce`, allocating `new_cid` as the channel. Advertises CBOR
/// (CTAP2) and NMSG (no U2F). Payload: nonce(8) ‖ newCID(4) ‖ version ‖
/// device major/minor/build ‖ capability flags.
pub fn init_response(req_cid: u32, nonce: &[u8], new_cid: u32) -> Message {
    let mut data = Vec::with_capacity(17);
    data.extend_from_slice(&nonce[..nonce.len().min(8)]);
    data.resize(8, 0); // pad a short nonce
    data.extend_from_slice(&new_cid.to_be_bytes());
    data.push(2); // CTAPHID protocol version
    data.extend_from_slice(&[0, 0, 0]); // device major/minor/build
    data.push(CAPABILITY_CBOR | CAPABILITY_NMSG);
    Message {
        cid: req_cid,
        cmd: CTAPHID_INIT,
        data,
    }
}

/// Build a single-report `CTAPHID_ERROR` frame.
pub fn error_report(cid: u32, code: u8) -> [u8; REPORT_SIZE] {
    let msg = Message {
        cid,
        cmd: CTAPHID_ERROR,
        data: vec![code],
    };
    split_message(&msg)[0]
}

/// Build a single-report `CTAPHID_KEEPALIVE` frame.
pub fn keepalive_report(cid: u32, status: u8) -> [u8; REPORT_SIZE] {
    let msg = Message {
        cid,
        cmd: CTAPHID_KEEPALIVE,
        data: vec![status],
    };
    split_message(&msg)[0]
}

/// Reassembles inbound reports into a [`Message`]. One assembler tracks a
/// single in-flight message; `push` returns `Ok(Some(msg))` when complete.
#[derive(Debug, Default)]
pub struct Assembler {
    cid: u32,
    cmd: u8,
    expected: usize,
    buf: Vec<u8>,
    next_seq: u8,
    in_progress: bool,
}

/// Outcome of feeding one report to the [`Assembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum Feed {
    /// Need more continuation packets.
    Incomplete,
    /// A complete message is ready.
    Complete(Message),
    /// Protocol error; the caller should emit `error_report(cid, code)`.
    Error { cid: u32, code: u8 },
}

impl Assembler {
    /// Feed one 64-byte report. Shorter buffers are padded conceptually; a
    /// buffer with no full header is rejected.
    pub fn push(&mut self, report: &[u8]) -> Feed {
        if report.len() < 5 {
            return Feed::Error {
                cid: CID_BROADCAST,
                code: ERR_INVALID_LEN,
            };
        }
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        let is_init = report[4] & 0x80 != 0;

        if is_init {
            if report.len() < 7 {
                return Feed::Error {
                    cid,
                    code: ERR_INVALID_LEN,
                };
            }
            let cmd = report[4] & 0x7f;
            let bcnt = ((report[5] as usize) << 8) | report[6] as usize;
            if bcnt > MAX_MESSAGE_LEN {
                return Feed::Error {
                    cid,
                    code: ERR_INVALID_LEN,
                };
            }
            self.cid = cid;
            self.cmd = cmd;
            self.expected = bcnt;
            self.buf.clear();
            self.next_seq = 0;
            self.in_progress = true;
            let take = bcnt.min(INIT_DATA);
            let avail = (report.len() - 7).min(take);
            self.buf.extend_from_slice(&report[7..7 + avail]);
            self.maybe_complete()
        } else {
            if !self.in_progress || cid != self.cid {
                return Feed::Error {
                    cid,
                    code: ERR_CHANNEL_BUSY,
                };
            }
            let seq = report[4] & 0x7f;
            if seq != self.next_seq {
                self.in_progress = false;
                return Feed::Error {
                    cid,
                    code: ERR_INVALID_SEQ,
                };
            }
            self.next_seq = self.next_seq.wrapping_add(1);
            let remaining = self.expected - self.buf.len();
            let avail = (report.len() - 5).min(remaining);
            self.buf.extend_from_slice(&report[5..5 + avail]);
            self.maybe_complete()
        }
    }

    fn maybe_complete(&mut self) -> Feed {
        if self.buf.len() >= self.expected {
            self.in_progress = false;
            Feed::Complete(Message {
                cid: self.cid,
                cmd: self.cmd,
                data: std::mem::take(&mut self.buf),
            })
        } else {
            Feed::Incomplete
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assemble(reports: &[[u8; REPORT_SIZE]]) -> Feed {
        let mut a = Assembler::default();
        let mut last = Feed::Incomplete;
        for r in reports {
            last = a.push(r);
        }
        last
    }

    #[test]
    fn init_response_allocates_channel_and_advertises_cbor() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let resp = init_response(CID_BROADCAST, &nonce, 0xABCD);
        assert_eq!(resp.cmd, CTAPHID_INIT);
        assert_eq!(resp.cid, CID_BROADCAST);
        // nonce(8) ‖ newCID(4) ‖ version ‖ maj/min/build(3) ‖ caps = 17 bytes.
        assert_eq!(resp.data.len(), 17);
        assert_eq!(&resp.data[0..8], &nonce);
        assert_eq!(&resp.data[8..12], &0xABCDu32.to_be_bytes());
        assert_eq!(resp.data[12], 2); // protocol version
        assert_eq!(resp.data[16], CAPABILITY_CBOR | CAPABILITY_NMSG);
    }

    #[test]
    fn single_report_message_roundtrips() {
        let msg = Message {
            cid: 0x11223344,
            cmd: CTAPHID_CBOR,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let reports = split_message(&msg);
        assert_eq!(reports.len(), 1);
        assert_eq!(assemble(&reports), Feed::Complete(msg));
    }

    #[test]
    fn multi_report_message_roundtrips() {
        // 200 bytes forces one init + continuation packets.
        let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let msg = Message {
            cid: 0xAABBCCDD,
            cmd: CTAPHID_MSG,
            data,
        };
        let reports = split_message(&msg);
        assert!(reports.len() > 1);
        assert_eq!(assemble(&reports), Feed::Complete(msg));
    }

    #[test]
    fn out_of_order_seq_is_rejected() {
        let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let msg = Message {
            cid: 1,
            cmd: CTAPHID_MSG,
            data,
        };
        let mut reports = split_message(&msg);
        // Corrupt the sequence number of the first continuation packet.
        reports[1][4] = 5;
        let mut a = Assembler::default();
        a.push(&reports[0]);
        assert!(matches!(
            a.push(&reports[1]),
            Feed::Error {
                code: ERR_INVALID_SEQ,
                ..
            }
        ));
    }

    #[test]
    fn oversized_bcnt_rejected() {
        let mut report = [0u8; REPORT_SIZE];
        report[0..4].copy_from_slice(&1u32.to_be_bytes());
        report[4] = CTAPHID_CBOR | 0x80;
        report[5] = 0xFF; // BCNTH → huge
        report[6] = 0xFF;
        let mut a = Assembler::default();
        assert!(matches!(
            a.push(&report),
            Feed::Error {
                code: ERR_INVALID_LEN,
                ..
            }
        ));
    }

    #[test]
    fn error_and_keepalive_frames_are_well_formed() {
        let e = error_report(0x01020304, ERR_INVALID_CMD);
        assert_eq!(&e[0..4], &0x01020304u32.to_be_bytes());
        assert_eq!(e[4], CTAPHID_ERROR | 0x80);
        assert_eq!(e[7], ERR_INVALID_CMD);

        let k = keepalive_report(0x01020304, KEEPALIVE_UPNEEDED);
        assert_eq!(k[4], CTAPHID_KEEPALIVE | 0x80);
        assert_eq!(k[7], KEEPALIVE_UPNEEDED);
    }
}
