//! GUI mode dispatcher: picks the right Iced application for the request.

mod prompt;
mod qr;
mod totp;

use anyhow::Result;

pub(crate) use qr::run_screenshot_helper;

use crate::request::PromptRequest;

pub(crate) fn run(request: PromptRequest) -> Result<()> {
    if request.qr_scan {
        qr::run(request)
    } else if request.totp_display.is_some() {
        totp::run(request)
    } else {
        prompt::run(request)
    }
}
