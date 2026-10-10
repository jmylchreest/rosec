// SPDX-License-Identifier: GPL-3.0-or-later
//! Best-effort cleanup of successfully parsed JSON, including unused fields.
use serde_json::Value;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

pub struct SensitiveJson(pub Value);
impl Deref for SensitiveJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl DerefMut for SensitiveJson {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}
fn scrub(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(scrub),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                scrub(&mut value);
            }
        }
        _ => {}
    }
}
// Generated protobuf types remain byte-for-byte upstream. This wrapper scrubs
// known sensitive fields on mapping failures as well as successful reads.
use crate::upstream::item_v1::*;
pub struct SensitiveItem(pub Item);
impl Deref for SensitiveItem {
    type Target = Item;
    fn deref(&self) -> &Item {
        &self.0
    }
}
impl DerefMut for SensitiveItem {
    fn deref_mut(&mut self) -> &mut Item {
        &mut self.0
    }
}
fn scrub_fields(fields: &mut [ExtraField]) {
    for field in fields {
        match field.content.as_mut() {
            Some(extra_field::Content::Text(v)) => v.content.zeroize(),
            Some(extra_field::Content::Hidden(v)) => v.content.zeroize(),
            Some(extra_field::Content::Totp(v)) => v.totp_uri.zeroize(),
            _ => {}
        }
    }
}
fn scrub_sections(sections: &mut [CustomSection]) {
    for section in sections {
        scrub_fields(&mut section.section_fields);
    }
}
impl Drop for SensitiveItem {
    fn drop(&mut self) {
        if let Some(m) = self.0.metadata.as_mut() {
            m.note.zeroize();
            m.custom_icon.zeroize();
        }
        scrub_fields(&mut self.0.extra_fields);
        macro_rules! wipe {($v:ident,$($field:ident),+)=>{$($v.$field.zeroize();)+};}
        match self.0.content.as_mut().and_then(|c| c.content.as_mut()) {
            Some(content::Content::Login(v)) => {
                wipe!(v, password, totp_uri);
                for p in &mut v.passkeys {
                    wipe!(p, content, note, user_id, user_handle);
                }
            }
            Some(content::Content::CreditCard(v)) => {
                wipe!(
                    v,
                    cardholder_name,
                    number,
                    verification_number,
                    expiration_date,
                    pin
                );
            }
            Some(content::Content::Identity(v)) => {
                wipe!(
                    v,
                    full_name,
                    email,
                    phone_number,
                    first_name,
                    middle_name,
                    last_name,
                    birthdate,
                    gender,
                    organization,
                    street_address,
                    zip_or_postal_code,
                    city,
                    state_or_province,
                    country_or_region,
                    floor,
                    county,
                    social_security_number,
                    passport_number,
                    license_number,
                    website,
                    x_handle,
                    second_phone_number,
                    linkedin,
                    reddit,
                    facebook,
                    yahoo,
                    instagram,
                    company,
                    job_title,
                    personal_website,
                    work_phone_number,
                    work_email
                );
                for f in [
                    &mut v.extra_personal_details,
                    &mut v.extra_address_details,
                    &mut v.extra_contact_details,
                    &mut v.extra_work_details,
                ] {
                    scrub_fields(f);
                }
                scrub_sections(&mut v.extra_sections);
            }
            Some(content::Content::SshKey(v)) => {
                v.private_key.zeroize();
                scrub_sections(&mut v.sections);
            }
            Some(content::Content::Wifi(v)) => {
                v.password.zeroize();
                scrub_sections(&mut v.sections);
            }
            Some(content::Content::Custom(v)) => scrub_sections(&mut v.sections),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wipes_nested_strings_and_objects() {
        let mut v = serde_json::json!(["secret",{"unused":"token"}]);
        scrub(&mut v);
        assert_eq!(v, serde_json::json!(["", {}]));
    }
}
