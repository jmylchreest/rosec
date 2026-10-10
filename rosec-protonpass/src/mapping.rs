// SPDX-License-Identifier: GPL-3.0-or-later
use crate::sensitive::SensitiveItem;
use crate::upstream::item_v1;
use protobuf::Message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub label: String,
    pub public: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, Zeroizing<String>>,
    pub passkeys: Vec<crate::passkey::Credential>,
    pub totp_fields: Vec<String>,
}
pub fn map_item(id: String, bytes: &[u8]) -> Result<Entry, &'static str> {
    if bytes.len() > 1024 * 1024 {
        return Err("Item content too large");
    }
    let mut item =
        SensitiveItem(item_v1::Item::parse_from_bytes(bytes).map_err(|_| "Invalid item protobuf")?);
    let mut e = Entry {
        id,
        label: String::new(),
        public: BTreeMap::new(),
        secrets: BTreeMap::new(),
        passkeys: Vec::new(),
        totp_fields: Vec::new(),
    };
    if let Some(metadata) = item.metadata.as_mut() {
        e.label = std::mem::take(&mut metadata.name);
        e.secrets.insert(
            "notes".into(),
            Zeroizing::new(std::mem::take(&mut metadata.note)),
        );
    }
    let content = item
        .content
        .as_mut()
        .and_then(|c| c.content.as_mut())
        .ok_or("Missing item content")?;
    macro_rules! secret_fields {
        ($e:ident, $item:ident, $($field:ident),+) => { $(
            $e.secrets.insert(stringify!($field).into(), Zeroizing::new(std::mem::take(&mut $item.$field)));
        )+ };
    }
    match content {
        item_v1::content::Content::Login(login) => {
            e.public.insert("rosec:type".into(), "login".into());
            e.public
                .insert("username".into(), std::mem::take(&mut login.item_username));
            e.public.insert(
                "uri".into(),
                login.urls.first().cloned().unwrap_or_default(),
            );
            e.secrets.insert(
                "password".into(),
                Zeroizing::new(std::mem::take(&mut login.password)),
            );
            if !login.totp_uri.is_empty() {
                e.public.insert("rosec:totp".into(), "true".into());
                e.secrets.insert(
                    "totp".into(),
                    Zeroizing::new(std::mem::take(&mut login.totp_uri)),
                );
            }
            e.public
                .insert("email".into(), std::mem::take(&mut login.item_email));
            for p in &login.passkeys {
                e.passkeys.push(crate::passkey::decode(p)?);
            }
        }
        item_v1::content::Content::Note(_) => {
            e.public.insert("rosec:type".into(), "note".into());
        }
        item_v1::content::Content::SshKey(ssh) => {
            e.public.insert("rosec:type".into(), "ssh-key".into());
            e.public
                .insert("public_key".into(), std::mem::take(&mut ssh.public_key));
            e.secrets.insert(
                "private_key".into(),
                Zeroizing::new(std::mem::take(&mut ssh.private_key)),
            );
            map_sections(&mut e, &mut ssh.sections)?;
        }
        item_v1::content::Content::Alias(_) => {
            e.public.insert("rosec:type".into(), "generic".into());
            e.public.insert("proton_type".into(), "alias".into());
        }
        item_v1::content::Content::CreditCard(card) => {
            e.public.insert("rosec:type".into(), "card".into());
            secret_fields!(
                e,
                card,
                cardholder_name,
                number,
                verification_number,
                expiration_date,
                pin
            );
            e.public.insert(
                "card_type".into(),
                format!("{:?}", card.card_type.enum_value_or_default()),
            );
        }
        item_v1::content::Content::Identity(identity) => {
            e.public.insert("rosec:type".into(), "identity".into());
            secret_fields!(
                e,
                identity,
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
            for fields in [
                &mut identity.extra_personal_details,
                &mut identity.extra_address_details,
                &mut identity.extra_contact_details,
                &mut identity.extra_work_details,
            ] {
                map_fields(&mut e, "custom", fields)?;
            }
            map_sections(&mut e, &mut identity.extra_sections)?;
        }
        item_v1::content::Content::Wifi(wifi) => {
            e.public.insert("rosec:type".into(), "generic".into());
            e.public.insert("proton_type".into(), "wifi".into());
            e.public
                .insert("ssid".into(), std::mem::take(&mut wifi.ssid));
            e.public.insert(
                "security".into(),
                format!("{:?}", wifi.security.enum_value_or_default()),
            );
            secret_fields!(e, wifi, password);
            map_sections(&mut e, &mut wifi.sections)?;
        }
        item_v1::content::Content::Custom(custom) => {
            e.public.insert("rosec:type".into(), "generic".into());
            e.public.insert("proton_type".into(), "custom".into());
            map_sections(&mut e, &mut custom.sections)?;
        }
    }
    map_fields(&mut e, "custom", &mut item.extra_fields)?;
    // Keep the established attributes consistent across providers. Proton-only
    // fields remain available under their original names.
    for (source, canonical) in [
        ("cardholder_name", "cardholder"),
        ("verification_number", "code"),
        ("social_security_number", "ssn"),
        ("phone_number", "phone"),
        ("street_address", "address1"),
        ("zip_or_postal_code", "postal_code"),
        ("state_or_province", "state"),
        ("country_or_region", "country"),
    ] {
        if let Some(value) = e.secrets.remove(source) {
            e.secrets.insert(canonical.into(), value);
        }
    }
    if let Some(expiry) = e.secrets.get("expiration_date").filter(|v| !v.is_empty()) {
        let (year, month) = expiry.split_once('-').ok_or("Invalid card expiry")?;
        if year.len() != 4
            || !year.bytes().all(|c| c.is_ascii_digit())
            || month.len() != 2
            || !month.parse::<u8>().is_ok_and(|n| (1..=12).contains(&n))
        {
            return Err("Invalid card expiry");
        }
        let year = Zeroizing::new(year.to_owned());
        let month = Zeroizing::new(month.to_owned());
        e.secrets.insert("exp_year".into(), year);
        e.secrets.insert("exp_month".into(), month);
    }
    Ok(e)
}

fn map_sections(
    e: &mut Entry,
    sections: &mut [item_v1::CustomSection],
) -> Result<(), &'static str> {
    for section in sections {
        map_fields(
            e,
            &format!("custom.{}", section.section_name),
            &mut section.section_fields,
        )?;
    }
    Ok(())
}
fn map_fields(
    e: &mut Entry,
    prefix: &str,
    fields: &mut [item_v1::ExtraField],
) -> Result<(), &'static str> {
    use item_v1::extra_field::Content;
    for field in fields {
        let name = format!("{prefix}.{}", field.field_name);
        let value = match field.content.as_mut() {
            Some(Content::Text(v)) => std::mem::take(&mut v.content),
            Some(Content::Hidden(v)) => std::mem::take(&mut v.content),
            Some(Content::Totp(v)) => {
                e.totp_fields.push(name.to_owned());
                std::mem::take(&mut v.totp_uri)
            }
            Some(Content::Timestamp(v)) => v
                .timestamp
                .as_ref()
                .map(|t| t.seconds.to_string())
                .unwrap_or_default(),
            None => continue,
        };
        // Conservative default: custom text can contain credentials too.
        if e.secrets.insert(name, Zeroizing::new(value)).is_some() {
            return Err("Duplicate custom field name");
        }
    }
    Ok(())
}

/// rosec's TOTP frontend selects one `totp` attribute per entry. Give additional
/// Proton TOTP fields stable derived IDs while retaining their original names
/// on the parent item for direct retrieval.
pub fn additional_totp_entries(parent: &Entry) -> Vec<Entry> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    parent
        .totp_fields
        .iter()
        .filter_map(|name| {
            let value = parent.secrets.get(name).filter(|v| !v.is_empty())?;
            Some(Entry {
                id: format!("{}#totp/{}", parent.id, URL_SAFE_NO_PAD.encode(name)),
                label: format!("{} — {}", parent.label, name.trim_start_matches("custom.")),
                public: BTreeMap::from([
                    ("rosec:type".into(), "login".into()),
                    ("rosec:totp".into(), "true".into()),
                ]),
                // Both independently owned entries must survive cache serialization.
                secrets: BTreeMap::from([("totp".into(), Zeroizing::new(value.to_string()))]),
                passkeys: Vec::new(),
                totp_fields: Vec::new(),
            })
        })
        .collect()
}
