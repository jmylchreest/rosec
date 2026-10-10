// SPDX-License-Identifier: GPL-3.0-or-later
use protobuf::{Message, MessageField};
use rosec_protonpass::{mapping::map_item, upstream::item_v1::*};

#[test]
fn all_native_item_types_map_without_exposing_secrets() {
    let cases = [
        (content::Content::Login(ItemLogin::new()), "login"),
        (content::Content::Note(ItemNote::new()), "note"),
        (content::Content::Alias(ItemAlias::new()), "generic"),
        (content::Content::CreditCard(ItemCreditCard::new()), "card"),
        (content::Content::Identity(ItemIdentity::new()), "identity"),
        (content::Content::SshKey(ItemSSHKey::new()), "ssh-key"),
        (content::Content::Wifi(ItemWifi::new()), "generic"),
        (content::Content::Custom(ItemCustom::new()), "generic"),
    ];
    for (variant, expected) in cases {
        let mut item = Item::new();
        let mut metadata = Metadata::new();
        metadata.name = "Demo".into();
        metadata.note = "hidden-note".into();
        item.metadata = MessageField::some(metadata);
        let mut c = Content::new();
        c.content = Some(variant);
        item.content = MessageField::some(c);
        let mapped = map_item("demo".into(), &item.write_to_bytes().unwrap()).unwrap();
        assert_eq!(mapped.public["rosec:type"], expected);
        assert!(!mapped.public.values().any(|v| v == "hidden-note"));
        assert_eq!(mapped.secrets["notes"].as_str(), "hidden-note");
    }
}

fn map(variant: content::Content) -> rosec_protonpass::mapping::Entry {
    let mut item = Item::new();
    let mut c = Content::new();
    c.content = Some(variant);
    item.content = MessageField::some(c);
    map_item("demo".into(), &item.write_to_bytes().unwrap()).unwrap()
}
#[test]
fn card_identity_wifi_and_custom_values_are_sensitive() {
    let mut card = ItemCreditCard::new();
    card.number = "4111111111111111".into();
    card.verification_number = "123".into();
    card.pin = "9876".into();
    let e = map(content::Content::CreditCard(card));
    assert_eq!(e.secrets["number"].as_str(), "4111111111111111");
    assert_eq!(e.secrets["verification_number"].as_str(), "123");
    assert_eq!(e.secrets["pin"].as_str(), "9876");
    assert!(!e.public.contains_key("number"));
    assert!(!e.public.contains_key("pin"));
    let mut identity = ItemIdentity::new();
    identity.social_security_number = "SYNTHETIC".into();
    let e = map(content::Content::Identity(identity));
    assert_eq!(e.secrets["social_security_number"].as_str(), "SYNTHETIC");
    assert!(!e.public.values().any(|v| v == "SYNTHETIC"));
    let mut wifi = ItemWifi::new();
    wifi.password = "wifi-secret".into();
    wifi.ssid = "test-network".into();
    let e = map(content::Content::Wifi(wifi));
    assert_eq!(e.secrets["password"].as_str(), "wifi-secret");
    assert_eq!(e.public["ssid"], "test-network");
    assert!(!e.public.contains_key("password"));
    let mut text = ExtraTextField::new();
    text.content = "text-may-be-secret".into();
    let mut field = ExtraField::new();
    field.field_name = "Token".into();
    field.content = Some(extra_field::Content::Text(text));
    let mut section = CustomSection::new();
    section.section_name = "Demo".into();
    section.section_fields.push(field);
    let mut custom = ItemCustom::new();
    custom.sections.push(section);
    let e = map(content::Content::Custom(custom));
    assert_eq!(
        e.secrets["custom.Demo.Token"].as_str(),
        "text-may-be-secret"
    );
    assert!(!e.public.contains_key("custom.Demo.Token"));
}
#[test]
fn duplicate_custom_names_are_rejected_without_leaking_the_value() {
    let mut text = ExtraHiddenField::new();
    text.content = "DO-NOT-LEAK".into();
    let mut field = ExtraField::new();
    field.field_name = "Token".into();
    field.content = Some(extra_field::Content::Hidden(text));
    let mut item = Item::new();
    let mut c = Content::new();
    c.content = Some(content::Content::Note(ItemNote::new()));
    item.content = MessageField::some(c);
    item.extra_fields = vec![field.clone(), field];
    assert!(matches!(
        map_item("demo".into(), &item.write_to_bytes().unwrap()),
        Err("Duplicate custom field name")
    ));
}
