// SPDX-License-Identifier: GPL-3.0-or-later
use rosec_protonpass::{mapping::map_item, parse_pat, valid_api_endpoint};
#[test]
fn endpoint_validation_rejects_userinfo_paths_and_non_loopback() {
    assert!(valid_api_endpoint("https://pass-api.proton.me"));
    for bad in [
        "http://pass-api.proton.me",
        "https://pass-api.proton.me.evil.invalid",
        "http://127.0.0.1:80@evil.invalid",
        "http://127.0.0.1:80/path",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://localhost:8080",
    ] {
        assert!(!valid_api_endpoint(bad));
    }
    assert_eq!(
        valid_api_endpoint("http://127.0.0.1:8080"),
        cfg!(feature = "test-http")
    );
}
#[test]
fn oversized_inputs_fail_with_static_errors() {
    assert!(matches!(
        parse_pat(&"x".repeat(1024 * 1024)),
        Err("Invalid PAT format")
    ));
    assert!(matches!(
        map_item("x".into(), &vec![0; 1024 * 1024 + 1]),
        Err("Item content too large")
    ));
}
