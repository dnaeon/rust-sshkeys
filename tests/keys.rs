use std::collections::HashMap;
use std::error::Error;

extern crate sshkeys;

#[test]
fn test_rsa_pubkey_1024() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_1024.pub").unwrap();

    assert_eq!(key.key_type.name, "ssh-rsa");
    assert_eq!(key.key_type.plain, "ssh-rsa");
    assert_eq!(key.key_type.short_name, "RSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::Rsa);

    assert_eq!(key.bits(), 1024);
    assert_eq!(key.comment, None);

    match key.kind {
        sshkeys::PublicKeyKind::Rsa(_) => {}
        _ => panic!("Expected RSA public key"),
    }

    let sha256fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "izTlwvAwZNoPhsSHPFvSWBx7mAnX0regyVjXfQTMv6Y");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "dBi3NL7zSWb1zsQob8ROuRggCtkr6n60VbIy+Io4iYil4UIieUvcco03TWpjdv/u"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "0GhrWC58WCwoXXE5mfmKBeLdEjwH2Xzg1Z3K7n5mBtLmcTu+OeIOw9bJJ2FPuskz57Bu2dJvOFkGidw2RW4fvg"
    );
}

#[test]
fn test_rsa_pubkey_2048() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_2048.pub").unwrap();

    assert_eq!(key.key_type.name, "ssh-rsa");
    assert_eq!(key.key_type.plain, "ssh-rsa");
    assert_eq!(key.key_type.short_name, "RSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::Rsa);

    assert_eq!(key.bits(), 2048);
    assert_eq!(key.comment, Some("me@home".to_string()));

    match key.kind {
        sshkeys::PublicKeyKind::Rsa(_) => {}
        _ => panic!("Expected RSA public key"),
    };

    let sha256fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "5mDozobgKuNO6/FutOgATBvGfYQbNfBlUY6iBYSdqF0");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "dgNFIE9GNNznHqdnL7Ml1CScn5X/5NAT2tpSqd6NWGhXPU3o1rz3SMKyELzuuArv"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "FDoxtx0ir1FlZUkHjUugzNZE7Qi3lJaUkN9QabPulm6/MXAcXXIhsW5C/mJaCDY1hDbeoo39aqHcTO+MdQiJsQ"
    );
}

#[test]
#[should_panic(expected = "Invalid format")]
fn test_rsa_pubkey_2048_invalid_format() {
    match sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_2048_invalid_format.pub") {
        Ok(v) => panic!("Expected invalid format, got {:?}", v),
        Err(e) => panic!("{}", e.description()),
    }
}

#[test]
#[should_panic(expected = "Unknown key type")]
fn test_rsa_pubkey_2048_unknown_keytype() {
    match sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_2048_unknown_keytype.pub") {
        Ok(v) => panic!("Expected unknown key type, got {:?}", v),
        Err(e) => panic!("{}", e.description()),
    }
}

#[test]
fn test_rsa_user_cert() {
    let cert = sshkeys::Certificate::from_path("tests/test-keys/id_rsa_2048-cert.pub").unwrap();

    assert_eq!(cert.key_type.name, "ssh-rsa-cert-v01@openssh.com");
    assert_eq!(cert.key_type.plain, "ssh-rsa");
    assert_eq!(cert.key_type.short_name, "RSA-CERT");
    assert_eq!(cert.key_type.is_cert, true);
    assert_eq!(cert.key_type.kind, sshkeys::KeyTypeKind::RsaCert);

    // Public key part of the certificate
    assert_eq!(cert.key.key_type.name, "ssh-rsa-cert-v01@openssh.com");
    assert_eq!(cert.key.key_type.plain, "ssh-rsa");
    assert_eq!(cert.key.key_type.short_name, "RSA-CERT");
    assert_eq!(cert.key.key_type.is_cert, true);
    assert_eq!(cert.key.key_type.kind, sshkeys::KeyTypeKind::RsaCert);
    assert_eq!(cert.key.bits(), 2048);
    assert_eq!(cert.key.comment, None);

    // Fingerprints of public key
    let sha256fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "5mDozobgKuNO6/FutOgATBvGfYQbNfBlUY6iBYSdqF0");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "dgNFIE9GNNznHqdnL7Ml1CScn5X/5NAT2tpSqd6NWGhXPU3o1rz3SMKyELzuuArv"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "FDoxtx0ir1FlZUkHjUugzNZE7Qi3lJaUkN9QabPulm6/MXAcXXIhsW5C/mJaCDY1hDbeoo39aqHcTO+MdQiJsQ"
    );

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::User);
    assert_eq!(cert.key_id, "john.doe");
    assert_eq!(cert.valid_principals, vec!["root"]);
    assert_eq!(cert.valid_after, 1505374860);
    assert_eq!(cert.valid_before, 1536824561);

    let mut co = HashMap::new();
    co.insert("force-command".to_string(), "/usr/bin/true".to_string());
    co.insert("source-address".to_string(), "127.0.0.1".to_string());
    assert_eq!(cert.critical_options, co);

    let mut extensions = HashMap::new();
    extensions.insert("permit-X11-forwarding".to_string(), "".to_string());
    extensions.insert("permit-agent-forwarding".to_string(), "".to_string());
    extensions.insert("permit-port-forwarding".to_string(), "".to_string());
    extensions.insert("permit-pty".to_string(), "".to_string());
    extensions.insert("permit-user-rc".to_string(), "".to_string());
    assert_eq!(cert.extensions, extensions);

    // The `reserved` field is empty in the current implementation of OpenSSH certificates
    assert_eq!(cert.reserved, Vec::new());

    // CA public key
    assert_eq!(cert.signature_key.key_type.name, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.plain, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.short_name, "RSA");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(cert.signature_key.key_type.kind, sshkeys::KeyTypeKind::Rsa);
    assert_eq!(cert.signature_key.bits(), 2048);
    assert_eq!(cert.signature_key.comment, None);

    // CA public key fingerprints
    let sha256fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "8bEmsdiV2BXhjrzPhp8dPrSLUK3U/YpIXT8NIw6Ym+s");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "7+2ZLPaqbntHUtypie8404NhIIqgo9b6/XWNABjgTphWic38/EDYXYm35SLllIxm"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "BrQgwbsBLlnyiOGITMfl+H2I7HCcCYiy22Hx0j62bWvifyZLyGA5PIoId+846U1P31cMX77l9Ok0qh9meltGCw"
    );

    assert_eq!(cert.comment, Some("me@home".to_string()));
}

#[test]
#[should_panic(expected = "Not a certificate")]
fn test_rsa_not_cert() {
    match sshkeys::Certificate::from_path("tests/test-keys/id_rsa_2048.pub") {
        Ok(v) => panic!("Expected public key, got certificate {:?}", v),
        Err(e) => panic!("{}", e.description()),
    }
}

#[test]
fn test_dsa_pubkey_1024() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_dsa_1024.pub").unwrap();

    assert_eq!(key.key_type.name, "ssh-dss");
    assert_eq!(key.key_type.plain, "ssh-dss");
    assert_eq!(key.key_type.short_name, "DSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::Dsa);

    assert_eq!(key.bits(), 1024);
    assert_eq!(key.comment, Some("me@home".to_string()));

    match key.kind {
        sshkeys::PublicKeyKind::Dsa(_) => {}
        _ => panic!("Expected DSA public key"),
    }

    let sha256fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "i+5TCv/r9PXHeJMeGbgH8xfpgbGsTFFKapQudFR2aFQ");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "m55cGSOiyn+U2mJX7sLOK/hcwDQmh16YhC5/ibhc2tnn8OOin4sXgpBRY6ZLXL/j"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "nNCtXgIQx+DZTUQPDVEVIl5SObBlD4MiJzBiFUsuNGPnjoF22kQeQkGYCioWfGQBrUR33p9/1jXLHfpHETuYSw"
    );
}

#[test]
fn test_dsa_user_cert() {
    let cert = sshkeys::Certificate::from_path("tests/test-keys/id_dsa_1024-cert.pub").unwrap();

    assert_eq!(cert.key_type.name, "ssh-dss-cert-v01@openssh.com");
    assert_eq!(cert.key_type.plain, "ssh-dss");
    assert_eq!(cert.key_type.short_name, "DSA-CERT");
    assert_eq!(cert.key_type.is_cert, true);
    assert_eq!(cert.key_type.kind, sshkeys::KeyTypeKind::DsaCert);

    // Public key part of the certificate
    assert_eq!(cert.key.key_type.name, "ssh-dss-cert-v01@openssh.com");
    assert_eq!(cert.key.key_type.plain, "ssh-dss");
    assert_eq!(cert.key.key_type.short_name, "DSA-CERT");
    assert_eq!(cert.key.key_type.is_cert, true);
    assert_eq!(cert.key.key_type.kind, sshkeys::KeyTypeKind::DsaCert);
    assert_eq!(cert.key.bits(), 1024);
    assert_eq!(cert.key.comment, None);

    let sha256fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "i+5TCv/r9PXHeJMeGbgH8xfpgbGsTFFKapQudFR2aFQ");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "m55cGSOiyn+U2mJX7sLOK/hcwDQmh16YhC5/ibhc2tnn8OOin4sXgpBRY6ZLXL/j"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "nNCtXgIQx+DZTUQPDVEVIl5SObBlD4MiJzBiFUsuNGPnjoF22kQeQkGYCioWfGQBrUR33p9/1jXLHfpHETuYSw"
    );

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::User);
    assert_eq!(cert.key_id, "john.doe");
    assert_eq!(cert.valid_principals, vec!["root"]);

    assert_eq!(cert.valid_after, 1505475180);
    assert_eq!(cert.valid_before, 1536924895);

    let mut co = HashMap::new();
    co.insert("force-command".to_string(), "/usr/bin/true".to_string());
    co.insert("source-address".to_string(), "127.0.0.1".to_string());
    assert_eq!(cert.critical_options, co);

    let mut extensions = HashMap::new();
    extensions.insert("permit-X11-forwarding".to_string(), "".to_string());
    extensions.insert("permit-agent-forwarding".to_string(), "".to_string());
    extensions.insert("permit-port-forwarding".to_string(), "".to_string());
    extensions.insert("permit-pty".to_string(), "".to_string());
    extensions.insert("permit-user-rc".to_string(), "".to_string());
    assert_eq!(cert.extensions, extensions);

    // The `reserved` field is empty in the current implementation of OpenSSH certificates
    assert_eq!(cert.reserved, Vec::new());

    // CA public key
    assert_eq!(cert.signature_key.key_type.name, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.plain, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.short_name, "RSA");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(cert.signature_key.key_type.kind, sshkeys::KeyTypeKind::Rsa);
    assert_eq!(cert.signature_key.bits(), 2048);
    assert_eq!(cert.signature_key.comment, None);

    // CA public key fingerprints
    let sha256fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "8bEmsdiV2BXhjrzPhp8dPrSLUK3U/YpIXT8NIw6Ym+s");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "7+2ZLPaqbntHUtypie8404NhIIqgo9b6/XWNABjgTphWic38/EDYXYm35SLllIxm"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "BrQgwbsBLlnyiOGITMfl+H2I7HCcCYiy22Hx0j62bWvifyZLyGA5PIoId+846U1P31cMX77l9Ok0qh9meltGCw"
    );

    assert_eq!(cert.comment, Some("me@home".to_string()));
}

#[test]
pub fn test_ecdsa_nistp256_pubkey() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_ecdsa_256.pub").unwrap();

    assert_eq!(key.key_type.name, "ecdsa-sha2-nistp256");
    assert_eq!(key.key_type.plain, "ecdsa-sha2-nistp256");
    assert_eq!(key.key_type.short_name, "ECDSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::Ecdsa);

    assert_eq!(key.bits(), 256);
    assert_eq!(key.comment, Some("me@home".to_string()));

    let sha256fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "RiRAmX+9kOD9dgFhocPtQi726sZXbQ2RmrkXevu6Avg");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "fM0Czmf55Od4g4zbLZueLFnbwFr0DmJQytpB7Xb2kjG6diar/7CskhVUkfX43fh6"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "8qXVmeSbYWN6D79reref2iz+tadg68qpkJDG0Z6B6u4U7XK0C3vYrDQVHg38FUKxvzAkw0c2gOYXqhP1RYo+Fw"
    );

    let ecdsa = match key.kind {
        sshkeys::PublicKeyKind::Ecdsa(ref k) => k,
        _ => panic!("Expected ECDSA public key"),
    };

    assert_eq!(ecdsa.curve.identifier, "nistp256");
    assert_eq!(ecdsa.curve.kind, sshkeys::CurveKind::Nistp256);
}

#[test]
pub fn test_ecdsa_nistp384_pubkey() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_ecdsa_384.pub").unwrap();

    assert_eq!(key.key_type.name, "ecdsa-sha2-nistp384");
    assert_eq!(key.key_type.plain, "ecdsa-sha2-nistp384");
    assert_eq!(key.key_type.short_name, "ECDSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::Ecdsa);

    assert_eq!(key.bits(), 384);
    assert_eq!(key.comment, Some("me@home".to_string()));

    let sha256fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "XyWmNHs59uQcNJBv6Iq6sbDAa5/u2GD1Nyu2YHcS2jQ");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "YXnQ8c1kDAQirgRgHSwswvT6zOFmvbvwL8au771Ska7+arFQgMe5Se9LPXeKmIWR"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "p73av0cbNsWXLexTQNpUxjGE4k+on8IrwsmIJP7xUhf7s1irVTBCpLA0wJ44IbMzUvMLuIj/FtoV1nTilYpb3w"
    );

    let ecdsa = match key.kind {
        sshkeys::PublicKeyKind::Ecdsa(ref k) => k,
        _ => panic!("Expected ECDSA public key"),
    };

    assert_eq!(ecdsa.curve.identifier, "nistp384");
    assert_eq!(ecdsa.curve.kind, sshkeys::CurveKind::Nistp384);
}

#[test]
pub fn test_ecdsa_nistp521_pubkey() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_ecdsa_521.pub").unwrap();

    assert_eq!(key.key_type.name, "ecdsa-sha2-nistp521");
    assert_eq!(key.key_type.plain, "ecdsa-sha2-nistp521");
    assert_eq!(key.key_type.short_name, "ECDSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::Ecdsa);

    assert_eq!(key.bits(), 521);
    assert_eq!(key.comment, Some("me@home".to_string()));

    let sha256fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "kEdMLsbAeJPDv3mEwIchjSxkcL/+XFzI9u1NHCWbsT8");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "ZD2U1VncXLttbPAEMtUX/rCl4JtgxI1XJOYPXeP7EzzBeXr3KVVb4Wn/u/Qp4i0Q"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "4EI3hnZ0KhIa0Sp8Z1CWWL8I0t8DaSs4+E8jiLFRAZ+EUeFYPysy6SrCbMDgSk5sfo3+2UA5SVqnZtBdmVQeIg"
    );

    let ecdsa = match key.kind {
        sshkeys::PublicKeyKind::Ecdsa(ref k) => k,
        _ => panic!("Expected ECDSA public key"),
    };

    assert_eq!(ecdsa.curve.identifier, "nistp521");
    assert_eq!(ecdsa.curve.kind, sshkeys::CurveKind::Nistp521);
}

#[test]
fn test_ecdsa_user_cert() {
    let cert = sshkeys::Certificate::from_path("tests/test-keys/id_ecdsa_521-cert.pub").unwrap();

    assert_eq!(
        cert.key_type.name,
        "ecdsa-sha2-nistp521-cert-v01@openssh.com"
    );
    assert_eq!(cert.key_type.plain, "ecdsa-sha2-nistp521");
    assert_eq!(cert.key_type.short_name, "ECDSA-CERT");
    assert_eq!(cert.key_type.is_cert, true);
    assert_eq!(cert.key_type.kind, sshkeys::KeyTypeKind::EcdsaCert);

    // Public key part of the certificate
    assert_eq!(
        cert.key.key_type.name,
        "ecdsa-sha2-nistp521-cert-v01@openssh.com"
    );
    assert_eq!(cert.key.key_type.plain, "ecdsa-sha2-nistp521");
    assert_eq!(cert.key.key_type.short_name, "ECDSA-CERT");
    assert_eq!(cert.key.key_type.is_cert, true);
    assert_eq!(cert.key.key_type.kind, sshkeys::KeyTypeKind::EcdsaCert);
    assert_eq!(cert.key.bits(), 521);
    assert_eq!(cert.key.comment, None);

    let sha256fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha512);
    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "kEdMLsbAeJPDv3mEwIchjSxkcL/+XFzI9u1NHCWbsT8");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "ZD2U1VncXLttbPAEMtUX/rCl4JtgxI1XJOYPXeP7EzzBeXr3KVVb4Wn/u/Qp4i0Q"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "4EI3hnZ0KhIa0Sp8Z1CWWL8I0t8DaSs4+E8jiLFRAZ+EUeFYPysy6SrCbMDgSk5sfo3+2UA5SVqnZtBdmVQeIg"
    );

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::User);
    assert_eq!(cert.key_id, "john.doe");
    assert_eq!(cert.valid_principals, vec!["root"]);

    assert_eq!(cert.valid_after, 1506340920);
    assert_eq!(cert.valid_before, 1537790635);

    let mut co = HashMap::new();
    co.insert("source-address".to_string(), "127.0.0.1".to_string());
    assert_eq!(cert.critical_options, co);

    let mut extensions = HashMap::new();
    extensions.insert("permit-X11-forwarding".to_string(), "".to_string());
    extensions.insert("permit-agent-forwarding".to_string(), "".to_string());
    extensions.insert("permit-port-forwarding".to_string(), "".to_string());
    extensions.insert("permit-pty".to_string(), "".to_string());
    extensions.insert("permit-user-rc".to_string(), "".to_string());
    assert_eq!(cert.extensions, extensions);

    // The `reserved` field is empty in the current implementation of OpenSSH certificates
    assert_eq!(cert.reserved, Vec::new());

    // CA public key
    assert_eq!(cert.signature_key.key_type.name, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.plain, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.short_name, "RSA");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(cert.signature_key.key_type.kind, sshkeys::KeyTypeKind::Rsa);
    assert_eq!(cert.signature_key.bits(), 2048);
    assert_eq!(cert.signature_key.comment, None);

    let sha256fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha512);
    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "8bEmsdiV2BXhjrzPhp8dPrSLUK3U/YpIXT8NIw6Ym+s");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "7+2ZLPaqbntHUtypie8404NhIIqgo9b6/XWNABjgTphWic38/EDYXYm35SLllIxm"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "BrQgwbsBLlnyiOGITMfl+H2I7HCcCYiy22Hx0j62bWvifyZLyGA5PIoId+846U1P31cMX77l9Ok0qh9meltGCw"
    );

    assert_eq!(cert.comment, Some("me@home".to_string()));
}

#[test]
pub fn test_ed25519_pubkey() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_ed25519.pub").unwrap();

    assert_eq!(key.key_type.name, "ssh-ed25519");
    assert_eq!(key.key_type.plain, "ssh-ed25519");
    assert_eq!(key.key_type.short_name, "ED25519");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::Ed25519);

    assert_eq!(key.bits(), 256);
    assert_eq!(key.comment, Some("me@home".to_string()));

    let sha256fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "ppYFPx0k4Ogs230n6eX9vGPpnNsTB0LPrDWXh1YjClA");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "B4spD+NiA6esYoqr6dx+w0wBI3p3rQJsTku1rXIWGXTO87W1vvTKMFpwUOdNST2h"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "ljOfAT2lmNZbMDGNwNiLH/dPFIu+euUdXHP+5m0IobCBFYdg7mv8ltqtDBP2vP9vUcOWOow90EQoTPR4oZR1Nw"
    );

    let ed25519 = match key.kind {
        sshkeys::PublicKeyKind::Ed25519(ref k) => k,
        _ => panic!("Expected ED25519 public key"),
    };

    // Key size should be 32 bytes
    // https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03#section-5.5
    assert_eq!(ed25519.key.len(), 32);
}

#[test]
pub fn test_ed25519_user_cert() {
    let cert = sshkeys::Certificate::from_path("tests/test-keys/id_ed25519-cert.pub").unwrap();

    assert_eq!(cert.key_type.name, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(cert.key_type.plain, "ssh-ed25519");
    assert_eq!(cert.key_type.short_name, "ED25519-CERT");
    assert_eq!(cert.key_type.is_cert, true);
    assert_eq!(cert.key_type.kind, sshkeys::KeyTypeKind::Ed25519Cert);

    // Public key part of the certificate
    assert_eq!(cert.key.key_type.name, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(cert.key.key_type.plain, "ssh-ed25519");
    assert_eq!(cert.key.key_type.short_name, "ED25519-CERT");
    assert_eq!(cert.key.key_type.is_cert, true);
    assert_eq!(cert.key.key_type.kind, sshkeys::KeyTypeKind::Ed25519Cert);
    assert_eq!(cert.key.bits(), 256);
    assert_eq!(cert.key.comment, None);

    let sha256fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "ppYFPx0k4Ogs230n6eX9vGPpnNsTB0LPrDWXh1YjClA");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "B4spD+NiA6esYoqr6dx+w0wBI3p3rQJsTku1rXIWGXTO87W1vvTKMFpwUOdNST2h"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "ljOfAT2lmNZbMDGNwNiLH/dPFIu+euUdXHP+5m0IobCBFYdg7mv8ltqtDBP2vP9vUcOWOow90EQoTPR4oZR1Nw"
    );

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::User);
    assert_eq!(cert.key_id, "john.doe");
    assert_eq!(cert.valid_principals, vec!["root"]);

    assert_eq!(cert.valid_after, 1506934140);
    assert_eq!(cert.valid_before, 1538383841);

    let mut co = HashMap::new();
    co.insert("force-command".to_string(), "/usr/bin/true".to_string());
    assert_eq!(cert.critical_options, co);

    let mut extensions = HashMap::new();
    extensions.insert("permit-X11-forwarding".to_string(), "".to_string());
    extensions.insert("permit-agent-forwarding".to_string(), "".to_string());
    extensions.insert("permit-port-forwarding".to_string(), "".to_string());
    extensions.insert("permit-pty".to_string(), "".to_string());
    extensions.insert("permit-user-rc".to_string(), "".to_string());
    assert_eq!(cert.extensions, extensions);

    // The `reserved` field is empty in the current implementation of OpenSSH certificates
    assert_eq!(cert.reserved, Vec::new());

    // CA public key
    assert_eq!(cert.signature_key.key_type.name, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.plain, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.short_name, "RSA");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(cert.signature_key.key_type.kind, sshkeys::KeyTypeKind::Rsa);
    assert_eq!(cert.signature_key.bits(), 2048);
    assert_eq!(cert.signature_key.comment, None);

    let sha256fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha512);
    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "8bEmsdiV2BXhjrzPhp8dPrSLUK3U/YpIXT8NIw6Ym+s");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "7+2ZLPaqbntHUtypie8404NhIIqgo9b6/XWNABjgTphWic38/EDYXYm35SLllIxm"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "BrQgwbsBLlnyiOGITMfl+H2I7HCcCYiy22Hx0j62bWvifyZLyGA5PIoId+846U1P31cMX77l9Ok0qh9meltGCw"
    );

    assert_eq!(cert.comment, Some("me@home".to_string()));
}

#[test]
fn test_ed25519_host_cert() {
    let cert = sshkeys::Certificate::from_path("tests/test-keys/id_ed25519_host-cert.pub").unwrap();

    assert_eq!(cert.key_type.name, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(cert.key_type.plain, "ssh-ed25519");
    assert_eq!(cert.key_type.short_name, "ED25519-CERT");
    assert_eq!(cert.key_type.is_cert, true);
    assert_eq!(cert.key_type.kind, sshkeys::KeyTypeKind::Ed25519Cert);

    // Public key part of the certificate
    assert_eq!(cert.key.key_type.name, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(cert.key.key_type.plain, "ssh-ed25519");
    assert_eq!(cert.key.key_type.short_name, "ED25519-CERT");
    assert_eq!(cert.key.key_type.is_cert, true);
    assert_eq!(cert.key.key_type.kind, sshkeys::KeyTypeKind::Ed25519Cert);
    assert_eq!(cert.key.bits(), 256);
    assert_eq!(cert.key.comment, None);

    let sha256fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.key.fingerprint_with(sshkeys::FingerprintKind::Sha512);

    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "kkaqMnJz4XAhwz7n7Ov8RbHEYIJ8sxyGQWDmM5Ckot0");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "vGjciz1R26zOHfZ8Vv8m2O7Cz7HxHKWbfuev/LbznWlOWuAqLl1QuuDk/oqhSxKr"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "NCUwuFl6hLiLLX9TUVwmaLjD5q4ql1ayGciFBklt3GYdQzLpX8sLMMBEgcrUgEfZjQtF18d3mNWbEx/okW6Vqw"
    );

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::Host);
    assert_eq!(cert.key_id, "host01");
    assert_eq!(cert.valid_principals, vec!["host01.example.com"]);

    assert_eq!(cert.valid_after, 1506936000);
    assert_eq!(cert.valid_before, 1538385716);

    // No critical options are defined for host certificates
    let co = HashMap::new();
    assert_eq!(cert.critical_options, co);

    // No extensions are defined for host certificates
    let extensions = HashMap::new();
    assert_eq!(cert.extensions, extensions);

    // The `reserved` field is empty in the current implementation of OpenSSH certificates
    assert_eq!(cert.reserved, Vec::new());

    // CA public key
    assert_eq!(cert.signature_key.key_type.name, "ssh-ed25519");
    assert_eq!(cert.signature_key.key_type.plain, "ssh-ed25519");
    assert_eq!(cert.signature_key.key_type.short_name, "ED25519");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(
        cert.signature_key.key_type.kind,
        sshkeys::KeyTypeKind::Ed25519
    );
    assert_eq!(cert.signature_key.bits(), 256);
    assert_eq!(cert.signature_key.comment, None);

    let sha256fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha256);
    let sha384fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha384);
    let sha512fp = cert.signature_key
        .fingerprint_with(sshkeys::FingerprintKind::Sha512);
    assert_eq!(sha256fp.kind, sshkeys::FingerprintKind::Sha256);
    assert_eq!(sha256fp.hash, "elYqUIgEUqMyc8AdNNk+IeI+2l1vWEh4K4n03hqhoD8");
    assert_eq!(sha384fp.kind, sshkeys::FingerprintKind::Sha384);
    assert_eq!(
        sha384fp.hash,
        "XPQbeB2kZcG3AUIjIq2wtUDMQYS/Iy0G6trb4XH97zzi4MK+YUqEdx7BAKkZYs0u"
    );
    assert_eq!(sha512fp.kind, sshkeys::FingerprintKind::Sha512);
    assert_eq!(
        sha512fp.hash,
        "nIa7CBs7SST41mSeHA7/69y7yy9y3Ec7W6JQKWJsgsBNbY3hq8WiPaa00z5q0AEgC+TO4MK56MoYY2PsE997zw"
    );

    assert_eq!(cert.comment, Some("me@home".to_string()));
}
