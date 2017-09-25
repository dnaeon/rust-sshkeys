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
        sshkeys::PublicKeyKind::Rsa(_) => {},
        _ => panic!("Expected RSA public key"),
    }

    assert_eq!(key.fingerprint().unwrap(), "izTlwvAwZNoPhsSHPFvSWBx7mAnX0regyVjXfQTMv6Y");
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
        sshkeys::PublicKeyKind::Rsa(_) => {},
        _ => panic!("Expected RSA public key"),
    };

    assert_eq!(key.fingerprint().unwrap(), "5mDozobgKuNO6/FutOgATBvGfYQbNfBlUY6iBYSdqF0");
}

#[test]
#[should_panic(expected = "Invalid format")]
fn test_rsa_pubkey_2048_invalid_format() {
    match sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_2048_invalid_format.pub") {
        Ok(v)  => panic!("Expected invalid format, got {:?}", v),
        Err(e) => panic!("{}", e.description()),
    }
}

#[test]
#[should_panic(expected = "Unknown key type")]
fn test_rsa_pubkey_2048_unknown_keytype() {
    match sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_2048_unknown_keytype.pub") {
        Ok(v)  => panic!("Expected unknown key type, got {:?}", v),
        Err(e) => panic!("{}", e.description()),
    }
}

#[test]
fn test_rsa_cert() {
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
    assert_eq!(cert.key.fingerprint().unwrap(), "5mDozobgKuNO6/FutOgATBvGfYQbNfBlUY6iBYSdqF0");

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::User);
    assert_eq!(cert.key_id, "john.doe");
    assert_eq!(cert.valid_principals, vec!("root"));
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

    assert_eq!(cert.signature_key.key_type.name, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.plain, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.short_name, "RSA");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(cert.signature_key.key_type.kind, sshkeys::KeyTypeKind::Rsa);
    assert_eq!(cert.signature_key.bits(), 2048);
    assert_eq!(cert.signature_key.comment, None);

    // TODO: Fingerprint
    // TODO: Validate CA Public key fingerprint
    // TODO: Validate the `signature` field
}

#[test]
#[should_panic(expected = "Not a certificate")]
fn test_rsa_not_cert() {
    match sshkeys::Certificate::from_path("tests/test-keys/id_rsa_2048.pub") {
        Ok(v)  => panic!("Expected public key, got certificate {:?}", v),
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

    let kind = match key.kind {
        sshkeys::PublicKeyKind::Dsa(ref k) => k,
        _ => panic!("Expected DSA public key"),
    };

    // TODO: Verify fingerprint of key
}

#[test]
fn test_dsa_cert() {
    let cert = sshkeys::Certificate::from_path("tests/test-keys/id_dsa_1024-cert.pub").unwrap();

    assert_eq!(cert.key_type.name, "ssh-dss-cert-v01@openssh.com");
    assert_eq!(cert.key_type.plain, "ssh-dss");
    assert_eq!(cert.key_type.short_name, "DSA-CERT");
    assert_eq!(cert.key_type.is_cert, true);
    assert_eq!(cert.key_type.kind, sshkeys::KeyTypeKind::DsaCert);

    assert_eq!(cert.key.key_type.name, "ssh-dss-cert-v01@openssh.com");
    assert_eq!(cert.key.key_type.plain, "ssh-dss");
    assert_eq!(cert.key.key_type.short_name, "DSA-CERT");
    assert_eq!(cert.key.key_type.is_cert, true);
    assert_eq!(cert.key.key_type.kind, sshkeys::KeyTypeKind::DsaCert);

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::User);
    assert_eq!(cert.key_id, "john.doe");
    assert_eq!(cert.valid_principals, vec!("root"));

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

    assert_eq!(cert.signature_key.key_type.name, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.plain, "ssh-rsa");
    assert_eq!(cert.signature_key.key_type.short_name, "RSA");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(cert.signature_key.key_type.kind, sshkeys::KeyTypeKind::Rsa);
    assert_eq!(cert.signature_key.bits(), 2048);
    assert_eq!(cert.signature_key.comment, None);
    // TODO: Validate CA Public key fingerprint
    // TODO: Validate the `signature` field
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

    assert_eq!(key.fingerprint().unwrap(), "RiRAmX+9kOD9dgFhocPtQi726sZXbQ2RmrkXevu6Avg");

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

    assert_eq!(key.fingerprint().unwrap(), "XyWmNHs59uQcNJBv6Iq6sbDAa5/u2GD1Nyu2YHcS2jQ");

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

    assert_eq!(key.fingerprint().unwrap(), "kEdMLsbAeJPDv3mEwIchjSxkcL/+XFzI9u1NHCWbsT8");

    let ecdsa = match key.kind {
        sshkeys::PublicKeyKind::Ecdsa(ref k) => k,
        _ => panic!("Expected ECDSA public key"),
    };

    assert_eq!(ecdsa.curve.identifier, "nistp521");
    assert_eq!(ecdsa.curve.kind, sshkeys::CurveKind::Nistp521);
}
