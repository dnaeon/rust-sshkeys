use std::collections::HashMap;
use std::error::Error;

extern crate sshkeys;

#[test]
fn test_rsa_pubkey_1024() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_1024.pub").unwrap();

    assert_eq!(key.key_type.name, "ssh-rsa");
    assert_eq!(key.key_type.short_name, "RSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::KeyRsa);

    assert_eq!(key.bits(), 1024);
    assert_eq!(key.comment, None);

    let rsa = match key.kind {
        sshkeys::PublicKeyKind::Rsa(k) => k,
        _ => panic!("Expected an RSA public key"),
    };

    // TODO: Test the fingerprint
}

#[test]
fn test_rsa_pubkey_2048() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_rsa_2048.pub").unwrap();

    assert_eq!(key.key_type.name, "ssh-rsa");
    assert_eq!(key.key_type.short_name, "RSA");
    assert_eq!(key.key_type.is_cert, false);
    assert_eq!(key.key_type.kind, sshkeys::KeyTypeKind::KeyRsa);

    assert_eq!(key.bits(), 2048);
    assert_eq!(key.comment, Some(String::from("me@home")));

    let rsa = match key.kind {
        sshkeys::PublicKeyKind::Rsa(k) => k,
        _ => panic!("Expected an RSA public key"),
    };

    // TODO: Test the fingerprint
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
    assert_eq!(cert.key_type.short_name, "RSA-CERT");
    assert_eq!(cert.key_type.is_cert, true);
    assert_eq!(cert.key_type.kind, sshkeys::KeyTypeKind::KeyRsaCert);

    assert_eq!(cert.key.key_type.name, "ssh-rsa-cert-v01@openssh.com");
    assert_eq!(cert.key.key_type.short_name, "RSA-CERT");
    assert_eq!(cert.key.key_type.is_cert, true);
    assert_eq!(cert.key.key_type.kind, sshkeys::KeyTypeKind::KeyRsaCert);

    assert_eq!(cert.serial, 0);
    assert_eq!(cert.cert_type, sshkeys::CertType::User);
    assert_eq!(cert.key_id, "john.doe".to_string());
    assert_eq!(cert.valid_principals, vec!("root".to_string()));
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
    assert_eq!(cert.signature_key.key_type.short_name, "RSA");
    assert_eq!(cert.signature_key.key_type.is_cert, false);
    assert_eq!(cert.signature_key.key_type.kind, sshkeys::KeyTypeKind::KeyRsa);
    assert_eq!(cert.signature_key.bits(), 2048);
    assert_eq!(cert.signature_key.comment, None);
    // TODO: Validate CA Public key fingerprint
    // TODO: Validate the `signature` field
}

#[test]
#[should_panic(expected = "Not a certificate")]
fn test_rsa_not_cert() {
    match sshkeys::Certificate::from_path("tests/test-keys/id_rsa_2048.pub") {
        Ok(v)  => panic!("Expected not a certificate error, got {:?}", v),
        Err(e) => panic!("{}", e.description()),
    }
}
