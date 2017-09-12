use super::error::{Kind, Result, Error};

#[derive(Debug, PartialEq)]
pub enum KeyTypeKind {
    KeyRsa,
    KeyDsa,
    KeyEcdsa,
    KeyEd25519,
    KeyRsaCert,
    KeyDsaCert,
    KeyEcdsaCert,
    KeyEd25519Cert,
}

// The `KeyType` represents the type of an OpenSSH key.
#[derive(Debug)]
pub struct KeyType {
    pub name: &'static str,
    pub short_name: &'static str,
    pub is_cert: bool,
    pub kind: KeyTypeKind,
}

impl KeyType {
    pub fn from_name(name: &str) -> Result<KeyType> {
        let kt = match name {
            "ssh-ed25519" =>
                KeyType {
                    name: "ssh-ed25519",
                    short_name: "ED25519",
                    is_cert: false,
                    kind: KeyTypeKind::KeyEd25519,
                },
            "ssh-rsa" =>
                KeyType {
                    name: "ssh-rsa",
                    short_name: "RSA",
                    is_cert: false,
                    kind: KeyTypeKind::KeyRsa,
                },
            "rsa-sha2-256" =>
                KeyType {
                    name: "rsa-sha2-256",
                    short_name: "RSA",
                    is_cert: false,
                    kind: KeyTypeKind::KeyRsa,
                },
            "rsa-sha2-512" =>
                KeyType {
                    name: "rsa-sha2-512",
                    short_name: "RSA",
                    is_cert: false,
                    kind: KeyTypeKind::KeyRsa,
                },
            "ssh-dss" =>
                KeyType {
                    name: "ssh-dss",
                    short_name: "DSA",
                    is_cert: false,
                    kind: KeyTypeKind:: KeyDsa,
                },
            "ecdsa-sha2-nistp256" =>
                KeyType {
                    name: "ecdsa-sha2-nistp256",
                    short_name: "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::KeyEcdsa,
                },
            "ecdsa-sha2-nistp384" =>
                KeyType {
                    name: "ecdsa-sha2-nistp384",
                    short_name:
                    "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::KeyEcdsa,
                },
            "ecdsa-sha2-nistp521" =>
                KeyType {
                    name: "ecdsa-sha2-nistp521",
                    short_name: "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::KeyEcdsa,
                },
            "ssh-ed25519-cert-v01@openssh.com" =>
                KeyType {
                    name: "ssh-ed25519-cert-v01@openssh.com",
                    short_name: "ED25519-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::KeyEd25519Cert,
                },
            "ssh-rsa-cert-v01@openssh.com" =>
                KeyType {
                    name: "ssh-rsa-cert-v01@openssh.com",
                    short_name: "RSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::KeyRsaCert,
                },
            "ssh-dss-cert-v01@openssh.com" =>
                KeyType {
                    name: "ssh-dss-cert-v01@openssh.com",
                    short_name: "DSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::KeyDsaCert,
                },
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::KeyEcdsaCert,
                },
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::KeyEcdsaCert,
                },
            "ecdsa-sha2-nistp521-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp521-cert-v01@openssh.com",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::KeyEcdsaCert,
                },
            _ => return Err(Error::with_kind(Kind::UnknownKeyType(String::from(name)))),
        };

        Ok(kt)
    }
}
