use super::error::{Error, ErrorKind, Result};

#[derive(Debug, PartialEq)]
pub enum KeyTypeKind {
    Rsa,
    Dsa,
    EcdsaNistp256,
    EcdsaNistp384,
    EcdsaNistp521,
    Ed25519,
    RsaCert,
    DsaCert,
    EcdsaNistp256Cert,
    EcdsaNistp384Cert,
    EcdsaNistp521Cert,
    Ed25519Cert,
}

// The `KeyType` represents the type of an OpenSSH key.
#[derive(Debug)]
pub struct KeyType {
    pub name: &'static str,
    pub short_name: &'static str,
    pub is_cert: bool,
    pub kind: KeyTypeKind,
    pub plain: &'static str, // The cert-less equivalent to a certified key type
}

impl KeyType {
    pub fn from_name(name: &str) -> Result<KeyType> {
        let kt = match name {
            "ssh-rsa" =>
                KeyType {
                    name: "ssh-rsa",
                    plain: "ssh-rsa",
                    short_name: "RSA",
                    is_cert: false,
                    kind: KeyTypeKind::Rsa,
                },
            "ssh-rsa-cert-v01@openssh.com" =>
                KeyType {
                    name: "ssh-rsa-cert-v01@openssh.com",
                    plain: "ssh-rsa",
                    short_name: "RSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::RsaCert,
                },
            "ssh-dss" =>
                KeyType {
                    name: "ssh-dss",
                    plain: "ssh-dss",
                    short_name: "DSA",
                    is_cert: false,
                    kind: KeyTypeKind:: Dsa,
                },
            "ssh-dss-cert-v01@openssh.com" =>
                KeyType {
                    name: "ssh-dss-cert-v01@openssh.com",
                    plain: "ssh-dss",
                    short_name: "DSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::DsaCert,
                },
            "ecdsa-sha2-nistp256" =>
                KeyType {
                    name: "ecdsa-sha2-nistp256",
                    plain: "ecdsa-sha2-nistp256",
                    short_name: "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::EcdsaNistp256,
                },
            "ecdsa-sha2-nistp384" =>
                KeyType {
                    name: "ecdsa-sha2-nistp384",
                    plain: "ecdsa-sha2-nistp384",
                    short_name: "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::EcdsaNistp384,
                },
            "ecdsa-sha2-nistp521" =>
                KeyType {
                    name: "ecdsa-sha2-nistp521",
                    plain: "ecdsa-sha2-nistp521",
                    short_name: "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::EcdsaNistp521,
                },
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                    plain: "ecdsa-sha2-nistp256",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::EcdsaNistp256Cert,
                },
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                    plain: "ecdsa-sha2-nistp384",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::EcdsaNistp384Cert,
                },
            "ecdsa-sha2-nistp521-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp521-cert-v01@openssh.com",
                    plain: "ecdsa-sha2-nistp521",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::EcdsaNistp521Cert,
                },
            "ssh-ed25519" =>
                KeyType {
                    name: "ssh-ed25519",
                    plain: "ssh-ed25519",
                    short_name: "ED25519",
                    is_cert: false,
                    kind: KeyTypeKind::Ed25519,
                },
            "ssh-ed25519-cert-v01@openssh.com" =>
                KeyType {
                    name: "ssh-ed25519-cert-v01@openssh.com",
                    plain: "ssh-ed25519",
                    short_name: "ED25519-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::Ed25519Cert,
                },
            _ => return Err(Error::with_kind(ErrorKind::UnknownKeyType(name.to_string()))),
        };

        Ok(kt)
    }
}
