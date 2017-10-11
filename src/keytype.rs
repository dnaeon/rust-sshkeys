use super::error::{Error, ErrorKind, Result};

/// An enum which represents the different kinds of key types.
#[derive(Debug, PartialEq)]
pub enum KeyTypeKind {
    /// Represents a RSA key type.
    Rsa,

    /// Represents a DSA key type.
    Dsa,

    /// Represents a ED25519 key type.
    Ed25519,

    /// Represents a ECDSA key type.
    Ecdsa,

    /// Represents a RSA certificate key type.
    RsaCert,

    /// Represents a DSA certificate key type.
    DsaCert,

    /// Represents a ED25519 certificate key type.
    Ed25519Cert,

    /// Represents a ECDSA certificate key type.
    EcdsaCert,
}

/// A type which represents the type of an OpenSSH key.
#[derive(Debug)]
pub struct KeyType {
    /// Name of the key type.
    pub name: &'static str,

    /// Short name of the key type.
    pub short_name: &'static str,

    /// Indicates whether the key type represents a certificate or not.
    pub is_cert: bool,

    /// Kind of the key type.
    pub kind: KeyTypeKind,

    /// The cert-less equivalent to a certified key type.
    pub plain: &'static str,
}

impl KeyType {
    /// Creates a new `KeyType` from a given name.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// # fn example() -> sshkeys::Result<()> {
    /// let kt = sshkeys::KeyType::from_name("ssh-rsa")?;
    /// assert_eq!(kt.kind, sshkeys::KeyTypeKind::Rsa);
    /// # Ok(())
    /// # }
    /// ```
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
                    kind: KeyTypeKind::Ecdsa,
                },
            "ecdsa-sha2-nistp384" =>
                KeyType {
                    name: "ecdsa-sha2-nistp384",
                    plain: "ecdsa-sha2-nistp384",
                    short_name: "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::Ecdsa,
                },
            "ecdsa-sha2-nistp521" =>
                KeyType {
                    name: "ecdsa-sha2-nistp521",
                    plain: "ecdsa-sha2-nistp521",
                    short_name: "ECDSA",
                    is_cert: false,
                    kind: KeyTypeKind::Ecdsa,
                },
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                    plain: "ecdsa-sha2-nistp256",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::EcdsaCert,
                },
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                    plain: "ecdsa-sha2-nistp384",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::EcdsaCert,
                },
            "ecdsa-sha2-nistp521-cert-v01@openssh.com" =>
                KeyType {
                    name: "ecdsa-sha2-nistp521-cert-v01@openssh.com",
                    plain: "ecdsa-sha2-nistp521",
                    short_name: "ECDSA-CERT",
                    is_cert: true,
                    kind: KeyTypeKind::EcdsaCert
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
