use super::error::{Kind, Result, Error};

// The `KeyType` represents the type of an OpenSSH key.
pub struct KeyType {
    name: &'static str,
    short_name: &'static str,
    is_cert: bool,
}

impl KeyType {
    pub fn from_name(name: &str) -> Result<KeyType> {
        let key_type = match name {
            "ssh-ed25519"                              => KeyType { name: "ssh-ed25519", short_name: "ED25519", is_cert: false, },
            "ssh-rsa"                                  => KeyType { name: "ssh-rsa", short_name: "RSA", is_cert: false, },
            "rsa-sha2-256"                             => KeyType { name: "rsa-sha2-256", short_name: "RSA", is_cert: false, },
            "rsa-sha2-512"                             => KeyType { name: "rsa-sha2-512", short_name: "RSA", is_cert: false, },
            "ssh-dss"                                  => KeyType { name: "ssh-dss", short_name: "DSA", is_cert: false, },
            "ecdsa-sha2-nistp256"                      => KeyType { name: "ecdsa-sha2-nistp256", short_name: "ECDSA", is_cert: false, },
            "ecdsa-sha2-nistp384"                      => KeyType { name: "ecdsa-sha2-nistp384", short_name: "ECDSA", is_cert: false, },
            "ecdsa-sha2-nistp521"                      => KeyType { name: "ecdsa-sha2-nistp521", short_name: "ECDSA", is_cert: false, },
            "ssh-ed25519-cert-v01@openssh.com"         => KeyType { name: "ssh-ed25519-cert-v01@openssh.com", short_name: "ED25519-CERT", is_cert: true, },
            "ssh-rsa-cert-v01@openssh.com"             => KeyType { name: "ssh-rsa-cert-v01@openssh.com", short_name: "RSA-CERT", is_cert: true, },
            "ssh-dss-cert-v01@openssh.com"             => KeyType { name: "ssh-dss-cert-v01@openssh.com", short_name: "DSA-CERT", is_cert: true, },
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" => KeyType { name: "ecdsa-sha2-nistp256-cert-v01@openssh.com", short_name: "ECDSA-CERT", is_cert: true, },
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" => KeyType { name: "ecdsa-sha2-nistp384-cert-v01@openssh.com", short_name: "ECDSA-CERT", is_cert: true, },
            "ecdsa-sha2-nistp521-cert-v01@openssh.com" => KeyType { name: "ecdsa-sha2-nistp521-cert-v01@openssh.com", short_name: "ECDSA-CERT", is_cert: true, },
            _                                          => return Err(Error::with_kind(Kind::UnknownKeyType(String::from(name)))),
        };

        Ok(key_type)
    }

    pub fn name(&self) -> &str{
        self.name
    }

    pub fn short_name(&self) -> &str {
        self.short_name
    }

    pub fn is_cert(&self) -> bool {
        self.is_cert
    }
}
