extern crate sshkeys;

fn main() {
    let cert = sshkeys::Certificate::from_path("examples/id_ed25519-cert.pub").unwrap();

    println!("Type: {} {}", cert.key_type.name, cert.cert_type);
    println!("Public key: {}", cert.key);
    println!("Signing CA: {}", cert.signature_key);
    println!("Key ID: {}", cert.key_id);
    println!("Serial: {}", cert.serial);
    println!("Valid from {} to {}", cert.valid_after, cert.valid_before);
    println!("Principals:");
    for p in cert.valid_principals {
        println!("\t{}", p);
    }
    println!("Critical Options:");
    for (name, value) in cert.critical_options {
        println!("\t{} {}", name, value);
    }
    println!("Extensions:");
    for (name, _) in cert.extensions {
        println!("\t{}", name);
    }
}
