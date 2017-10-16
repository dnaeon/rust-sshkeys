extern crate sshkeys;

fn main() {
    let key = sshkeys::PublicKey::from_path("examples/id_rsa_2048.pub").unwrap();
    println!("{}", key);
}
