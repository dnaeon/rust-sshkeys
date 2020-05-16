#![cfg(feature = "serde")]

extern crate serde_test;
extern crate sshkeys;

use self::serde_test::{assert_de_tokens_error, assert_tokens, Token};
use std::fmt;

#[test]
fn serde_ok_both_ways() {
    let key = sshkeys::PublicKey::from_path("tests/test-keys/id_ed25519.pub").unwrap();

    assert_tokens(
        &key,
        &[Token::String(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMIVp6q5co/r5GwY0dH+NYQbfKicapeF3gXEU3dzaAvD me@home",
        )],
    );
}

#[test]
fn serde_de_error() {
    struct MockError {}
    impl fmt::Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Invalid format")
        }
    }
    let err_format = MockError {}.to_string();

    assert_de_tokens_error::<sshkeys::PublicKey>(&[Token::Str("M")], &err_format);
    assert_de_tokens_error::<sshkeys::PublicKey>(&[Token::Str("")], &err_format);
}
