use std::fs;

use duttcrypt::base64;
use duttcrypt::text;
use duttcrypt::aes;

#[test]
fn decrypt_aes_ecb() {
    let path = "7.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode(&content);
    let decrypted = aes::decrypt_ecb(&bytes, "YELLOW SUBMARINE");
    let clear = text::bytes(&decrypted);
    assert_eq!(&clear[0..33], "I'm back and I'm ringin' the bell");
}
