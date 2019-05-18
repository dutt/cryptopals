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

#[test]
fn test_is_ecb() {
	let path = "8.txt";
    let content = fs::read_to_string(path).expect("Failed to read file");
    let lines : Vec<String> = content.split('\n').map(|line| line.to_owned()).collect();
    let mut ecb_lines = Vec::new();
    for l in &lines {
        if aes::is_ecb(&l) {
            ecb_lines.push(l);
        }
    }
    assert_eq!(1, ecb_lines.len());
    let expected_line = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    assert_eq!(expected_line, ecb_lines[0]);
}

#[test]
fn test_decrypt_cbc() {
	let key = "YELLOW SUBMARINE";
    let iv = vec![0;16];
    let path = "10.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode(&content);
    let decrypted = aes::decrypt_cbc(&bytes, &key, &iv);
    let text = text::bytes(&decrypted);
    assert_eq!(&text[0..33], "I'm back and I'm ringin' the bell");
}
