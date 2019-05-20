use std::fs;

use duttcrypt::base64;
use duttcrypt::text;
use duttcrypt::aes;
use duttcrypt::aes_oracle;

#[test]
fn decrypt_aes_ecb() {
    let path = "7.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode(&content);
    let decrypted = aes::decrypt_ecb(&bytes, "YELLOW SUBMARINE".as_bytes());
    let clear = text::bytes(&decrypted);
    assert_eq!(&clear[0..33], "I'm back and I'm ringin' the bell");
}

#[test]
fn test_is_ecb() {
	let path = "8.txt";
    let content = fs::read_to_string(path).expect("Failed to read file");
    let lines : Vec<_> = content.split('\n').map(|line| line.to_owned()).collect();
    let mut ecb_lines = Vec::new();
    for l in &lines {
        let bytes = l.as_bytes();
        if aes::is_ecb(bytes).0 {
            ecb_lines.push(l);
        }
    }
    assert_eq!(1, ecb_lines.len());
    let actual_line = ecb_lines[0];
    let expected_line = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    assert_eq!(expected_line, actual_line);
}

#[test]
fn test_decrypt_cbc() {
	let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0;16];
    let path = "10.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode(&content);
    let decrypted = aes::decrypt_cbc(&bytes, key, &iv);
    let text = text::bytes(&decrypted);
    assert_eq!(&text[0..33], "I'm back and I'm ringin' the bell");
}

#[test]
fn test_ecb_oracle() {
    let key = aes::generate_key();
    let postfixstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let postfix = base64::decode(postfixstr);
    let padded_postfix = aes::pad_data(&postfix);

    let blocksize = aes_oracle::guess_blocksize(&key, &padded_postfix);
    let data = vec![12;1024];
    let encrypted = aes_oracle::encrypt_with_postfix(&data, &key, &padded_postfix);
    let mode = aes::guess_mode(&encrypted);
    assert_eq!(mode, "ecb");

    let mut known = Vec::new();
    let mut all_known = Vec::new();
    let mut _known_blocks = 0;
    'outer: loop {
        'inner: for i in 1..16 {
            let count = blocksize - i;
            let mut current_postfix = padded_postfix.clone();
            if _known_blocks * 16 > current_postfix.len() {
                break 'outer;
            }
            current_postfix = current_postfix.split_off(_known_blocks * 15);
            let maybe_known_byte = aes_oracle::check_prefix(count, &known, &key, &current_postfix, blocksize);
            if let Some(known_byte) = maybe_known_byte {
                if known_byte == 254 {
                    break 'outer;
                }
                //assert_eq!(padded_postfix[known.len() + all_known.len()], known_byte);
                known.push(known_byte);
                print!(".");
            } else {
                break 'outer;
            }
        }
        _known_blocks += 1;
        all_known.extend(known);
        known = Vec::new();
    }
    while all_known[all_known.len() - 1] == 4 { //padding
        all_known.pop();
    }
    assert_eq!(all_known, postfix);
}

// Challenge 13

fn profile_for(email : &str) -> Vec<(String, String)> {
    let mut data = String::from(email);
    data = data.replace("&", "");
    data = data.replace("=", "");
    data = format!("email={}&uid=10&role=user", data);
    parse(&data)
}

fn parse(text : &str) -> Vec<(String, String)> {
    println!("parsing {:?}", text);
    let mut retr = Vec::new();
    let textstr = String::from(text);
    let parts : Vec<_> = textstr.split('&').collect();
    for p in parts {
        let subparts : Vec<_> = p.split('=').collect();
        let name = String::from(subparts[0]);
        let value = String::from(subparts[1]);
        retr.push((name, value));
    }
    retr
}

fn encode(data : Vec<(String, String)>) -> String {
    let mut retr = String::new();
    for p in &data {
        if retr.len() > 0 {
            retr += "&";
        }
        let key = &p.0;
        let val = &p.1;
        retr += &format!("{}={}", key, val);
    }
    retr
}

fn attack(encrypted : &[u8]) -> Vec<u8> {
    let blobs : Vec<_> = encrypted.chunks(16).collect();
    let mut retr = Vec::new();
    for (idx, chunk) in encrypted.chunks(16).enumerate() {
        if idx == 3 {
            retr.extend(blobs[1]);
        } else {
            retr.extend(chunk);
        }
    }
    retr
}

#[test]
fn test_ecb_cutnpaste() {
    let key = aes::generate_key();
    let email = "AAAAAAAAAAadmin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let data = profile_for(email);
    println!("{:?}", data);
    let encoded = encode(data);
    println!("encoded {:?}", encoded);
    let encrypted = aes::encrypt_ecb(encoded.as_bytes(), &key);
    let attacked = attack(&encrypted);
    let decrypted = aes::decrypt_ecb(&encrypted, &key);
    println!("decrypted {:?}", text::bytes(&decrypted));
    let decrypted_attacked = aes::decrypt_ecb(&attacked, &key);
    let text_attacked = text::bytes(&decrypted_attacked);
    println!("dec_attac {:?}", text_attacked);
    println!("dec_attac {}", text_attacked);
    let expected = "email=AAAAAAAAAAadmin\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}&uid=10&role=admin\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}";
    assert_eq!(text_attacked, expected);
}