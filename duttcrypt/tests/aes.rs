use std::collections::HashMap;
use std::fs;

extern crate rand;
use rand::prelude::*;

use duttcrypt::base64;
use duttcrypt::text;
use duttcrypt::aes;
use duttcrypt::aes_oracle;
use duttcrypt::pkcs7;
use duttcrypt::math;

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
fn ch12_test_ecb_oracle() {
    let key = aes::generate_key();
    let postfixstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let postfix = base64::decode(postfixstr);
    let padded_postfix = aes::pad_data(&postfix);

    let blocksize = aes_oracle::guess_blocksize(&key);
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
fn ch13_test_ecb_cutnpaste() {
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

// Challenge 14

pub fn find_missing_count(key : &[u8], prefix : &[u8], postfix: &[u8]) -> usize {
    let mut datastr = String::from("A");
    let mut data = Vec::new();
    data.extend(prefix);
    data.extend(postfix);
    let encrypted = aes::encrypt_ecb(&data, &key);
    let mut last_enc_size = encrypted.len();
    for i in 1..15 {
        for _ in 0..i {
            datastr.push('A');
            let mut data = Vec::new();
            data.extend(prefix);
            data.extend(datastr.as_bytes());
            data.extend(postfix);
            let encrypted = aes::encrypt_ecb(&data, &key);
            if encrypted.len() != last_enc_size {
                return datastr.len() - 1
            }
            last_enc_size = encrypted.len()
        }
    }
    0
}


fn get_next_byte(prefix : &[u8], missing_count : usize, byte_index : usize,
                 known : &[u8], all_known : &[u8],
                 postfix: &[u8], key : &[u8], known_blocks : usize) -> Option<u8> {
    let mut data = Vec::new();
    data.extend(prefix);
    for _ in 0..missing_count + byte_index {
        data.push(0u8);
    }
    data.extend(postfix);
    let padded = pkcs7::pad_bytes(&data, math::find_nearest_16(data.len()));
    let mut encrypted = aes::encrypt_ecb(&padded, &key);

    let mut oracle = HashMap::new();
    let _arr = vec![10, 121, 98];
    let mut start_offset = 16;

    if known_blocks > 0 {
        start_offset = 16 + known_blocks * 16;
    }

    for i in 0..255 {
        let mut byte_data : Vec<u8> = Vec::new();
        byte_data.extend(prefix);
        let _count = math::find_nearest_16(prefix.len()) - prefix.len();

        for _ in 0.._count {
            byte_data.push(0u8);
        }

        byte_data.push(i);
        byte_data.extend(known);
        byte_data.extend(all_known);
        let padded_byte_data = pkcs7::pad_bytes(&byte_data, math::find_nearest_16(byte_data.len()));
        let mut enc = aes::encrypt_ecb(&padded_byte_data, &key);

        let mut enc_block = enc.split_off(enc.len() - start_offset);

        enc_block.split_off(16);

        if oracle.contains_key(&enc_block) {
            let val = oracle.get(&enc_block).unwrap();
            panic!("i={} oracle already contains block, from i={}", i, val);
        }
        oracle.insert(enc_block, i);
    }

    let mut encrypted_block = encrypted.split_off(encrypted.len() - start_offset);
    encrypted_block.split_off(16);

    if oracle.contains_key(&encrypted_block) {
        if let Some(val) = oracle.get(&encrypted_block) {
            println!("found {}", val);
            Some(*val)
        }
        else {
            None
        }
    } else {
        println!("Unknown encrypted block {:?}", encrypted_block);
        None
    }
}

#[test]
fn ch14_test_tricky_ecb_decrypt() {
    let key = aes::generate_key();

    //prefix
    let mut rng = rand::thread_rng();
    let prefix_count : u8 = rng.gen_range(1,10);
    let mut prefix = Vec::new();
    prefix.resize(prefix_count as usize, 0);
    rng.fill_bytes(&mut prefix);

    //postfix
    let postfixstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let postfix = base64::decode(postfixstr);
    let _padded_postfix = aes::pad_data(&postfix);
    let blocksize = aes_oracle::guess_blocksize(&key);

    // find how many to add t the next block
    let missing = find_missing_count(&key, &prefix, &postfix);

    let mut known : Vec<u8> = Vec::new();
    let mut all_known = Vec::new();
    let mut known_blocks = 0;
    'outer: loop {
        'inner: for byte_index in 0..blocksize {

            let current_postfix = postfix.clone();
            if known_blocks * blocksize > current_postfix.len() {
                break 'outer;
            }
            if let Some(known_byte) = get_next_byte(&prefix, missing+1, byte_index, &known, &all_known,
                                                    &postfix, &key, known_blocks) {
                if known_byte == 0 {
                    break;
                }
                known.insert(0, known_byte);
            } else {
                break 'outer;
            }
        }
        known.reverse();
        for c in known {
            all_known.insert(0, c);
        }
        known = Vec::new();
        known_blocks += 1;
    }

    let expected = vec![82, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121, 32, 53, 46, 48, 10, 87, 105, 116, 104, 32, 109, 121, 32, 114, 97, 103, 45, 116, 111, 112, 32, 100, 111, 119, 110, 32, 115, 111, 32, 109, 121, 32, 104, 97, 105, 114, 32, 99, 97, 110, 32, 98, 108, 111, 119, 10, 84, 104, 101, 32, 103, 105, 114, 108, 105, 101, 115, 32, 111, 110, 32, 115, 116, 97, 110, 100, 98, 121, 32, 119, 97, 118, 105, 110, 103, 32, 106, 117, 115, 116, 32, 116, 111, 32, 115, 97, 121, 32, 104, 105, 10, 68, 105, 100, 32, 121, 111, 117, 32, 115, 116, 111, 112, 63, 32, 78, 111, 44, 32, 73, 32, 106, 117, 115, 116, 32, 100, 114, 111, 118, 101, 32, 98, 121, 10];
    assert_eq!(all_known, expected);
}
