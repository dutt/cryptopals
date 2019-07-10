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
use duttcrypt::xor;

#[test]
fn decrypt_aes_ecb() {
    let path = "7.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode_str(&content);
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
    let bytes = base64::decode_str(&content);
    let decrypted = aes::decrypt_cbc(&bytes, key, &iv);
    let text = text::bytes(&decrypted);
    assert_eq!(&text[0..33], "I'm back and I'm ringin' the bell");
}

// Challenge 12

pub fn check_prefix(prefix_size : usize, known : &[u8],
                key : &[u8], postfix : &[u8],
                blocksize : usize) -> Option<u8> {
    let mut prefixstr = String::new();
    for _ in 0..prefix_size {
        prefixstr.push('A');
    }
    let prefix = Vec::from(prefixstr.as_bytes());
    let mut oracle = HashMap::new();
    for i in 0..255 {
        let mut data : Vec<u8> = prefix.clone();
        data.extend(known.iter());
        data.push(i);
        let mut encrypted = aes_oracle::encrypt_with_postfix(&data, &key, &postfix);
        encrypted.split_off(blocksize);
        oracle.insert(encrypted, i);
    }

    let mut encrypted = aes_oracle::encrypt_with_postfix(&prefix, &key, &postfix);
    encrypted.split_off(blocksize);
    if oracle.contains_key(&encrypted) {
        if let Some(val) = oracle.get(&encrypted) {
            Some(*val)
        } else {
            None
        }
    } else {
        println!("unknown encrypted {:?}", encrypted);
        None
    }
}

#[test]
fn ch12_test_ecb_oracle() {
    let key = aes::generate_key();
    let postfixstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let postfix = base64::decode_str(postfixstr);
    let padded_postfix = aes::pad_data(&postfix);

    println!("padded_postfix {:?}", padded_postfix);
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
            if (all_known.len() + known.len()) >= padded_postfix.len() {
                all_known.extend(known);
                break 'outer;
            }
            let mut current_postfix = padded_postfix.clone();
            current_postfix = current_postfix.split_off(_known_blocks * 15);
            let maybe_known_byte = check_prefix(count, &known, &key, &current_postfix, blocksize);
            if let Some(known_byte) = maybe_known_byte {
                known.push(known_byte);
            } else {
                all_known.extend(known);
                break 'outer;
            }
        }
        _known_blocks += 1;
        all_known.extend(known);
        known = Vec::new();
    }
    let nopadding = pkcs7::strip(&all_known);
    assert_eq!(nopadding, postfix);
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
    let padded = aes::pad_data(encoded.as_bytes());
    let encrypted = aes::encrypt_ecb(&padded, &key);
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
    let mut datastr = String::from("");
    let mut data = Vec::new();
    data.extend(prefix);
    data.extend(postfix);
    let padded = aes::pad_data(&data);
    let encrypted = aes::encrypt_ecb(&padded, &key);
    let mut last_enc_size = encrypted.len();
    for i in 1..15 {
        for _ in 0..i {
            datastr.push('A');
            let mut data = Vec::new();
            data.extend(prefix);
            data.extend(datastr.as_bytes());
            data.extend(postfix);
            let padded = aes::pad_data(&data);
            let encrypted = aes::encrypt_ecb(&padded, &key);
            if encrypted.len() != last_enc_size {
                return datastr.len()
            }
            last_enc_size = encrypted.len()
        }
    }
    panic!("failed to find missing number of bytes");
}

//tests added after refactoring issues...
#[test]
fn test_find_missing_count() {
    let key = aes::generate_key();
    let prefix = vec![1,1,1];
    let postfix = vec![2,2,2];
    assert_eq!(find_missing_count(&key, &prefix, &postfix), 10);

    let prefix = vec![1;16];
    let postfix = vec![2;4];
    assert_eq!(find_missing_count(&key, &prefix, &postfix), 12);

    let prefix = vec![55, 145, 74];
    let postfix = vec![82, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121, 32, 53, 46, 48, 10, 87, 105, 116, 104, 32, 109, 121, 32, 114, 97, 103, 45, 116, 111, 112, 32, 100, 111, 119, 110, 32, 115, 111, 32, 109, 121, 32, 104, 97, 105, 114, 32, 99, 97, 110, 32, 98, 108, 111, 119, 10, 84, 104, 101, 32, 103, 105, 114, 108, 105, 101, 115, 32, 111, 110, 32, 115, 116, 97, 110, 100, 98, 121, 32, 119, 97, 118, 105, 110, 103, 32, 106, 117, 115, 116, 32, 116, 111, 32, 115, 97, 121, 32, 104, 105, 10, 68, 105, 100, 32, 121, 111, 117, 32, 115, 116, 111, 112, 63, 32, 78, 111, 44, 32, 73, 32, 106, 117, 115, 116, 32, 100, 114, 111, 118, 101, 32, 98, 121, 10];
    assert_eq!(find_missing_count(&key, &prefix, &postfix), 3);

    let prefix = vec![36, 234, 81, 243, 196];
    assert_eq!(find_missing_count(&key, &prefix, &postfix), 1);
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
    //let padded = aes::pad_data(&data);
    println!("padded {:?}", padded);
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
        //let padded_byte_data = aes::pad_data(&byte_data);
        //println!("byte_data {:?}", byte_data);
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
    println!("prefix({}) {:?}", prefix.len(), prefix);

    //postfix
    let postfixstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let postfix = base64::decode_str(postfixstr);
    println!("postfix({}) {:?}", postfix.len(), postfix);

    //let padded_postfix = aes::pad_data(&postfix);
    let blocksize = aes_oracle::guess_blocksize(&key);

    // find how many to add to the next block
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

//
// Challenge 16
fn make_data16(userdata : &str, key : &[u8], iv : &[u8]) -> Vec<u8> {
    let mut encoded = String::from(userdata);
    encoded = encoded.replace(";", "%3B").replace("=", "%3D");
    let prefixstr = "comment1=cooking%20MCs;userdata=";
    let prefix = prefixstr.as_bytes();
    let postfixstr = ";comment2=%20like%20a%20pound%20of%20bacon";
    let postfix = postfixstr.as_bytes();

    let mut data = Vec::new();
    data.extend(prefix);
    data.extend(encoded.as_bytes());
    data.extend(postfix);

    let padded = aes::pad_data(&data);
    aes::encrypt_cbc(&padded, key, iv)
}

fn check_admin16(encrypted : &[u8], key : &[u8], iv : &[u8]) -> bool {
    let padded_clearbytes = aes::decrypt_cbc(encrypted, key, iv);
    let clearbytes = pkcs7::strip(&padded_clearbytes);
    let cleartext = text::bytes(&clearbytes);
    let mut decoded  = String::from(cleartext);
    decoded = decoded.replace("%3B",";").replace("%3D", "=").replace("%20", " ");
    let parts = decoded.split(";");
    for p in parts {
        if p == "admin=true" {
            return true
        }
    }
    false
}

fn flip16(data : &[u8]) -> Vec<u8> {
    let xor = vec![2, 11, 0, 4, 11, 83, 0, 64, 72, 64, 9];
    let mut retr = Vec::from(data);
    for i in 49..(49+xor.len()) {
        retr[i] ^= xor[i-49];
    }
    retr
}

#[test]
fn ch16_modify_cleartext_via_ciphertext() {
    let key = aes::generate_key();
    let iv = aes::generate_key();
    let userdata = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let data = make_data16(userdata, &key, &iv);
    let flipped = flip16(&data);
    assert_eq!(check_admin16(&data, &key, &iv), false);
    assert_eq!(check_admin16(&flipped, &key, &iv), true);
}

// Ch 17

fn produce_session(key : &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let lines = vec!["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                     "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                     "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                     "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                     "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                     "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                     "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                     "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                     "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                     "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG9"];
    let mut rng = rand::thread_rng();
    let line = lines.choose(&mut rng).unwrap().as_bytes();
    let mut iv = vec![0;16];
    rng.fill_bytes(&mut iv);
    let padded_line = aes::pad_data(line);
    let ciphertext = aes::encrypt_cbc(&padded_line, key, &iv);
    (Vec::from(line), ciphertext, iv)
}

fn check_session(ciphertext : &[u8], key : &[u8], iv : &[u8]) -> bool {
    let cleartext = aes::decrypt_cbc(ciphertext, key, iv);
    pkcs7::validate(&cleartext)
}

fn decode_block(prev_block : &Vec<u8>, block : &Vec<u8>,
                key : &[u8], iv : &[u8]) -> Vec<u8> {
    let mut known = HashMap::new();
    'outer : for byte_index in (0..16).rev() {
        //println!("byte_index {:?}", byte_index);
        let padding_value = 16u8 - byte_index as u8;
        //println!("padding_value {:?}", padding_value);
        'inner : for i in 0..256u16 {
            let iu = i as u8;
            let orig = prev_block[byte_index];
            let attempt = iu ^ padding_value as u8;
            let mut data = prev_block.clone();
            for pad_idx in (byte_index+1..16).rev() {
                let (_, prev_i) = known.get(&pad_idx).unwrap();
                let newval = prev_i ^ padding_value as u8;
                //println!("prev_val {:?}, prev_i {}, padding_value {}", prev_val, prev_i, padding_value);
                //println!("{:?} to padding {}", pad_idx, newval);
                data[pad_idx] = newval;
            }
            data[byte_index] = attempt;
            let mut full = Vec::new();
            //println!("data for {}:", i);
            //for c in &data {
            //    println!("{:?}", c);
            //    full.extend(c);
            //}
            full.extend(data);
            full.extend(block.iter());

            if check_session(&full, &key, &iv) {
                let val = iu ^ orig;
                println!("known[{:?}] = {}", byte_index, val);
                if known.contains_key(&byte_index) {
                    let (oldval, _) = known.get(&byte_index).unwrap();
                    if *oldval == padding_value as u8 {
                        println!("replacing old value for byte {:?} = ({},{})", byte_index, val, iu);
                        known.insert(byte_index, (val, iu));
                    }
                    continue 'outer;
                } else {
                    known.insert(byte_index, (val, iu));
                }
            }
        }
        if known.contains_key(&byte_index) == false {
            panic!("value for byte {} not found", byte_index);
        }
    }
    let mut blockdata = Vec::new();
    for i in (0..16).rev() {
        let (val, _) = known.get(&i).unwrap();
        blockdata.push(*val);
    }
    assert_eq!(blockdata.len(), 16);
    blockdata
}

#[test]
fn ch17_cbc_padding_oracle() {
    let key = aes::generate_key();
    let (cleartext, ciphertext, iv) = produce_session(&key);
    let mut chunks = Vec::new();
    for chunk in ciphertext.chunks(16) {
        chunks.push(Vec::from(chunk));
    }
    println!("chunks pre");
    for chunk in &chunks {
        println!("{:?}", chunk);
    }

    let len = chunks.len();
    let mut all_known = Vec::new();
    for chunk_index in (1..len).rev() {
        let known = decode_block(&chunks[chunk_index-1], &chunks[chunk_index], &key, &iv);
        for k in known {
            all_known.insert(0, k);
        }
    }
    let last_known = decode_block(&iv, &chunks[0], &key, &iv);
    for k in last_known {
        all_known.insert(0, k);
    }

    println!("all_known {:?}", all_known);
    let stripped = pkcs7::strip(&all_known);
    let text = text::bytes(&stripped);
    println!("all_known {}", text);
    assert_eq!(cleartext, stripped);
}

#[test]
fn ch18_aes_ctr() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let text = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".as_bytes();
    let b64ed = base64::decode(text);
    let decr = aes::encrypt_ctr(key, &b64ed, 0);
    let expected = vec![89, 111, 44, 32, 86, 73, 80, 32, 76, 101, 116, 39, 115, 32, 107, 105, 99, 107, 32, 105, 116, 32, 73, 99, 101, 44, 32, 73, 99, 101, 44, 32, 98, 97, 98, 121, 32, 73, 99, 101, 44, 32, 73, 99, 101, 44, 32, 98, 97, 98, 121, 32];
    assert_eq!(expected, decr);
}

#[test]
fn ch20_break_aes_ctr() {
    let path = "20.txt";
    let content = fs::read_to_string(path).expect("Failed to read file");
    let lines : Vec<String> = content.split("\n").map(|line| line.to_owned()).collect();
    assert!(lines.len() > 0);
    let mut min_length = usize::max_value();
    for l in &lines {
        if l.len() == 0 {
            continue;
        }
        if l.len() < min_length {
            min_length = l.len();
        }
    }
    assert!(min_length > 0);
    assert!(min_length < usize::max_value());

    let datalines : Vec<Vec<u8>> = lines.iter().map(|line| base64::decode(line.as_bytes())).collect();
    let trunc_lines: Vec<Vec<u8>> = datalines.iter().map(|line| {
            let mut copy = line.clone();
            copy.truncate(min_length);
            copy
        } ).collect();
    let mut bytes = Vec::new();
    for tl in trunc_lines {
        bytes.extend(tl);
    }

    let transposed = xor::transpose_blocks(min_length, &bytes);
    let mut keybytes = Vec::new();
    for block in transposed {
        let (_decrypted, keybyte) = xor::decrypt_byte(&block);
        keybytes.push(keybyte);
    }
    let decrypted = xor::xor_repeated(&bytes, &keybytes);
    let text = text::bytes(&decrypted);

    //println!("decrypted {:?}", decrypted);
    //println!("text {}", text);
    assert_eq!(&text[0..114], "I'm ratee \"R\"...this is f warning, ya better void / Poets are paranoid, Cuz I cale back to attacl others in spite-");
}

#[test]
fn ch25_test_edit() {
    let key = aes::generate_key();
    let nonce : u64 = random();
    let raw = vec![1,2,3,4,5,6];
    let padded = aes::pad_data(&raw);
    let ciphertext = aes::encrypt_ctr(&key, &padded, nonce);
    let newtext = [3,2,1];
    let edited = aes::edit_ctr(&ciphertext, &key, nonce, 3, &newtext);
    let origplaintext = aes::encrypt_ctr(&key, &ciphertext, nonce);
    assert_eq!(origplaintext, padded);
    let editplaintext = aes::encrypt_ctr(&key, &edited[..], nonce);
    let exp_edit = vec![1,2,3,3,2,1];
    let padded_exp_edit = aes::pad_data(&exp_edit);
    assert_eq!(padded_exp_edit, editplaintext);
}

#[test]
fn ch25_recover_plaintext() {
    let content = fs::read_to_string("25.txt").expect("Failed to read file");
    let content = content.replace("\n","");
    let plaintext = base64::decode_str(&content);

    let key = aes::generate_key();
    let nonce : u64 = random();
    let padded_plaintext = aes::pad_data(&plaintext);
    let ciphertext = aes::encrypt_ctr(&key, &padded_plaintext, nonce);

    let mut edittext = Vec::new();
    edittext.resize(padded_plaintext.len(), 0);
    let padded_edittext = aes::pad_data(&edittext);
    let edited = aes::edit_ctr(&ciphertext, &key, nonce, 0, &padded_edittext);

    let decrypted = xor::xor_bytes(&ciphertext, &edited);
    assert_eq!(decrypted, padded_plaintext);
}

// ch 26

fn make_data26(userdata : &str, key : &[u8], nonce : u64) -> Vec<u8> {
    let mut encoded = String::from(userdata);
    encoded = encoded.replace(";", "%3B").replace("=", "%3D");
    let prefixstr = "comment1=cooking%20MCs;userdata=";
    let prefix = prefixstr.as_bytes();
    let postfixstr = ";comment2=%20like%20a%20pound%20of%20bacon";
    let postfix = postfixstr.as_bytes();

    let mut data = Vec::new();
    data.extend(prefix);
    data.extend(encoded.as_bytes());
    data.extend(postfix);

    aes::encrypt_ctr(key, &data, nonce)
}

fn check_admin26(ciphertext : &[u8], key : &[u8], nonce : u64) -> bool {
    let plaintext = aes::encrypt_ctr(key, ciphertext, nonce);
    let plaintext = text::bytes(&plaintext);
    println!("plaintext {:?}", plaintext);

    let mut decoded  = String::from(plaintext);
    decoded = decoded.replace("%3B",";").replace("%3D", "=").replace("%20", " ");
    let parts = decoded.split(";");
    for p in parts {
        if p == "admin=true" {
            return true
        }
    }
    false
}

fn flip26(data : &[u8]) -> Vec<u8> {
    let xor = vec![2, 11, 0, 4, 11, 83, 0, 64, 72, 64, 9];
    let mut retr = Vec::from(data);
    for i in 65..(65+xor.len()) {
        retr[i] ^= xor[i-65];
    }
    retr
}

#[test]
fn ch26_ctr_bitflip() {
    let key = aes::generate_key();
    let nonce : u64 = random();
    let userdata = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let data = make_data26(userdata, &key, nonce);
    let flipped = flip26(&data);
    assert_eq!(check_admin26(&data, &key, nonce), false);
    assert_eq!(check_admin26(&flipped, &key, nonce), true);
}

fn make_data27(userdata : &str, key : &[u8]) -> Vec<u8> {
    let padded = aes::pad_data(&userdata.as_bytes());
    aes::encrypt_cbc(&padded, key, key)
}

fn check_admin27(encrypted : &[u8], key : &[u8]) -> Result<bool, Vec<u8>> {
    let padded_clearbytes = aes::decrypt_cbc(encrypted, key, key);
    let clearbytes = pkcs7::strip(&padded_clearbytes);
    for b in &clearbytes {
        if b.is_ascii() == false {
            return Err(clearbytes)
        }
    }
    let cleartext = text::bytes(&clearbytes);
    let mut decoded  = String::from(cleartext);
    decoded = decoded.replace("%3B",";").replace("%3D", "=").replace("%20", " ");
    let parts = decoded.split(";");
    for p in parts {
        if p == "admin=true" {
            return Ok(true)
        }
    }
    Ok(false)
}

fn modify27(ciphertext : &[u8]) -> Vec<u8> {
    let chunk1 = ciphertext.iter().take(16);
    let chunk2 = ciphertext.iter().take(16);
    let mut retr : Vec<u8> = Vec::new();
    retr.extend(chunk1);
    retr.extend(vec![0;16]);
    retr.extend(chunk2);
    retr
}

fn recover_key(clearbytes : &[u8]) -> Vec<u8> {
    let mut first : Vec<u8> = Vec::new();
    let mut third = Vec::new();
    for (idx, b) in clearbytes.iter().enumerate() {
        //println!("idx {:?} b {:?}", idx, b);
        if idx < 16 {
            first.push(*b);
        } else if idx >= 32 && idx < 48 {
            third.push(*b);
        }
    }
    xor::xor_bytes(&first, &third)
}

#[test]
fn ch27_recover_key() {
    let key = aes::generate_key();
    // an A block, a B block, a C block
    let block = "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC";
    let data = make_data27(&block, &key);
    let modified = modify27(&data);
    let recovered_key = match check_admin27(&modified, &key) {
        Ok(_) => panic!("Ascii was valid"),
        Err(plaintext) => recover_key(&plaintext)
    };
    assert_eq!(key, recovered_key);
}
