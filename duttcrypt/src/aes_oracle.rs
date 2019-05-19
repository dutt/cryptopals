use std::collections::HashMap;

use super::aes;

pub fn encrypt_with_postfix(data : &[u8], key : &[u8], postfix : &[u8]) -> Vec<u8> {
    let mut full_data = Vec::from(data);
    full_data.extend(postfix);
    aes::encrypt_ecb(&full_data, &key)
}

pub fn guess_mode(data : &[u8]) -> String {
    for i in 0..15 {
        let mut v = Vec::from(data);
        v = v.split_off(i);
        v.truncate(v.len() - i);
        let guess = aes::is_ecb(&v);
        if guess.1 > guess.2 && guess.1 - guess.2 > 1 {
            return String::from("ecb")
        }
    }
    String::from("cbc")
}

pub fn guess_blocksize(key : &[u8], postfix : &[u8]) -> usize {
    let mut datastr = String::from("A");
    let data = Vec::new();
    let encrypted = encrypt_with_postfix(&data, &key, &postfix);
    let mut last_enc_size = encrypted.len();
    for i in 2..15 {
        for _ in 0..i {
            datastr.push('A');
            let data = datastr.as_bytes();
            let encrypted = encrypt_with_postfix(&data, &key, &postfix);
            if encrypted.len() != last_enc_size {
                return encrypted.len() - last_enc_size
            }
            last_enc_size = encrypted.len()
        }
    }
    0
}

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
        let mut encrypted = encrypt_with_postfix(&data, &key, &postfix);
        encrypted.split_off(blocksize);
        oracle.insert(encrypted, i);
    }

    let mut encrypted = encrypt_with_postfix(&prefix, &key, &postfix);
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