use std::collections::HashSet;

extern crate aes;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

extern crate rand;
use rand::prelude::*;

use super::xor;
use super::pkcs7;

pub fn decrypt_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let mut decrypted : Vec<u8> = Vec::new();
    for chunk in bytes.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend(block.iter());

    }
    decrypted
}

pub fn encrypt_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let padded = pad_data(bytes);
    let mut encrypted : Vec<u8> = Vec::new();
    for chunk in padded.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend(block.iter());

    }
    encrypted
}

pub fn is_ecb(bytes : &[u8]) -> (bool, usize, usize) {
    let mut chunks = HashSet::new();
    for chunk in bytes.chunks(16) {
        if !chunks.contains(&chunk) {
            chunks.insert(chunk);
        }
    }
    (chunks.len() != bytes.len() / 16, bytes.len() / 16, chunks.len())
}

fn find_nearest_16(len: usize) -> usize {
	if len % 16 == 0 {
		return len;
	}
	let rem = len / 16;
	let retr = (rem+1) * 16;
	retr
}

pub fn pad_data(bytes: &[u8]) -> Vec<u8> {
	let new_len = find_nearest_16(bytes.len());
	if new_len == bytes.len() {
		Vec::from(bytes)
	} else {
		pkcs7::pad_bytes(bytes, new_len)
	}
}

pub fn decrypt_cbc(bytes: &[u8], key: &[u8], iv : &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let mut decrypted : Vec<u8> = Vec::new();
    let mut last_block = Vec::from(iv);
    for chunk in bytes.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&chunk);
        cipher.decrypt_block(&mut block);
        let xored = xor::xor_bytes(&block, &last_block);
        last_block = Vec::from(chunk);
        decrypted.extend(xored.iter());
    }
    decrypted
}

pub fn encrypt_cbc(bytes: &[u8], key: &[u8], iv : &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let mut encrypted : Vec<u8> = Vec::new();
    let mut last_block = Vec::from(iv);
    let padded = pad_data(bytes);
    for chunk in padded.chunks(16) {
        let xored = xor::xor_bytes(chunk, &last_block);
        let mut block = GenericArray::clone_from_slice(&xored);
        cipher.encrypt_block(&mut block);
        last_block = Vec::new();
        last_block.extend(block.iter());
        encrypted.extend(block.iter());
    }
    encrypted
}

pub fn generate_key() -> Vec<u8> {
    let mut data = vec![0u8;16];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

pub fn encrypt_with_rand_key(data : &[u8]) -> (String, Vec<u8>) {
    let mut rng = rand::thread_rng();

    let prefix_padding = rng.gen_range(5, 10);
    let mut prefix = Vec::new();
    prefix.resize(prefix_padding, 4u8);
    rng.fill_bytes(&mut prefix);

    let postfix_padding = rng.gen_range(5, 10);
    let mut postfix = Vec::new();
    postfix.resize(postfix_padding, 4u8);
    rng.fill_bytes(&mut postfix);

    let key = generate_key();
    let mut full_data = Vec::from(prefix);
    full_data.extend(data);
    full_data.extend(postfix);
    let use_ebc = rng.gen::<bool>();
    if use_ebc {
        (String::from("ecb"), encrypt_ecb(&full_data, &key))
    } else {
        let iv = generate_key();
        (String::from("cbc"), encrypt_cbc(&full_data, &key, &iv))
    }
}

pub fn guess_mode(data : &[u8]) -> String {
    for i in 0..15 {
        let mut v = Vec::from(data);
        v = v.split_off(i);
        v.truncate(v.len() - i);
        let guess = is_ecb(&v);
        if guess.1 > guess.2 && guess.1 - guess.2 > 1 {
            return String::from("ecb")
        }
    }
    String::from("cbc")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_find_nearest_16() {
		assert_eq!(16, find_nearest_16(1));
		assert_eq!(16, find_nearest_16(15));
		assert_eq!(16, find_nearest_16(16));

		assert_eq!(32, find_nearest_16(31));
		assert_eq!(32, find_nearest_16(32));
	}

	#[test]
	fn test_ecb() {
		let key = "YELLOW_SUBMARINE".as_bytes();
		let raw = vec![1;32];
		let encrypted = encrypt_ecb(&raw, key);
		let decrypted = decrypt_ecb(&encrypted, key);
		assert_eq!(decrypted, raw);
	}

	#[test]
	fn test_cbc() {
	    let key = "YELLOW SUBMARINE".as_bytes();
	    let iv = vec![2;32];

	    let clearbytes = vec![1;32];
	    let tenc = encrypt_cbc(&clearbytes, &key, &iv);
	    let tdec = decrypt_cbc(&tenc, &key, &iv);
	    assert_eq!(tdec, clearbytes);
	}

	#[test]
	fn test_guess_mode() {
		let data = vec![12u8;1024];
	    for _ in 0..50 {
	        let (actual_mode, encrypted) = encrypt_with_rand_key(&data);
	        let guessed_mode = guess_mode(&encrypted);
	        assert_eq!(actual_mode, guessed_mode);
	    }
	}
}
