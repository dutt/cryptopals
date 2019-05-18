use std::collections::HashSet;

extern crate aes;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

use super::hex;
use super::xor;

pub fn decrypt_ecb(bytes: &[u8], key: &str) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let cipher = Aes128::new(&key);
    let mut decrypted : Vec<u8> = Vec::new();
    for chunk in bytes.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend(block.iter());

    }
    decrypted
}

pub fn encrypt_ecb(bytes: &[u8], key: &str) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let cipher = Aes128::new(&key);
    let mut encrypted : Vec<u8> = Vec::new();
    for chunk in bytes.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend(block.iter());

    }
    encrypted
}

pub fn is_ecb(text : &str) -> bool {
    let bytes = hex::parse_hex_str(&text);
    let mut chunks = HashSet::new();
    for chunk in bytes.chunks(16) {
        if !chunks.contains(&chunk) {
            chunks.insert(chunk);
        }
    }
    chunks.len() != bytes.len() / 16
}

pub fn decrypt_cbc(bytes: &[u8], key: &str, iv : &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
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

pub fn encrypt_cbc(bytes: &[u8], key: &str, iv : &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let cipher = Aes128::new(&key);
    let mut encrypted : Vec<u8> = Vec::new();
    let mut last_block = Vec::from(iv);
    for chunk in bytes.chunks(16) {
        let xored = xor::xor_bytes(chunk, &last_block);
        let mut block = GenericArray::clone_from_slice(&xored);
        cipher.encrypt_block(&mut block);
        last_block = Vec::new();
        last_block.extend(block.iter());
        encrypted.extend(block.iter());
    }
    encrypted
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ecb() {
		let key = "YELLOW_SUBMARINE";
		let raw = vec![1;16];
		let encrypted = encrypt_ecb(&raw, key);
		let decrypted = decrypt_ecb(&encrypted, key);
		assert_eq!(decrypted, raw);
	}

	#[test]
	fn test_cbc() {
	    let key = "YELLOW SUBMARINE";
	    let iv = vec![0;16];

	    let clearbytes = vec![1;32];
	    let tenc = encrypt_cbc(&clearbytes, &key, &iv);
	    let tdec = decrypt_cbc(&tenc, &key, &iv);
	    assert_eq!(tdec, clearbytes);	
	}
}
