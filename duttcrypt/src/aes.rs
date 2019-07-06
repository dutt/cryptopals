use std::collections::HashSet;

extern crate aes;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::generic_array::typenum::U16;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

extern crate rand;
use rand::prelude::*;

use super::xor;
use super::pkcs7;
use super::math;

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
    if bytes.len() % 16 != 0 {
        panic!("encryp_cbc needs buffers with sized a multiple of 16");
    }
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let mut encrypted : Vec<u8> = Vec::new();
    //println!("encrypt_ecb:");
    //println!(" cleartext:");
    for chunk in bytes.chunks(16) {
        println!("  {:?}", chunk);
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        //println!("  enc {:?}", block);
        encrypted.extend(block.iter());
        //println!("current encrypted");
        //println!("{:?}", encrypted);
    }
    //println!(" encrypted:");
    //for chunk in encrypted.chunks(16) {
    //    println!("   {:?}", chunk);
    //}
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

pub fn pad_data(bytes: &[u8]) -> Vec<u8> {
	let mut new_len = math::find_nearest_16(bytes.len());
	if new_len == bytes.len() {
        new_len += 16;
	}
	pkcs7::pad_bytes(bytes, new_len)
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
    if bytes.len() % 16 != 0 {
        panic!("encryp_cbc needs buffers with sized a multiple of 16");
    }
    if iv.len() != 16 {
        panic!("encryp_cbc needs IV with a size of 16");
    }
    let key = GenericArray::clone_from_slice(key);
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

    let padded = pad_data(&full_data);

    let use_ebc = rng.gen::<bool>();
    if use_ebc {
        (String::from("ecb"), encrypt_ecb(&padded, &key))
    } else {
        let iv = generate_key();
        (String::from("cbc"), encrypt_cbc(&padded, &key, &iv))
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

pub fn encrypt_ctr(key : &[u8], data : &[u8], nonce : u64) -> Vec<u8> {
    if key.len() != 16 {
        panic!("encrypt_ctr::key len must be 16 long, len was {}", key.len());
    }
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let mut encrypted : Vec<u8> = Vec::new();
    let mut remaining = -1i16;
    let mut block_count = 0;

    //blocksource is just because I can't figure out how to create an
    // empty GenericArray of the right type...
    let blocksource = vec![1;16];
    let mut block : GenericArray<u8, U16> = GenericArray::clone_from_slice(&blocksource);

    for d in data.iter() {
        if remaining < 0 {
            let mut data : Vec<u8> = Vec::new();
            data.extend(nonce.to_le_bytes().iter());
            let counter = block_count as u64;
            data.extend(counter.to_le_bytes().iter());
            assert_eq!(data.len(), 16);
            //println!("data {:?}", data);
            block = GenericArray::clone_from_slice(&data);
            cipher.encrypt_block(&mut block);
            remaining = 15;
            block_count += 1;
        }
        encrypted.push(d ^ block[15-remaining as usize]);
        remaining -= 1;
    }
    encrypted
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn test_ctr_simple() {
        let data = "abcdefg".as_bytes();
        let key = "YELLOW SUBMARINE".as_bytes();
        let encrypted = encrypt_ctr(key, data, 0);
        let decrypted = encrypt_ctr(key, &encrypted, 0);
        assert_eq!(decrypted, data);
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
	    let iv = vec![2;16];
	    let raw = vec![1;32];
	    let tenc = encrypt_cbc(&raw, &key, &iv);
	    let tdec = decrypt_cbc(&tenc, &key, &iv);
	    assert_eq!(tdec, raw);
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
