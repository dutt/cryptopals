use std::collections::HashMap;

use rand::prelude::*;

use duttcrypt::pkcs7;
use duttcrypt::aes;
use duttcrypt::text;
use duttcrypt::base64;

fn produce_session(key : &[u8]) -> (Vec<u8>, Vec<u8>) {
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
    //let line = "abcdefghabcdefghabcdefgh".as_bytes();
    //println!("line {:?}", line);
    let mut iv = vec![0;16];
    rng.fill_bytes(&mut iv);
    let ciphertext = aes::encrypt_cbc(line, key, &iv);
    (ciphertext, iv)
}

fn check_session(ciphertext : &[u8], key : &[u8], iv : &[u8]) -> bool {
    let cleartext = aes::decrypt_cbc(ciphertext, key, iv);
    //println!("cleartext {:?}", cleartext);
    pkcs7::validate(&cleartext)
}

fn _get_padding(chunks : &Vec<Vec<u8>>, key : &[u8], iv : &[u8]) -> (u8, u8, u8) {
    let len = chunks.len();
    for i in 0..255 {
        let orig = chunks[len-2][15];
        let mut data = chunks.clone();
        if i == orig {
            continue;
        }
        data[len-2][15] = i;
        let mut full = Vec::new();
        for c in &data {
            full.extend(c);
        }
        if check_session(&full, &key, &iv) {
            let val = i ^ orig ^ 1;
            return (i, orig, val)
        }
    }
    (0, 0, 0)
}

fn _decode_last_block(prev_block : &[u8], block : &[u8],
                     _key : &[u8], _iv : &[u8], padding : &[u8]) -> Vec<u8> {
    println!("prev_block {:?}", prev_block);
    println!("block {:?}", block);
    let padval = &padding[0];
    let _count = padval + 1;

    Vec::new()
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
            //let cleartext = aes::decrypt_cbc(&full, &key, &iv);
            //println!("cleartext {:?}", cleartext);
            //if byte_index == 8 {
            //    println!("chunks, byte {} i {}", byte_index, i);
            //    for c in &data {
            //        println!("{:?}", c);
            //    }

            //}
            if check_session(&full, &key, &iv) {
                let val = iu ^ orig;
                println!("known[{:?}] = {}", byte_index, val);
                if byte_index < 14 {
                    //return;
                }
                //let cleartext = aes::decrypt_cbc(&full, &key, &iv);
                //for c in cleartext.chunks(16) {
                //    println!("{:?}", c);
                //}
                //println!("known1 {:?}", known);
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
                //println!("known2 {:?}", known);
            }
        }
        if known.contains_key(&byte_index) == false {
            panic!("value for byte {} not found", byte_index);
        }
    }
    let mut blockdata = Vec::new();
    for i in (0..15).rev() {
        let (val, _) = known.get(&i).unwrap();
        blockdata.push(*val);
    }
    blockdata
}

fn main() {
    let key = aes::generate_key();
    let (ciphertext, iv) = produce_session(&key);
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
    println!("all_known {}", text::bytes(&stripped));
    let base64ed = base64::decode(&stripped);
}
