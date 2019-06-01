use std::collections::HashMap;

extern crate rand;
use rand::prelude::*;

//use duttcrypt::binary;
use duttcrypt::base64;
//use duttcrypt::xor;
//use duttcrypt::hex;
use duttcrypt::aes_oracle;
use duttcrypt::pkcs7;
use duttcrypt::math;
use duttcrypt::text;
use duttcrypt::aes;

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

    let do_debug_print = false;

    if do_debug_print {
        println!("len data {} padded chunks :", data.len());
        for c in padded.chunks(16) {
            println!("   {:?}", c);
        }
        println!("known {:?}", known);
        println!("all_known {:?}", all_known);
    }

    //println!("{:?}", padded);
    let mut oracle = HashMap::new();
    let _arr = vec![10, 121, 98];
    let mut start_offset = 16;
    if known_blocks > 0 {
        start_offset = 16 + known_blocks * 16;
    }
    //println!("getting data starting at {}", start_offset);

    let _start_known = 16;// * known_blocks + known.len();
    let _end_known = _start_known + 16;
    //println!("getting known {}-{}", start_known, end_known);
    //for i in vec![10,121,98] {
    for i in 0..255 {
        let mut byte_data : Vec<u8> = Vec::new();
        byte_data.extend(prefix);
        let _count = math::find_nearest_16(prefix.len()) - prefix.len();
        //println!("count {:?}", count);
        for _ in 0.._count {
            byte_data.push(0u8);
        }

        byte_data.push(i);
        byte_data.extend(known);
        byte_data.extend(all_known);
        let padded_byte_data = pkcs7::pad_bytes(&byte_data, math::find_nearest_16(byte_data.len()));
        let mut enc = aes::encrypt_ecb(&padded_byte_data, &key);

        if do_debug_print {
            println!("i = {}, padded_byte_data:", i);
            for c in padded_byte_data.chunks(16) {
                println!("   {:?}", c);
            }
            println!("encrypted for i = {}", i);
            for c in enc.chunks(16) {
                println!("   {:?}", c);
            }
        }

        let mut enc_block = enc.split_off(enc.len() - start_offset);

        //if do_debug_print {
        //    println!("enc block 1", );
        //    for c in enc_block.chunks(16) {
        //        println!("   {:?}", c);
        //    }
        //}

        enc_block.split_off(16);

        //if do_debug_print {
        //    println!("enc block 2", );
        //    for c in enc_block.chunks(16) {
        //        println!("   {:?}", c);
        //    }
        //}

        if oracle.contains_key(&enc_block) {
            let val = oracle.get(&enc_block).unwrap();
            println!("i={} oracle already contains block, from i={}", i, val);
            return None
            //panic!("i={} oracle already contains block, from i={}", i, val);
        }
        oracle.insert(enc_block, i);
    }

    if do_debug_print {
        println!("encrypted");
        for c in encrypted.chunks(16) {
            println!("   {:?}", c);
        }
    }
    let mut encrypted_block = encrypted.split_off(encrypted.len() - start_offset);
    encrypted_block.split_off(16);

    //println!("encblock {:?}", encrypted_block);
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

fn main() {
    let key = aes::generate_key();

    //prefix
    let mut rng = rand::thread_rng();
    let prefix_count : u8 = rng.gen_range(1,10);
    let mut prefix = Vec::new();
    prefix.resize(prefix_count as usize, 0);
    rng.fill_bytes(&mut prefix);

    println!("prefix size {:?}", prefix.len());
    //postfix
    let postfixstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    //let postfixstr = "TWFu";
    let postfix = base64::decode(postfixstr);
    let _padded_postfix = aes::pad_data(&postfix);
    println!("postfix len {:?}", postfix.len());
    println!("postfix {:?}", postfix);
    for c in postfix.chunks(16) {
        println!("   {:?}", c);
    }

    let blocksize = aes_oracle::guess_blocksize(&key);
    println!("blocksize {:?}", blocksize);
    // find how many to add t the next block
    let missing = find_missing_count(&key, &prefix, &postfix);
    println!("missing count {:?}", missing);

    let mut known : Vec<u8> = Vec::new();
    let mut all_known = Vec::new();
    let mut known_blocks = 0;
    'outer: loop {
        'inner: for byte_index in 0..blocksize {

            let current_postfix = postfix.clone();
            if known_blocks * blocksize > current_postfix.len() {
                break 'outer;
            }
            //current_postfix = current_postfix.split_off();
            //for _ in &known {
            //    current_postfix.pop();
            //}
            //println!("current_postfix {:?}", current_postfix);
            //padding.extend(&current_postfix);
            //println!("known {:?}", known);
            //padding.extend(&known);
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
        //all_known.extend(known);
        known.reverse();
        for c in known {
            all_known.insert(0, c);
        }
        known = Vec::new();
        known_blocks += 1;
        println!("-------");
        println!(" OUTER ");
        let cleartext = text::bytes(&all_known);
        println!("cleartext {:?}", cleartext);
        println!("-------");
    }

    //println!("all_known {:?}", all_known);
    println!("all_known {:?}", all_known);
    let cleartext = text::bytes(&all_known);
    println!("cleartext:");
    println!("{}", cleartext);

    //'outer: loop {
    //    'inner: for i in 1..blocksize {
    //        let count = blocksize - i;
    //        let mut current_postfix = padded_postfix.clone();
    //        if known_blocks * blocksize > current_postfix.len() {
    //            break 'outer;
    //        }
    //        current_postfix = current_postfix.split_off(known_blocks * 15);
    //        let maybe_known_byte = check_prefix(&prefix, count, &known, &key, &current_postfix, blocksize);
    //        if let Some(known_byte) = maybe_known_byte {
    //            if known_byte == 254 {
    //                break 'outer;
    //            }
    //            //assert_eq!(padded_postfix[known.len() + all_known.len()], known_byte);
    //            known.push(known_byte);
    //            print!(".");
    //        } else {
    //            break 'outer;
    //        }
    //    }
    //    known_blocks += 1;
    //    all_known.extend(known);
    //    known = Vec::new();
    //}
    //while all_known[all_known.len() - 1] == 4 { //padding
    //    all_known.pop();
    //}
    //assert_eq!(all_known, postfix);
}
