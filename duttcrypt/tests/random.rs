use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::prelude::*;

use duttcrypt::random::{untemper, MersenneTwister, encrypt_mt19937};

fn get_rng_val() -> u32 {
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    println!("{:?}", timestamp.as_secs() as u32);
    let mut rnd = MersenneTwister::new();
    rnd.seed(timestamp.as_secs() as u32);
    let randval = 40 + rnd.gen() as u64 % 1000;
    let seed = timestamp.as_secs() + randval;
    let mut rnd = MersenneTwister::new();
    println!("seed {:?}", seed);
    rnd.seed(seed as u32);
    rnd.gen()
}

fn get_rng_from_seed(seed : u32) -> u32 {
    let mut rng = MersenneTwister::from_seed(seed);
    rng.gen()
}

#[test]
fn check_prng() {
    let path = "2500_random_from_cpp_seed_1.log";
    let content = fs::read_to_string(path).expect("Failed to read file");
    let lines : Vec<String> = content.split("\n").map(|line| line.to_owned()).collect();
    let line_iter = lines.iter().filter(|line| line.len() > 0);
    let mut lines = Vec::new();
    lines.extend(line_iter);
    let values : Vec<u32> = lines.iter().map(|line| u32::from_str_radix(line, 10).unwrap()).collect();
    let mut rng = MersenneTwister::from_seed(1);
    for i in 0..values.len() {
        let mtval = rng.gen();
        assert_eq!(mtval, values[i]);
    }
}

#[test]
fn ch22_crack_seed() {
    let val = get_rng_val();
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let min = timestamp.as_secs();
    let max = timestamp.as_secs() + 1000;
    for i in min..max {
        if get_rng_from_seed(i as u32) == val {
            println!("found seed {:?}", i);
            break;
        }
    }
}

#[test]
fn ch23_clone_prng() {
    let mut rnd = MersenneTwister::new();
    rnd.seed(1);
    let mut origvals = Vec::new();
    for _ in 0..624 {
        origvals.push(rnd.gen());
    }
    let mut rnd2 = MersenneTwister::new();
    rnd2.seed(rnd.gen()); // random value, shouldn't matter
    rnd2.index = 0;
    for i in 0..624 {
        rnd2.mt[i] = untemper(origvals[i]);
    }
    let mut newvals = Vec::new();
    for _ in 0..624 {
        newvals.push(rnd2.gen());
    }
    assert_eq!(origvals, newvals);
}

#[test]
fn ch24_simple_test() {
    let raw = vec![1,2,3,4,5,6,7,8,9];
    let encrypted = encrypt_mt19937(&raw, 35);
    let cleartext = encrypt_mt19937(&encrypted, 35);
    assert_eq!(raw, cleartext);
}

fn get_ciphertext() -> (u16, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let prefix_count : u8 = rng.gen_range(1,20);
    let mut prefix = Vec::new();
    prefix.resize(prefix_count as usize, 0);
    rng.fill_bytes(&mut prefix);

    let mut raw = prefix.clone();
    for _ in 0..14 {
        raw.push('A' as u8);
    }
    println!("raw({}) {:?}", raw.len(), raw);

    let seed : u16 = random();
    println!("seed {:?}", seed);

    (seed, encrypt_mt19937(&raw, seed))
}

fn get_seed(ciphertext : &[u8]) -> u16 {
    let rndcount = ciphertext.len() / 4;
    //println!("rndcount {:?}", rndcount);
    let len = rndcount*4;
    let mut bytes = Vec::new();
    for i in 1..5 {
        if len-i >= ciphertext.len() {
            break;
        }
        let v = ciphertext[len-i] ^ 'A' as u8;
        //println!("v {:?}", v);
        bytes.push(v as u32);
    }
    //println!("bytes {:?}", bytes);
    let rndval = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
    //println!("rndval {} = {:?}", rndcount, rndval);

    for try_seed in 0..std::u16::MAX {
        let mut mt = MersenneTwister::from_seed(try_seed as u32);
        for _ in 0..rndcount-1 {
            mt.gen();
        }
        if mt.gen() == rndval {
            //println!("found seed: {:?}", try_seed);
            return try_seed;
        }
    }
    panic!("seed not found");
}


#[test]
fn ch24_crack_seed_key() {
    let (raw_seed, ciphertext) = get_ciphertext();
    let cracked_seed = get_seed(&ciphertext);
    assert_eq!(raw_seed, cracked_seed);
}

fn generate_token(seed : u16) -> Vec<u8> {
    let token = "user=1".as_bytes();
    let encrypted = encrypt_mt19937(token, seed);
    encrypted
}

fn validate_token(token  :&[u8]) -> bool {
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    for try_sec in 0..10 {
        let seed = timestamp.as_secs() as u16 - try_sec;
        let attempt = encrypt_mt19937(token, seed);
        let part = &attempt[0..5];
        return part == "user=".as_bytes();
    }
    false
}

#[test]
fn ch24_password_token() {
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let valid_token = generate_token(timestamp.as_secs() as u16);
    let invalid_token = generate_token(3);
    assert!(validate_token(&valid_token));
    assert!(!validate_token(&invalid_token));
}
