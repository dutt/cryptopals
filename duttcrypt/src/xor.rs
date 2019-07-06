use std::collections::HashMap;
use std::cmp;

pub fn xor_bytes(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut retr : Vec<_> = Vec::new();
    let len = cmp::min(first.len(), second.len());
    for i in 0..len {
        let a = first[i];
        let b = second[i];
        retr.push(a ^ b);
    }
    retr
}

pub fn xor_byte(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|b| {
        b ^ key
    }).collect()
}

pub fn xor_repeated(bytes : &[u8], key : &[u8]) -> Vec<u8> {
    let mut data = Vec::from(bytes);
    for chunk in data.chunks_mut(key.len()) {
        let len = cmp::min(chunk.len(), key.len());
        for idx in 0..len {
            //print!("{} ^ {} =", chunk[idx], key[idx]);
            chunk[idx] = chunk[idx] ^ key[idx];
            //println!("{}, {:02x}", chunk[idx], chunk[idx]);
        }
        //println!(" ");
    };
    data
}

pub fn get_english_freqs() -> HashMap<char, i32> {
    let mut english = HashMap::new();
    english.insert('e', 127);
    english.insert('t', 91);
    english.insert('a', 82);
    english.insert('o', 75);
    english.insert('i', 70);
    english.insert('n', 67);
    english.insert('s', 63);
    english.insert('h', 61);
    english.insert('r', 60);
    english.insert('d', 43);
    english.insert('l', 40);
    english.insert('u', 28);
    english.insert('c', 28);
    english.insert('m', 24);
    english.insert('w', 24);
    english.insert('f', 22);
    english.insert('y', 20);
    english.insert('g', 20);
    english.insert('p', 19);
    english.insert('b', 15);
    english.insert('v', 10);
    english.insert('k', 08);
    english.insert('x', 02);
    english.insert('j', 02);
    english.insert('q', 01);
    english.insert('z', 01);
    english
}

pub fn score(bytes: &[u8]) -> i32 {
    //frequency diff

    //first create a character count map
    let mut counts : HashMap<char, i32> = HashMap::new();

    for &b in bytes {
        let c = (b as char).to_ascii_lowercase();
        if let Some(val) = counts.get_mut(&c) {
            *val += 1;
        } else {
            counts.insert(c, 1i32);
        }
    }

    //build ordering string
    let mut current = String::new();
    while counts.len() > 0 {
        let mut max_f = 0;
        let mut max_key = ' ';
        for (key, f) in &counts {
            if *f > max_f {
                max_f = *f;
                max_key = *key;
            }
        }
        current.push(max_key);
        counts.remove(&max_key);
    }

    let english = " etaoinshrdlcumwfgypbvkjxqz";
    let mut diff = 0;
    for c in current.chars() {
        if let Some(english_offset) = english.find(c) {
            let current_offset = current.find(c).unwrap() as i32;
            diff += english_offset as i32 - current_offset;
        } else {
            diff += 255i32;
        }
    }

    return diff;
}

// assumes english language
pub fn decrypt_byte(bytes: &[u8]) -> (Vec<u8>, u8) {
    let mut min_score = i32::max_value();
    let mut key = 0;
    for i in 0..0xFF {
        let decoded = xor_byte(bytes, i);
        let score = score(&decoded);
        if score != 0 {
            //println!("i {:?}", i);
            //println!("score {:?}", score);
            //println!("decoded {:?}", decoded);
            //println!("text {:?}", text::bytes(&decoded));
        }
        if score < min_score {
            //println!("min");
            min_score = score;
            key = i;
        }
    }
    //println!("min_score {:?}", min_score);
    let result = xor_byte(bytes, key);
    (result, key)
}

// helpers for decrypt_bytes

use super::text;
use super::binary;

use std::fmt;

struct KeySize {
    keysize : usize,
    distance : f32
}

impl KeySize {
    pub fn new(keysize : usize, distance : f32) -> KeySize {
        KeySize {
            keysize,
            distance
        }
    }
}

impl fmt::Debug for KeySize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<keysize ks={}, dist={}>", self.keysize, self.distance)
    }
}

#[derive(Debug, Clone)]
pub struct KeysizeScore {
    pub keysize : usize,
    pub score : i32,
    pub text : String
}

impl KeysizeScore {
    pub fn new(keysize : usize, score : i32, text : String) -> KeysizeScore {
        KeysizeScore {
            keysize,
            score,
            text
        }
    }
}

pub fn transpose_blocks(keysize: usize, data : &[u8]) -> Vec<Vec<u8>> {
    let mut retr = Vec::new();
    for y in 0..keysize {
        let mut part = Vec::new();
        for x in (0..data.len()).step_by(keysize) {
            if x+y >= data.len() {
                break
            }
            part.push(data[x+y]);
        }
        retr.push(part);
    }
    retr
}

fn get_keydistance(keysize: usize, content: &[u8]) -> KeySize {
    let chunks : Vec<_> = content.chunks(keysize).collect();
    let a = chunks[0];
    let b = chunks[1];
    let hamming_ab = binary::hamming(a, b);
    let mut hamming_bc = 0;
    let mut hamming_cd = 0;
    if keysize > 2 {
        let c = chunks[2];
        hamming_bc = binary::hamming(b,c);
        if keysize > 3 {
            let d = chunks[3];
            hamming_cd = binary::hamming(c,d);
        }
    }
    let total_hamming = hamming_ab + hamming_bc + hamming_cd;
    let norm_dist = total_hamming as f32 / keysize as f32;
    KeySize::new(keysize, norm_dist)
}

fn get_sizes(bytes : &[u8]) -> Vec<KeySize> {
    let mut sizes = Vec::new();
    for keysize in 2.. 40 {
        //println!("keysize {}", keysize);
        sizes.push(get_keydistance(keysize, &bytes));
        //println!(" ");
    }
    sizes.sort_by(|a,b| {
        if a.distance < b.distance && b.distance - a.distance > 0.005 {
            cmp::Ordering::Less
        } else if a.distance > b.distance && a.distance - b.distance > 0.005 {
            cmp::Ordering::Greater
        } else {
            cmp::Ordering::Equal
        }
    });
    sizes
}

pub fn decrypt_bytes(bytes: &[u8]) -> KeysizeScore {
    let mut sizes = get_sizes(&bytes);
    let _ = sizes.split_off(5);
    //println!("try sizes {:?}", sizes);
    let mut scores = Vec::new();
    for keysize in sizes {
        //println!("assumed keysize {:?}", keysize);
        let transposed = transpose_blocks(keysize.keysize, &bytes);
        let mut keybytes = Vec::new();
        for block in transposed {
            let (_decrypted, keybyte) = decrypt_byte(&block);
            keybytes.push(keybyte);
        }
        let decrypted = xor_repeated(&bytes, &keybytes);
        let score = score(&decrypted);
        let text = text::bytes(&decrypted);
        scores.push(KeysizeScore::new(keysize.keysize, score, text));
    }
    scores.sort_by(|a,b| a.score.cmp(&b.score));
    scores[0].clone()
}
