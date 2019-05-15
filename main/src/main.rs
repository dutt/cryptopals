use std::fs;
use std::fmt;
use std::cmp;

use duttcrypt::binary;
use duttcrypt::base64;
use duttcrypt::xor;
//use duttcrypt::hex;
use duttcrypt::text;

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

struct KeysizeScore {
    keysize : usize,
    score : i32,
    text : String
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

impl fmt::Debug for KeysizeScore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<keyscore ks={}, score={}>", self.keysize, self.score)
    }
}

fn _write_rabbit() {
    let path = "rabbit.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = content.as_bytes();
    let key = "ICE".as_bytes();
    println!("ICE bytes {:?}", key);
    let xored = xor::xor_repeated(&bytes, key);
    let base64ed = base64::encode(&xored);

    let debase64ed = base64::decode(&base64ed);
    let clear = xor::xor_repeated(&debase64ed, key);
    assert_eq!(clear, bytes);
    let _ = match fs::write("rabbit.base64", &base64ed) {
        Ok(_) => (),
        Err(_) => ()
    };
}

fn transpose_blocks(keysize: usize, data : &[u8]) -> Vec<Vec<u8>> {
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

fn main() {
    //_write_rabbit();
    //let path = "rabbit.txt";
    //let path = "rabbit.base64";
    let path = "6.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode(&content);
    //let bytes = content.as_bytes();
    let mut sizes = get_sizes(&bytes);
    //let keysize = sizes[0].keysize;
    let _ = sizes.split_off(5);
    println!("try sizes {:?}", sizes);
    //let keysizes = vec![2,3,4,5,6,7];
    let mut scores = Vec::new();
    for keysize in sizes {
        println!("assumed keysize {:?}", keysize);
        let transposed = transpose_blocks(keysize.keysize, &bytes);
        let mut keybytes = Vec::new();
        for block in transposed {
            let (_decrypted, keybyte) = xor::decrypt_byte(&block);
            keybytes.push(keybyte);
        }
        //println!("keybytes {:?}", keybytes);
        //println!("keybytes {:?}", text::bytes(&keybytes));
        let decrypted = xor::xor_repeated(&bytes, &keybytes);
        let score = xor::score(&decrypted);
        let text = text::bytes(&decrypted);
        scores.push(KeysizeScore::new(keysize.keysize, score, text));
        //println!("decrypted {:?}", text::bytes(&decrypted));
        //println!(" ");
    }
    scores.sort_by(|a,b| a.score.cmp(&b.score));
    println!("scores {:?}", scores);
    println!("decrypted {}", scores[0].text);
}
