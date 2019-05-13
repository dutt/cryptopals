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
    //let _ = match fs::write("rabbit.base64", &base64ed) {
    //    Ok(_) => (),
    //    Err(_) => ()
    //};
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
    let hamming = binary::hamming(a, b);
    let norm_dist = hamming as f32 / keysize as f32;
    KeySize::new(keysize, norm_dist)
}

fn get_sizes(bytes : &[u8]) -> Vec<KeySize> {
    let mut sizes = Vec::new();
    for keysize in 2.. 15 {
        println!("keysize {}", keysize);
        sizes.push(get_keydistance(keysize, &bytes));
        println!(" ");
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
    _write_rabbit();
    let path = "rabbit.base64";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode(&content);
    let sizes = get_sizes(&bytes);
    for s in &sizes {
        println!("s {:?}", s);
    }
    let keysize = sizes[0].keysize;

    println!("assumed keysize {:?}", keysize);
    let transposed = transpose_blocks(keysize, &bytes);
    let mut keybytes = Vec::new();
    for block in transposed {
        let (_decrypted, keybyte) = xor::decrypt_byte(&block);
        keybytes.push(keybyte);
    }
    println!("keybytes {:?}", keybytes);
    println!("keybytes {:?}", text::bytes(&keybytes));
    let decrypted = xor::xor_repeated(&bytes, &keybytes);
    println!("decrypted {:?}", text::bytes(&decrypted));
}
