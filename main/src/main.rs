extern crate sha1;

//use sha1::{Sha1, Digest};
use sha1::{Sha1, Digest};

fn get_sig(digest : Digest) -> Vec<u8> {
    let mut retr = Vec::new();
    retr.extend(digest.bytes().iter());
    retr
}

fn sign(key : &[u8], message : &[u8]) -> (Digest, Vec<u8>) {
    let mut hasher = Sha1::new();
    //hasher.input(key);
    //hasher.input(message);
    //hasher.result().to_vec()
    hasher.update(key);
    hasher.update(message);
    let digest = hasher.digest();
    (digest, get_sig(hasher.digest()))
}

fn verify(key : &[u8], message : &[u8], sig : &[u8]) -> bool {
    let mut hasher = Sha1::new();
    //hasher.input(key);
    //hasher.input(message);
    hasher.update(key);
    hasher.update(message);
    //let r : &[u8] = &hasher.result();
    let r : &[u8] = &hasher.digest().bytes();
    r == sig
}

fn calculate_padding_len(data : &[u8]) -> u32 {
    let len : u32 = (data.len() as u32 % 512) * 8;
    let mut max = 512;
    loop {
        if len > max {
            max += 512;
        } else {
            max -= 64;
            return max - (1+len);
        }
    }
}

fn pad_data(data : &[u8]) -> Vec<u8> {
    let pad_len = calculate_padding_len(data);
    let odd = pad_len % 8;
    let mut retr = Vec::new();
    retr.extend(u64::to_be_bytes(data.len() as u64 * 8).iter());
    retr
}

fn main() {
    //let mut hasher = Sha1::new();
    ////hasher.input(b"foo");
    ////println!("{:x?}", hasher.result());
    assert_eq!(423, calculate_padding_len(b"abc"));
    //hasher.update(b"foo");
    //let digest = hasher.digest();
    let key = b"velysecret!";
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let msg_size = msg.len() * 8;
    //let msg_size = 704;
    println!("msg size {:?}", msg_size);
    println!("creating orig digest");
    let (digest, _sig) = sign(key, msg);
    //assert!(verify(key, msg, &sig));
    //assert!(verify(key, b"foobaa", &sig) == false);
    //assert!(verify(b"otherkey", msg, &sig) == false);

    let first_padding_len = calculate_padding_len(msg);
    println!("first_padding_len {:?}", first_padding_len);

    let extra_msg = b";admin=true";
    let mut h2 = Sha1::from_registers(digest.registers());
    //let padding = get_padding(extra_msg);
    println!("adding glue");
    h2.update(&u64::to_be_bytes(msg_size as u64));
    println!("adding admin");
    h2.update(extra_msg);
    let digest = h2.digest();

    let full_new_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true";
    assert!(verify(key, full_new_msg, &digest.bytes()));
}

fn _str_to_vec(text : &str) -> Vec<u8> {
    let chars : Vec<_> = text.chars().collect();
    let pairs : Vec<String> = chars.chunks(2).map(|p| p[0].to_string() + &p[1].to_string()).collect();
    let data : Vec<u8> = pairs.iter().map(|p| u8::from_str_radix(p, 16).unwrap()).collect();
    data
}
