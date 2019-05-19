use std::collections::HashMap;

//use duttcrypt::binary;
//use duttcrypt::base64;
//use duttcrypt::xor;
//use duttcrypt::hex;
use duttcrypt::text;
use duttcrypt::aes;

fn profile_for(email : &str) -> HashMap<String, String> {
    let mut data = String::from(email);
    data = data.replace("&", "");
    data = data.replace("=", "");
    data = format!("email={}&uid=10&role=user", data);
    parse(&data)
}

fn parse(text : &str) -> HashMap<String, String> {
    println!("parsing {:?}", text);
    let mut retr = HashMap::new();
    let textstr = String::from(text);
    let parts : Vec<_> = textstr.split('&').collect();
    for p in parts {
        let subparts : Vec<_> = p.split('=').collect();
        let name = String::from(subparts[0]);
        let value = String::from(subparts[1]);
        retr.insert(name, value);
    }
    retr
}

fn encode(data : HashMap<String, String>) -> String {
    let mut retr = String::new();
    for k in data.keys() {
        if retr.len() > 0 {
            retr += "&";
        }
        let val = data.get(k).unwrap();
        retr += &format!("{}={}", k, val);
    }
    retr
}

fn main() {
    let key = aes::generate_key();
    let data = profile_for("bob@bob.com");
    println!("{:?}", data);
    let encoded = encode(data);
    println!("encoded {:?}", encoded);
    let encrypted = aes::encrypt_ecb(encoded.as_bytes(), &key);
    let decrypted = aes::decrypt_ecb(&encrypted, &key);
    println!("decrypted {:?}", text::bytes(&decrypted));
}
