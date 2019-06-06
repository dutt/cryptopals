use duttcrypt::pkcs7;
use duttcrypt::text;
use duttcrypt::aes;

fn make_data(userdata : &str, key : &[u8]) -> Vec<u8> {
    let mut encoded = String::from(userdata);
    encoded = encoded.replace(";", "%3B").replace("=", "%3D");
    let prefixstr = "comment1=cooking%20MCs;userdata=";
    let prefix = prefixstr.as_bytes();
    let postfixstr = ";comment2=%20like%20a%20pound%20of%20bacon";
    let postfix = postfixstr.as_bytes();

    let mut data = Vec::new();
    data.extend(prefix);
    data.extend(encoded.as_bytes());
    data.extend(postfix);

    let padded = aes::pad_data(&data);
    aes::encrypt_cbc(&padded, key, &key)
}

fn check_admin(encrypted : &[u8], key : &[u8]) -> bool {
    let padded_clearbytes = aes::decrypt_cbc(encrypted, key, key);
    println!("padded_clearbytes {:?}", padded_clearbytes);
    let clearbytes = pkcs7::strip(&padded_clearbytes);
    let cleartext = text::bytes(&clearbytes);
    println!("clearbytes {:?}", cleartext);
    let mut decoded  = String::from(cleartext);
    decoded = decoded.replace("%3B",";").replace("%3D", "=").replace("%20", " ");
    println!("decoded {}", decoded);
    let parts = decoded.split(";");
    for p in parts {
        println!("{:?}", p);
        if p == "admin=true" {
            return true
        }
    }
    false
}

fn flip(data : &[u8]) -> Vec<u8> {
    let mut retr = Vec::from(data);
    println!("retr {:?}", retr);
    retr[2] += 1;
    retr
}

fn main() {
    let key = aes::generate_key();
    let userdata = "testing";
    let data = make_data(userdata, &key);
    let flipped = flip(&data);
    //let is_admin = check_admin(&data, &key);
    //println!("is admin? {}", is_admin);
    let is_flipped_admin = check_admin(&flipped, &key);
    println!("is flipped admin? {}", is_flipped_admin);

}
