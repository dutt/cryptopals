use super::aes;

pub fn encrypt_with_postfix(data : &[u8], key : &[u8], postfix : &[u8]) -> Vec<u8> {
    let mut full_data = Vec::from(data);
    full_data.extend(postfix);
    let padded = aes::pad_data(&full_data);
    aes::encrypt_ecb(&padded, &key)
}

pub fn guess_mode(data : &[u8]) -> String {
    for i in 0..15 {
        let mut v = Vec::from(data);
        v = v.split_off(i);
        v.truncate(v.len() - i);
        let guess = aes::is_ecb(&v);
        if guess.1 > guess.2 && guess.1 - guess.2 > 1 {
            return String::from("ecb")
        }
    }
    String::from("cbc")
}

pub fn guess_blocksize(key : &[u8]) -> usize {
    let mut datastr = String::from("A");
    let data = Vec::new();
    let padded = aes::pad_data(&data);
    let encrypted = aes::encrypt_ecb(&padded, &key);
    let mut last_enc_size = encrypted.len();
    for i in 2..15 {
        for _ in 0..i {
            datastr.push('A');
            let data = datastr.as_bytes();
            let padded = aes::pad_data(&data);
            let encrypted = aes::encrypt_ecb(&padded, &key);
            if encrypted.len() != last_enc_size {
                return encrypted.len() - last_enc_size
            }
            last_enc_size = encrypted.len()
        }
    }
    0
}
