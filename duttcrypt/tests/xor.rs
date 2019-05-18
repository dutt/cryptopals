use std::fs;
use std::thread;

use duttcrypt::hex;
use duttcrypt::xor;
use duttcrypt::text;
use duttcrypt::base64;


#[test]
fn test_xor() {
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";
    assert_eq!(hex::format_hex_str(&xor::xor_bytes(&hex::parse_hex_str(a),
                                                   &hex::parse_hex_str(b))),
               "746865206b696420646f6e277420706c6179");
}

#[test]
fn test_decrypt_bytes() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = hex::parse_hex_str(ciphertext);
    let expected_bytes : Vec<u8> = vec![27, 55, 55, 51, 49, 54, 63, 120, 21, 27, 127, 43, 120, 52, 49, 51, 61, 120, 57, 120, 40, 55, 45, 54, 60, 120, 55, 62, 120, 58, 57, 59, 55, 54];
    assert_eq!(bytes, expected_bytes);
    let (result, _key) = xor::decrypt_byte(&bytes);
    let expected_result : Vec<u8> = vec![67, 111, 111, 107, 105, 110, 103, 32, 77, 67, 39, 115, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 117, 110, 100, 32, 111, 102, 32, 98, 97, 99, 111, 110];
    let cleartext = text::bytes(&result);
    assert_eq!(cleartext, "Cooking MC's like a pound of bacon");
    assert_eq!(result, expected_result);
}

fn runxor(l : String) -> (String, Vec<u8>, i32) {
    let bytes = hex::parse_hex_str(&l);
    let (result, _key) = xor::decrypt_byte(&bytes);
    let score = xor::score(&result);
    (l, result, score)
}

#[test]
fn run4() {
    let path = "4.txt";
    let content = fs::read_to_string(path).expect("Failed to read file");
    let lines : Vec<String> = content.split('\n').map(|line| line.to_owned()).collect();
    let mut min_score = i32::max_value();
    let mut min_line = String::new();
    let mut min_result = Vec::new();
    let mut handles : Vec<_> = Vec::new();
    for l in lines {
        let handle = thread::spawn(move || runxor(l) );
        handles.push(handle);
    }
    for h in handles {
        let (l, result, score) = h.join().unwrap();
        if score < min_score {
            min_score = score;
            min_result = result;
            min_line = l;
        }
    }
    let expected_result : Vec<u8> = vec![78, 111, 119, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 112, 97, 114, 116, 121, 32, 105, 115, 32, 106, 117, 109, 112, 105, 110, 103, 10];
    let decrypted = text::bytes(&min_result);
    assert_eq!(decrypted, "Now that the party is jumping\n");
    assert_eq!(min_result, expected_result);
    assert_eq!(min_line, "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f");
}

#[test]
fn xor_repeated() {
    let text = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let bytes = text.as_bytes();
    let key_bytes = "ICE".as_bytes();
    let encrypted = xor::xor_repeated(bytes, key_bytes);
    let expected_bytes = vec![11, 54, 55, 39, 42, 43, 46, 99, 98, 44, 46, 105, 105, 42, 35, 105, 58, 42, 60, 99, 36, 32, 45, 98, 61, 99, 52, 60, 42, 38, 34, 99, 36, 39, 39, 101, 39, 42, 40, 43, 47, 32, 67, 10, 101, 46, 44, 101, 42, 49, 36, 51, 58, 101, 62, 43, 32, 39, 99, 12, 105, 43, 32, 40, 49, 101, 40, 99, 38, 48, 46, 39, 40, 47];
    assert_eq!(encrypted, expected_bytes);
    let hex = hex::format_hex_str(&encrypted);
    let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(hex, expected_hex);
}

#[test]
fn break_xor_repeated() {
    let path = "6.txt";
    let content = fs::read_to_string(path).expect("Failed to read file").replace("\n","");
    let bytes = base64::decode(&content);
    let result = xor::decrypt_bytes(&bytes);
    assert!(result.score >= 3515 and result.score <= 3525);
    assert_eq!(&result.text[0..33], "I'm back and I'm ringii' the bell");
}
