extern crate aes;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;


pub fn decrypt_ecb(bytes: &[u8], key: &str) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let cipher = Aes128::new(&key);
    let mut decrypted : Vec<u8> = Vec::new();
    for chunk in bytes.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend(block.iter());

    }
    decrypted
}
