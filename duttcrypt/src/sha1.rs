use sha1::{Sha1, Digest};

pub fn sign(key : &[u8], message : &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.input(key);
    hasher.input(message);
    let mut retr = Vec::new();
    retr.extend(hasher.result().iter());
    retr
}

pub fn verify(key : &[u8], message : &[u8], sig : &[u8]) -> bool {
    let mut hasher = Sha1::new();
    hasher.input(key);
    hasher.input(message);
    let r : &[u8] = &hasher.result();
    r == sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ch28_sha1_signing() {
        let sig = sign(b"key", b"foobar");
        assert!(verify(b"key", b"foobar", &sig));
        assert!(verify(b"key", b"foobaa", &sig) == false);
        assert!(verify(b"kee", b"foobar", &sig) == false);
    }
}
