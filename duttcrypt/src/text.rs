use super::binary;

pub fn bytes(bytes: &[u8]) -> String {
    let mut retr = String::new();
    for &b in bytes {
        retr.push(b as char);
    }
    retr
}

pub fn hamming(a: &str, b : &str) -> u32 {
    binary::hamming(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming() {
        assert_eq!(0, hamming("a", "a"));
        assert_eq!(2, hamming("a", "b"));
        assert_eq!(37, hamming("this is a test", "wokka wokka!!!"));
    }
}
