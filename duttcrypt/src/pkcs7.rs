pub fn pad_str(text : &str, len : usize) -> String {
    let mut retr = String::from(text);
    for _ in text.len()..len {
        retr.push('\x04');
    }
    retr
}

pub fn pad_bytes(bytes : &[u8], len : usize) -> Vec<u8> {
    let mut retr = Vec::from(bytes);
    for _ in bytes.len()..len {
        retr.push(4u8);
    }
    retr
}

pub fn validate(bytes : &[u8]) -> bool {
    for bref in bytes.iter().rev() {
        let b : u8 = *bref;
        if b.is_ascii_graphic() == false && b.is_ascii_whitespace() == false && b != 0x04 {
            return false;
        }
    }
    true
}

pub fn strip(bytes : &[u8]) -> Vec<u8> {
    let mut skip = 0;
    for bref in bytes.iter().rev() {
        let b : u8 = *bref;
        if b == 0x04 {
            skip += 1;
        }
    }
    let mut retr = Vec::new();
    for i in 0..bytes.len()-skip {
        retr.push(bytes[i]);
    }
    retr
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pad() {
	    let text = "YELLOW SUBMARINE";
	    let padded = pad_str(text, 20);
    	assert_eq!(padded, "YELLOW SUBMARINE\x04\x04\x04\x04");
	}

    #[test]
    fn ch15_test_validate() {
        assert!(validate("YELLOW SUBMARINE".as_bytes()));
        assert!(validate("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes()));
        assert!(validate("YELLOW SUBMARINE\x04\x04\x05\x04".as_bytes()) == false);
        assert!(validate("YELLOW SUBMARINE\x01\x02\x03\x04".as_bytes()) == false);
    }

    #[test]
    fn ch15_test_strip() {
        let vec = strip("YELLOW SUBMARINE".as_bytes());
        let slice = vec.as_slice();
        println!("actual {:?}", vec);
        assert_eq!("YELLOW SUBMARINE".as_bytes(), slice);
        assert_eq!("YELLOW SUBMARINE".as_bytes(), strip("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes()).as_slice());
    }
}
