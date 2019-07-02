pub fn pad_str(text : &str, len : usize) -> String {
    let bytes = text.as_bytes();
    let padded = pad_bytes(bytes, len);
    let text = String::from_utf8(padded).unwrap();
    text
}

pub fn pad_bytes(bytes : &[u8], len : usize) -> Vec<u8> {
    let mut retr = Vec::from(bytes);
    let val = len - bytes.len();
    for _ in bytes.len()..len {
        retr.push(val as u8);
    }
    retr
}

pub fn validate(bytes : &[u8]) -> bool {
    let count = bytes[bytes.len()-1];
    if count > 16 { // no padding
        return true
    }
    let mut matches = 0;
    for bref in bytes.iter().rev() {
        let b : u8 = *bref;
        if count <= matches {
            return true
        }
        else if count == b {
            matches += 1;
        } else {
            return false;
        }
        //if b.is_ascii_graphic() == false && b.is_ascii_whitespace() == false && b != count {
        //    return false;
        //}
    }
    true
}

pub fn strip(bytes : &[u8]) -> Vec<u8> {
    let mut skip = 0;
    let val = bytes[bytes.len()-1];
    if val > 16 {
        return Vec::from(bytes);
    }
    for bref in bytes.iter().rev() {
        let b : u8 = *bref;
        if b == val {
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

        let text = "YELLOW SUBMARIN";
        let padded = pad_str(text, 16);
        assert_eq!(padded, "YELLOW SUBMARIN\x01");

        let text = "YELLOW SUBMARI";
        let padded = pad_str(text, 16);
        assert_eq!(padded, "YELLOW SUBMARI\x02\x02");

        let text = "YELLOW SUBMAR";
        let padded = pad_str(text, 16);
        assert_eq!(padded, "YELLOW SUBMAR\x03\x03\x03");

        let text = "YELLOW SUBMA";
        let padded = pad_str(text, 16);
        assert_eq!(padded, "YELLOW SUBMA\x04\x04\x04\x04");
    }

    #[test]
    fn ch15_test_validate() {
        assert!(validate("YELLOW SUBMARINE".as_bytes()));
        assert!(validate("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes()));
        assert!(validate("YELLOW SUBMARIN\x01".as_bytes()));
        assert!(validate("YELLOW SUBMARI\x02\x02".as_bytes()));
        assert!(validate("YELLOW SUBMAR\x03\x03\x03".as_bytes()));
        assert!(validate("YELLOW SUBMA\x04\x04\x04\x04".as_bytes()));
        assert!(validate("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes()));
        assert!(validate("YELLOW SUBMARINE\x03\x03".as_bytes()) == false);
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
