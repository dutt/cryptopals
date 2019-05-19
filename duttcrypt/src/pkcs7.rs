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


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pad() {
	    let text = "YELLOW SUBMARINE";
	    let padded = pad_str(text, 20);
    	assert_eq!(padded, "YELLOW SUBMARINE\x04\x04\x04\x04");
	}
}
