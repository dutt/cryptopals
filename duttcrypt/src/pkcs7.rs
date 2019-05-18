fn pad(text : &str, len : usize) -> String {
    let mut retr = String::from(text);
    for _ in text.len()..len {
        retr.push('\x04');
    }
    retr
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pad() {
	    let text = "YELLOW SUBMARINE";
	    let padded = pad(text, 20);
    	assert_eq!(padded, "YELLOW SUBMARINE\x04\x04\x04\x04");
	}
}