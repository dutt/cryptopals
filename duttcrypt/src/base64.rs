pub fn encode(bytes : &[u8]) -> String {
    let mut retr = String::new();
    let alphabet : Vec<_> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".chars().collect();
    for chunk in bytes.chunks(3) {
        // first character
        let c0 = chunk[0];
        let b = (c0 & 0xFC) >> 2;
        retr.push(alphabet[b as usize]);

        // second character
        let mut b = (c0 & 0x03) << 4;
        if let Some(c1) = chunk.get(1) {
            b |= (c1 & 0xF0) >> 4;
            retr.push(alphabet[b as usize]);

            // third character
            let mut b = (c1 & 0x0F) << 2;
            if let Some(c2) = chunk.get(2) {
                b |= (c2 & 0xC0) >> 6;
                retr.push(alphabet[b as usize]);

                // fourth character
                let b = c2 & 0x3F;
                retr.push(alphabet[b as usize]);
            } else {
                retr.push(alphabet[b as usize]);
                retr.push('=');
            }
        } else {
            retr.push(alphabet[b as usize]);
            retr.push_str("==");
        }
    }
    retr
}

pub fn decode(b64text: &str) -> Vec<u8> {
    let mut clear = Vec::new();
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let chars : Vec<_> = b64text.chars().map(|x| alphabet.find(x).unwrap() as u8).collect();
    for chunk in chars.chunks(4) {
        let mut a = (chunk[0] as u16) << 2;
        let a2 = (chunk[1] as u16) & 0b110000;
        let a2 = a2 >> 4;
        a = a | a2;
        clear.push(a as u8);

        let b_masked = (chunk[1] & 0b001111) as u16;
        let mut b = b_masked << 4;
        if let Some(chunk2) = chunk.get(2) {
            if *chunk2 != 64 { // third character not padding
                b = b | (chunk2 >> 2) as u16;
                clear.push(b as u8);

                let mut c = (chunk2 & 0b11) << 6;
                if let Some(chunk3) = chunk.get(3) {
                    if *chunk3 != 64 { //fourth character not padding
                        c = c | chunk3;
                        clear.push(c as u8);
                    } else if c != 0{ //fourth character is padding
                        clear.push(c as u8);
                    }
                } else if c != 0 { //no fourth character
                    clear.push(c as u8);
                }
            } else if b != 0 { //third character is padding
                clear.push(b as u8);
            }
        } else if b != 0 { //no third character
            clear.push(b as u8);
        }
    }
    clear
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        let bytes = vec![1,2];
        assert_eq!(encode(&bytes), "AQI=");

        let bytes = vec![6,5,4];
        assert_eq!(encode(&bytes), "BgUE");

        let bytes = vec![97];
        assert_eq!(encode(&bytes), "YQ==");
    }

    #[test]
    fn test_decode() {
        let expected = vec![97, 97, 97];
        assert_eq!(decode("YWFh"), expected);

        let expected = vec![6,5,4];
        assert_eq!(decode("BgUE"), expected);

        let expected = vec![97];
        assert_eq!(decode("YQ=="), expected);
    }
}
