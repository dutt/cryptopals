pub fn parse_hex_str(hex_str: &str) -> Vec<u8> {
    let chars : Vec<_> = hex_str.chars().collect();
    chars.chunks(2).map(|chunk| {
        let first = chunk[0].to_digit(16).unwrap();
        let second = chunk[1].to_digit(16).unwrap();
        ((first << 4) | second) as u8
    }).collect()
}

pub fn format_hex_str(data : &[u8]) -> String {
    let mut retr = String::new();
    for b in data {
        retr.push_str(&format!("{:02x}", b));
    }
    retr
}
