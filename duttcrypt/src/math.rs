pub fn find_nearest_16(len: usize) -> usize {
    if len % 16 == 0 {
        return len;
    }
    let rem = len / 16;
    let retr = (rem+1) * 16;
    retr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_nearest_16() {
        assert_eq!(16, find_nearest_16(1));
        assert_eq!(16, find_nearest_16(15));
        assert_eq!(16, find_nearest_16(16));

        assert_eq!(32, find_nearest_16(31));
        assert_eq!(32, find_nearest_16(32));
    }
}
