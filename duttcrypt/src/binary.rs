use std::cmp;

use super::binary;

pub fn count_bits(val : u32) -> u32 {
    let i = val - ((val >> 1) & 0x55555555);
    let i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
    let i = (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
    return i as u32
}

pub fn hamming(a: &[u8], b : &[u8]) -> u32 {
    let len = cmp::min(a.len(), b.len());
    let mut sum = 0;
    for i in 0..len {
        let val = (a[i]) ^ (b[i]);
        sum += binary::count_bits(val as u32);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_bits() {
        assert_eq!(count_bits(1), 1);
        assert_eq!(count_bits(3), 2);
        assert_eq!(count_bits(4), 1);
        assert_eq!(count_bits(5), 2);
        assert_eq!(count_bits(9), 2);
        assert_eq!(count_bits(128), 1);
    }

    #[test]
    fn test_hamming() {
        let a = vec![1];
        let b = vec![0];
        assert_eq!(1, hamming(&a, &b));
        let a = vec![1];
        let b = vec![2];
        assert_eq!(2, hamming(&a, &b));
        let a = vec![1,2,3];
        let b = vec![2,4,6];
        assert_eq!(6, hamming(&a, &b));
    }
}
