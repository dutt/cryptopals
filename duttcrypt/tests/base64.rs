use duttcrypt::hex;
use duttcrypt::base64;

#[test]
fn test_hex_to_base64() {
  let bytes = hex::parse_hex_str("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
  let base64ed = base64::encode(&bytes);
  assert_eq!(base64ed, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}
