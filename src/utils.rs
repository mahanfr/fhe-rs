/// Encodes each byte from `data` into base-p digits (least significant first),
/// returning a Vec<i64> of digits, along with digits per byte.
///
/// Works safely for all u8 values, even when p < 256.
pub fn encode_base_p(data: &[u8], p: u64) -> Vec<i64> {
    if p > 0xFF {
        return data.iter().map(|i| *i as i64).collect();
    }
    assert!(p >= 2, "Plaintext modulus p must be ≥ 2");
    let digits_per_byte = ((255.0f32).ln() / (p as f32).ln()).ceil() as usize;

    let mut encoded = Vec::with_capacity(data.len() * digits_per_byte);
    for &b in data {
        let mut rem = b as i64;
        for _ in 0..digits_per_byte {
            encoded.push(rem % p as i64);
            rem /= p as i64;
        }
    }
    encoded
}

/// Decodes a slice of base-p digits (stored as i64) back into the original Vec<u8>.
/// Always succeeds for valid input.
pub fn decode_base_p(encoded: &[i64], p: u64) -> Vec<u8> {
    assert!(p >= 2, "Plaintext modulus p must be ≥ 2");
    if p > 0xFF {
        return encoded.iter().map(|i| (*i & 0xff) as u8).collect();
    }
    let digits_per_byte = ((255.0f32).ln() / (p as f32).ln()).ceil() as usize;
    assert!(encoded.len() % digits_per_byte == 0, "Invalid encoded length");

    let mut decoded = Vec::with_capacity(encoded.len() / digits_per_byte);
    let p32 = p as u32;

    for chunk in encoded.chunks(digits_per_byte) {
        let mut value: u32 = 0;
        let mut base: u32 = 1;
        for &digit in chunk {
            value += (digit as u32) * base;
            base *= p32;
        }
        decoded.push(value as u8); // safe: value ≤ 255
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_encoding() {
        let data = vec![200u8, 123, 255];
        let p = 5u64;
        let encoded = encode_base_p(&data, p);
        let decoded = decode_base_p(&encoded, p);
        assert_eq!(data, decoded);

        let data = "Hello world!\n";
        let p = 8u64;
        let encoded = encode_base_p(&data.as_bytes(), p);
        let decoded = decode_base_p(&encoded, p);
        assert_eq!(data.as_bytes(), decoded);

        let data = "Encodable message!\n";
        let p = 512u64;
        let encoded = encode_base_p(&data.as_bytes(), p);
        let decoded = decode_base_p(&encoded, p);
        assert_eq!(data.as_bytes(), decoded);
    }
}
