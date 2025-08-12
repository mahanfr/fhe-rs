use crate::fhe::FHEParams;

/// Polynumial multiplication
pub fn poly_add(params: &FHEParams, vec1: &mut Vec<i64>, vec2: &Vec<i64>) {
    for i in 0..params.n {
        vec1[i] = (vec1[i] + vec2[i]) % params.q;
    }
}

/// Polynumial multiplication
pub fn poly_mul(params: &FHEParams, vec1: &Vec<i64>, vec2: &Vec<i64>) -> Vec<i64> {
    let mut res: Vec<i64> = Vec::with_capacity(params.n);
    let us_n = params.n;
    for i in 0..us_n {
        for j in 0..us_n {
            let k = (i + j) % us_n;
            let mut coef = vec1[i] * vec2[j];
            if i + j >= us_n {
                coef *= -1;
            }
            res[k] = (res[k] + coef) % params.q;
        }
    }
    res
}

/// Encodes each byte from `data` into base-p digits (least significant first),
/// returning a Vec<i64> of digits, along with digits per byte.
///
/// Works safely for all u8 values, even when p < 256.
pub fn encode_base_p(data: &[u8], p: i64) -> Vec<i64> {
    if p > 0xFF {
        return data.iter().map(|i| *i as i64).collect();
    }
    assert!(p >= 2, "Plaintext modulus p must be ≥ 2");
    let digits_per_byte = ((255.0f32).ln() / (p as f32).ln()).ceil() as usize;

    let mut encoded = Vec::with_capacity(data.len() * digits_per_byte);
    for &b in data {
        let mut rem = b as i64;
        for _ in 0..digits_per_byte {
            let mut val = rem % p;
            if p > 2 {
                val += -(p / 2);
            }
            encoded.push(val);
            rem /= p;
        }
    }
    encoded
}

/// Decodes a slice of base-p digits (stored as i64) back into the original Vec<u8>.
/// Always succeeds for valid input.
pub fn decode_base_p(encoded: &[i64], p: i64) -> Vec<u8> {
    assert!(p >= 2, "Plaintext modulus p must be ≥ 2");
    if p > 0xFF {
        return encoded.iter().map(|i| (*i & 0xff) as u8).collect();
    }
    let digits_per_byte = ((255.0f32).ln() / (p as f32).ln()).ceil() as usize;
    assert!(
        encoded.len() % digits_per_byte == 0,
        "Invalid encoded length"
    );

    let mut decoded = Vec::with_capacity(encoded.len() / digits_per_byte);

    for chunk in encoded.chunks(digits_per_byte) {
        let mut value: i64 = 0;
        let mut base: i64 = 1;
        for &ed in chunk {
            let mut digit = ed;
            if p > 2 {
                digit += p / 2;
            }
            value += digit * base;
            base *= p;
        }
        decoded.push((value & 0xFF) as u8); // safe: value ≤ 255
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_encoding() {
        let data = vec![200u8, 123, 255];
        let p = 5i64;
        let encoded = encode_base_p(&data, p);
        let decoded = decode_base_p(&encoded, p);
        assert_eq!(data, decoded);

        let data = "Hello world!\n";
        let p = 8i64;
        let encoded = encode_base_p(data.as_bytes(), p);
        let decoded = decode_base_p(&encoded, p);
        assert_eq!(data.as_bytes(), decoded);

        let data = "Encodable message!\n";
        let p = 512i64;
        let encoded = encode_base_p(data.as_bytes(), p);
        let decoded = decode_base_p(&encoded, p);
        assert_eq!(data.as_bytes(), decoded);
    }
}
