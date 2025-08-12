use crate::fhe::FHEParams;

/// normalize x into 0..q-1 (use i128 for safety)
#[inline]
pub fn mod_q_i64(x: i128, q: i64) -> i64 {
    let q_i = q as i128;
    let mut v = x % q_i;
    if v < 0 { v += q_i; }
    v as i64
}

#[inline]
pub fn center_to_signed(c: i64, q: i64) -> i64 {
    if c > q/2 { c - q } else { c }
}

/// round-to-nearest for signed integers
#[inline]
pub fn div_round_signed(centered: i64, delta: i64) -> i64 {
    if centered >= 0 {
        ((centered as i128 + (delta as i128)/2) / (delta as i128)) as i64
    } else {
        -((( - (centered as i128) + (delta as i128)/2) / (delta as i128)) as i64)
    }
}

/// ensure vec is exactly length n (pads with zeros or truncates)
pub fn ensure_len(vec: &mut Vec<i64>, n: usize) {
    if vec.len() < n {
        vec.resize(n, 0);
    } else if vec.len() > n {
        vec.truncate(n);
    }
}


/// Polynumial multiplication
pub fn poly_add(params: &FHEParams, vec1: &mut Vec<i64>, vec2: &Vec<i64>) {
    ensure_len(vec1, params.n);
    let mut rhs = vec2.clone();
    ensure_len(&mut rhs, params.n);
    for i in 0..params.n {
        let sum = vec1[i] as i128 + rhs[i] as i128;
        vec1[i] = mod_q_i64(sum, params.q);
    }
}

/// Polynumial multiplication
pub fn poly_mul(params: &FHEParams, a: &Vec<i64>, b: &Vec<i64>) -> Vec<i64> {
    let n = params.n;
    let q = params.q;
    // ensure inputs are n long
    let mut aa = a.clone();
    let mut bb = b.clone();
    ensure_len(&mut aa, n);
    ensure_len(&mut bb, n);

    let mut res: Vec<i64> = vec![0i64; n];

    for i in 0..n {
        for j in 0..n {
            let k = (i + j) % n;
            // compute product in i128
            let mut prod = (aa[i] as i128) * (bb[j] as i128);
            // negacyclic reduction: x^n = -1 so if i+j >= n flip sign
            if i + j >= n {
                prod = -prod;
            }
            // add to accumulator, reduce modularly using i128
            let acc = res[k] as i128 + prod;
            res[k] = mod_q_i64(acc, q);
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
