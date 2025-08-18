use crate::{
    fhe::FHEParams,
    sampling::{fhe_sample, FHESamplingMethod},
    utils::{center_to_signed, decompose_balanced, div_round_signed, encode_base_p, mod_q_i64, poly_add, poly_mul},
};

#[derive(Debug, Clone)]
pub struct GLWECiphertext {
    d: Vec<Vec<i64>>,
    b: Vec<i64>,
}

impl GLWECiphertext {

    fn zero(params: &FHEParams) -> Self {
        GLWECiphertext {
            b: vec![0i64; params.n],
            d: (0..params.k).map(|_| vec![0i64; params.n]).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GLWESecretKey {
    s: Vec<Vec<i64>>,
}

impl GLWESecretKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for si in self.s.iter() {
            for chunk in si.chunks(8) {
                let mut byte = 0;
                let mut base = 7;
                for bit in chunk {
                    byte |= ((bit & 0xff) as u8) << base;
                    base -= 1;
                }
                bytes.push(byte);
            }
        }
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct GLWEPublicKey {
    a: Vec<Vec<i64>>,
    b: Vec<i64>,
}

#[derive(Debug, Clone)]
pub struct GLWECrypto {
    params: FHEParams,
    sec_sampling_method: FHESamplingMethod,
}

impl GLWECrypto {
    pub fn new(params: FHEParams) -> Self {
        Self {
            params,
            sec_sampling_method: FHESamplingMethod::UniformBinary,
        }
    }

    fn gen_secret_key(&self) -> GLWESecretKey {
        let mut s = Vec::with_capacity(self.params.k);
        for _ in 0..self.params.k {
            s.push(fhe_sample(self.sec_sampling_method, self.params.n));
        }
        GLWESecretKey { s }
    }

    fn gen_error(&self) -> Vec<i64> {
        let error_sample = fhe_sample(
            FHESamplingMethod::Gaussian(self.params.std_dev),
            self.params.n,
        );
        error_sample.iter().map(|x| x % (self.params.delta() / 2)).collect()
    }

    pub fn gen_keypair(&self) -> (GLWESecretKey, GLWEPublicKey) {
        let sec_key = self.gen_secret_key();
        let mut as_sum: Vec<i64> = Vec::new();
        let mut a_vec: Vec<Vec<i64>> = Vec::new();
        for i in 0..self.params.k {
            let a = fhe_sample(
                FHESamplingMethod::Uniform(-self.params.q / 2, self.params.q / 2),
                self.params.n,
            );
            poly_add(
                &self.params,
                &mut as_sum,
                &poly_mul(&self.params, &a, &sec_key.s[i]),
            );
            a_vec.push(a);
        }
        let e = self.gen_error();
        poly_add(&self.params, &mut as_sum, &e);
        (
            sec_key,
            GLWEPublicKey {
                a: a_vec,
                b: as_sum,
            },
        )
    }

    pub fn encrypt(&self, pub_key: &GLWEPublicKey, data: Vec<u8>) -> GLWECiphertext {
        println!("original: {:?}",data);
        let mut pt = encode_base_p(&data, self.params.p);
        println!("pt-encoded: {:?}",pt);
        pt.resize(self.params.n, 0);
        let u = fhe_sample(FHESamplingMethod::UniformBinary, self.params.n);
        println!("U: {:?}", u);
        let delta_m: Vec<i64> = pt.iter().map(|x| x * self.params.delta()).collect();
        let e1 = self.gen_error();
        println!("E1: {:?}", e1);
        let mut b = poly_mul(&self.params, &pub_key.b, &u);
        poly_add(&self.params, &mut b, &delta_m);
        poly_add(&self.params, &mut b, &e1);

        let mut d: Vec<Vec<i64>> = Vec::new();
        for i in 0..self.params.k {
            let e2 = self.gen_error(); 
            let mut pka_dot_u = poly_mul(&self.params, &pub_key.a[i], &u);
            poly_add(&self.params, &mut pka_dot_u, &e2);
            d.push(pka_dot_u);
        }
        GLWECiphertext { b, d }
    }

    pub fn decrypt(&self, secret_key: &GLWESecretKey, ciphertext: GLWECiphertext) -> Vec<i64> {
        let q = self.params.q;
        let delta = self.params.delta();
        let mut ds_sum = Vec::new();
        for i in 0..self.params.k {
            poly_add(
                &self.params,
                &mut ds_sum,
                &poly_mul(&self.params, &ciphertext.d[i], &secret_key.s[i]),
            );
        }
        let mut sacled_pt: Vec<i64> = vec![0i64; self.params.n];
        for i in 0..self.params.n {
            let bi = ciphertext.b[i] as i128;
            let sterm = ds_sum[i] as i128;
            let r = bi - sterm;
            sacled_pt[i] = mod_q_i64(r, q);
        }
        let mut decoded_symbols: Vec<i64> = vec![0i64; self.params.n];
        for i in 0..self.params.n {
            let centered = center_to_signed(sacled_pt[i], q);
            let rounded = div_round_signed(centered, delta);
            decoded_symbols[i] = rounded;
        }
        decoded_symbols
    }

    pub fn add_ciphertexts(&self, c1: &GLWECiphertext, c2: &GLWECiphertext)
        -> GLWECiphertext {
        let n = self.params.n;
        let q = self.params.q;
        let mut b = vec![0i64; n];
        for i in 0..n { 
            let s = mod_q_i64(c1.b[i] as i128 + c2.b[i] as i128, q); 
            b[i] = mod_q_i64((s + q).into(), q);
        }
        let mut d = Vec::with_capacity(self.params.k);
        for i in 0..self.params.k {
            let mut di = vec![0i64; n];
            for j in 0..n {
                let s = mod_q_i64(c1.d[i][j] as i128 + c2.d[i][j] as i128, q);
                di[j] = mod_q_i64((s + q).into(), q);
            }
            d.push(di);
        }
        GLWECiphertext { b, d }
    }

    pub fn scale_ciphertext(&self, ct: &mut GLWECiphertext, c: i64) {
        for poly in ct.d.iter_mut() {
            for coeff in poly.iter_mut() {
                *coeff = (*coeff * c).rem_euclid(self.params.q);
            }
        }
        for coeff in ct.b.iter_mut() {
            *coeff = (*coeff * c).rem_euclid(self.params.q);
        }
    }

    pub fn multiply_decomposed(&self, ct: &GLWECiphertext, m_poly: &Vec<i64>, base: i64, balanced:bool) -> GLWECiphertext {
        let q = self.params.q;
        // Find max number of digits among coefficients
        let max_digits = m_poly.iter().map(|&c| {
            let mut cc = c.abs();
            let mut d = 0usize;
            while cc > 0 { cc /= base; d += 1; }
            d.max(1)
        }).max().unwrap_or(1);

        let mut acc = GLWECiphertext::zero(&self.params);
        let mut pow = 1i128; // B^i

        for i in 0..max_digits {
            // build digit polynomial d_i(x) in Z_q
            let mut di_poly_q = vec![0i64; self.params.n];
            for j in 0..self.params.n.min(m_poly.len()) {
                // extract i-th digit of m_poly[j]
                let cij = m_poly[j];
                let digit = if balanced {
                    // reconstruct balanced digit at layer i
                    // easiest: decompose cij once; for brevity here’s a compact method:
                    // NOTE: for production, pre-decompose each cij outside this loop.
                    let digs = decompose_balanced(cij, base);
                    if i < digs.len() { digs[i] } else { 0 }
                } else {
                    let mut cc = cij.abs();
                    let mut k = 0;
                    let mut dval = 0i64;
                    while k <= i {
                        dval = (cc % base) as i64;
                        cc /= base;
                        k += 1;
                    }
                    if cij < 0 { -dval } else { dval }
                };

                // effective scalar for this position is digit * B^i
                let eff = ((digit as i128) * pow) % (q as i128);
                di_poly_q[j] = mod_q_i64(eff, q);
            }

            // ct * di_poly_q (negacyclic multiplication)
            let part_b = poly_mul(&self.params, &ct.b, &di_poly_q);
            let mut part_d = Vec::with_capacity(self.params.k);
            for t in 0..self.params.k {
                part_d.push(poly_mul(&self.params, &ct.d[t], &di_poly_q));
            }
            let part = GLWECiphertext { b: part_b, d: part_d };
            acc = add_ciphertexts(&self.params, &acc, &part);

            pow = (pow * (base as i128)) % (q as i128);
            if pow < 0 { pow += q as i128; }
        }
        acc
    }

    pub fn multyply_by_plaintext(&self, ct:&GLWECiphertext, pt: &Vec<i64>) -> GLWECiphertext {
        // Negacyclic conv using your (fixed) poly_mul
        let b = poly_mul(&self.params, &ct.b, pt);

        let mut d = Vec::with_capacity(self.params.k);
        for i in 0..self.params.k {
            d.push(poly_mul(&self.params, &ct.d[i], pt));
        }

        GLWECiphertext { b, d } 
    }

    pub fn lift_plain_poly_to_q(&self, m_poly_p: &Vec<i64>) -> Vec<i64> {
        let q = self.params.q;
        let mut v = m_poly_p.clone();
        if v.len() < self.params.n { v.resize(self.params.n, 0); } else if v.len() > self.params.n { v.truncate(self.params.n); }
        for c in v.iter_mut() {
            *c = ((*c % q) + q) % q;
        }
        v
    }

}

#[inline]
fn add_ciphertexts(params: &FHEParams, c1: &GLWECiphertext, c2: &GLWECiphertext) -> GLWECiphertext {
    let q = params.q as i128;
    let mut b = vec![0i64; params.n];
    for i in 0..params.n {
        let s = (c1.b[i] as i128 + c2.b[i] as i128) % q;
        b[i] = ((s + q) % q) as i64;
    }
    let mut d = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let mut di = vec![0i64; params.n];
        for j in 0..params.n {
            let s = (c1.d[i][j] as i128 + c2.d[i][j] as i128) % q;
            di[j] = ((s + q) % q) as i64;
        }
        d.push(di);
    }
    GLWECiphertext { b, d }
}
