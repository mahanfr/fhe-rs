use crate::{
    fhe::FHEParams,
    sampling::{fhe_sample, FHESamplingMethod}, utils::{encode_base_p, poly_add, poly_mul},
};

#[derive(Debug, Clone)]
pub struct GLWECiphertext {
    body: Vec<i64>
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
    b: Vec<i64>
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

    pub fn gen_secret_key(&self) -> GLWESecretKey {
        let mut s = Vec::with_capacity(self.params.k);
        for _ in 0..self.params.k {
            s.push(fhe_sample(self.sec_sampling_method, self.params.n));
        }
        GLWESecretKey { s }
    }

    pub fn gen_keypair(&self) -> (GLWESecretKey, GLWEPublicKey) {
        let sec_key = self.gen_secret_key();
        let mut as_sum: Vec<i64> = Vec::new();
        let mut a_vec: Vec<Vec<i64>> = Vec::new();
        for i in 0..self.params.k {
            let a = fhe_sample(
                FHESamplingMethod::Uniform(self.params.q / 2, self.params.q / 2),
                self.params.n as usize
            );
            poly_add(
                &self.params, 
                &mut as_sum,
                &poly_mul(&self.params, &a, &sec_key.s[i])
            );
            a_vec.push(a);
        }
        let e = fhe_sample(FHESamplingMethod::Gaussian(self.params.std_dev), self.params.n);
        poly_add(&self.params, &mut as_sum, &e);
        (sec_key, GLWEPublicKey {a: a_vec, b: as_sum})
    }

    pub fn encrypt_with_secret(&self, sec_key: GLWESecretKey, data: Vec<u8>) {
        let mut pt = encode_base_p(&data, self.params.p);
        pt.resize(self.params.n as usize, 0);
        let delta_m: Vec<i64> = pt.iter().map(|x| x * self.params.delta()).collect();
        let mut as_sum: Vec<i64> = Vec::new();
        for i in 0..self.params.k {
            let a = fhe_sample(
                FHESamplingMethod::Uniform(self.params.q / 2, self.params.q / 2),
                self.params.n as usize
            );
            poly_add(
                &self.params, 
                &mut as_sum,
                &poly_mul(&self.params, &a, &sec_key.s[i])
            );
        }
        let e = fhe_sample(FHESamplingMethod::Uniform(0, self.params.delta() / 2), self.params.n);
        poly_add(&self.params, &mut as_sum, &delta_m);
        poly_add(&self.params, &mut as_sum, &e);

    }

}

