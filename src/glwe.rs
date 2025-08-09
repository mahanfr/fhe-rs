use crate::{
    fhe::FHEParams,
    sampling::{fhe_sample, FHESamplingMethod},
};

#[derive(Debug, Clone)]
pub struct GLWESecretKey {
    s: Vec<Vec<i64>>,
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

    pub fn get_secret_key(&self) -> GLWESecretKey {
        let k = self.params.k as usize;
        let n = self.params.n as usize;
        let mut s = Vec::with_capacity(self.params.k as usize);
        for _ in 0..k {
            s.push(fhe_sample(self.sec_sampling_method, n));
        }
        GLWESecretKey { s }
    }

}

