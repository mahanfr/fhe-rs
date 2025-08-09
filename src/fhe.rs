#[derive(Debug, Clone, Copy)]
pub struct FHEParams {
    /// Ciphertext modules
    /// Usually a large prime number
    pub q: u128,
    /// Plaintext modules
    /// Domain of plaintext vector
    pub p: u64,
    /// Polynomial degree
    pub n: u64,
    /// Scale of secret key operations
    pub k: u64,
}

impl FHEParams {
    pub fn new_lwe(q: u128, p: u64, k: u64) -> Self {
        Self { q, p, k, n: 1 }
    }

    pub fn new_rlwe(q: u128, p: u64, n: u64) -> Self {
        Self { q, p, k: 1, n }
    }

    pub fn delta(&self) -> u128 {
        self.q / self.p as u128
    }
}
