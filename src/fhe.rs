#[derive(Debug, Clone, Copy)]
pub struct FHEParams {
    /// Ciphertext modules
    /// Usually a large prime number
    pub q: i64,
    /// Plaintext modules
    /// Domain of plaintext vector
    pub p: i64,
    /// Polynomial degree
    pub n: usize,
    /// Scale of secret key operations
    pub k: usize,
    /// Security level
    pub security_level: u64,
    /// Standard Deviation for error generation
    pub std_dev: f32,
}

impl Default for FHEParams {
    fn default() -> Self {
        Self {
            q: 1024,
            p: 2,
            k: 1,
            n: 8,
            security_level: 256,
            std_dev: 3.2,
        }
    }
}

impl FHEParams {
    pub fn new_lwe(q: i64, p: i64, k: usize) -> Self {
        Self {
            q,
            p,
            k,
            n: 1,
            ..Default::default()
        }
    }

    pub fn new_rlwe(q: i64, p: i64, n: usize) -> Self {
        Self {
            q,
            p,
            k: 1,
            n,
            ..Default::default()
        }
    }

    pub fn set_complexity(&mut self, k: usize) {
        self.k = k;
    }

    pub fn set_standard_diviation(&mut self, std_dev: f32) {
        self.std_dev = std_dev;
    }

    pub fn delta(&self) -> i64 {
        (self.q - 1) / self.p
    }
}
