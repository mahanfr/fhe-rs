use rand_distr::{Distribution, Normal, Uniform};

#[derive(Debug, Clone, Copy)]
pub enum FHESamplingMethod {
    Uniform(i64, i64),
    UniformBinary,
    UniformTernary,
    Gaussian(f32),
}

pub fn fhe_sample(sampling_method: FHESamplingMethod, size: usize) -> Vec<i64> {
    match sampling_method {
        FHESamplingMethod::UniformBinary => fhe_sampling_uniform(0, 2, size),
        FHESamplingMethod::UniformTernary => fhe_sampling_uniform(-1, 2, size),
        FHESamplingMethod::Uniform(l, h) => fhe_sampling_uniform(l, h, size),
        FHESamplingMethod::Gaussian(std_dev) => fhe_sampling_gaussian(std_dev, size),
    }
}

pub fn fhe_sampling_uniform(low: i64, high: i64, size: usize) -> Vec<i64> {
    let mut coeff = Vec::new();
    let mut rng = rand::thread_rng();
    let bin_uniform = Uniform::new(low, high);
    for _ in 0..size {
        coeff.push(bin_uniform.sample(&mut rng));
    }
    coeff
}

pub fn fhe_sampling_gaussian(std_dev: f32, size: usize) -> Vec<i64> {
    let mut coeff: Vec<i64> = Vec::new();
    let mut rng = rand::thread_rng();
    let distr = Normal::new(0.0, std_dev).unwrap();
    for _ in 0..size {
        coeff.push(distr.sample(&mut rng).round() as i64);
    }
    coeff
}
