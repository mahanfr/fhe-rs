use hpre::{fhe::FHEParams, glwe::GLWECrypto};

fn main() {
    let mut params = FHEParams::new_rlwe(1048576, 256, 32);
    params.set_standard_diviation(1.0);
    params.set_complexity(8);
    let crypto_ctx = GLWECrypto::new(params);
    let (sec_key, pub_key) = crypto_ctx.gen_keypair();
    let ct = crypto_ctx.encrypt(&pub_key, "  ".as_bytes().to_vec());
    let mut ct2 = crypto_ctx.encrypt(&pub_key, "  ".as_bytes().to_vec());
    crypto_ctx.multiply_by_constant_value(&mut ct2, 2);
    let ctres = crypto_ctx.add_ciphertexts(&ct, &ct2);
    let pt = crypto_ctx.decrypt(&sec_key, ctres);
    println!("pt: {:?}", pt);
}
