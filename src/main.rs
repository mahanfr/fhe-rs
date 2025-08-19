use hpre::{fhe::FHEParams, glwe::GLWECrypto};

fn main() {
    let mut params = FHEParams::new_rlwe(16777216, 256, 32);
    params.set_standard_diviation(1.0);
    params.set_complexity(8);
    let crypto_ctx = GLWECrypto::new(params);
    let (sec_key, pub_key) = crypto_ctx.gen_keypair();
    let ct = crypto_ctx.encrypt(&pub_key, vec![2, 2, 2]);
    //let ct2 = crypto_ctx.multiply_decomposed(&ct, &vec![1050,1050], 2, true);
    let ct2 = crypto_ctx.multyply_by_plaintext(&ct, &vec![1050, 1050, 1050, 1050, 1050]);

    let pt = crypto_ctx.decrypt(&sec_key, ct2);
    println!("pt: {:?}", pt);
}

#[allow(dead_code)]
fn small_multipication() {
    let mut params = FHEParams::new_rlwe(1048576, 256, 32);
    params.set_standard_diviation(1.0);
    params.set_complexity(8);
    let crypto_ctx = GLWECrypto::new(params);
    let (sec_key, pub_key) = crypto_ctx.gen_keypair();
    let ct = crypto_ctx.encrypt(&pub_key, vec![2, 2, 2]);

    let poly = crypto_ctx.lift_plain_poly_to_q(&vec![32, 1]);
    let ct2 = crypto_ctx.multyply_by_plaintext(&ct, &poly);
    let pt = crypto_ctx.decrypt(&sec_key, ct2);
    println!("pt: {:?}", pt);
}

#[allow(dead_code)]
fn addition() {
    let mut params = FHEParams::new_rlwe(1048576, 256, 32);
    params.set_standard_diviation(1.0);
    params.set_complexity(8);
    let crypto_ctx = GLWECrypto::new(params);
    let (sec_key, pub_key) = crypto_ctx.gen_keypair();
    let ct = crypto_ctx.encrypt(&pub_key, "  ".as_bytes().to_vec());
    let ct2 = crypto_ctx.encrypt(&pub_key, "  ".as_bytes().to_vec());
    let ctres = crypto_ctx.add_ciphertexts(&ct, &ct2);
    let pt = crypto_ctx.decrypt(&sec_key, ctres);
    println!("pt: {:?}", pt);
}
