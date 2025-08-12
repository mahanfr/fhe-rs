use hpre::{fhe::FHEParams, glwe::GLWECrypto};

fn main() {
    let mut params = FHEParams::new_rlwe(4096, 4, 32);
    params.set_standard_diviation(1.0);
    let crypto_ctx = GLWECrypto::new(params);
    let (sec_key, pub_key) = crypto_ctx.gen_keypair();
    let ct = crypto_ctx.encrypt(&pub_key, "he".as_bytes().to_vec());
    println!("ct: {:?}", ct);
    let pt = crypto_ctx.decrypt(&sec_key, ct);
    println!("pt: {:?}", pt);
}
