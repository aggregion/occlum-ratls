use ring::digest::{Context, SHA512};

pub fn hash_sha512(input: Vec<u8>) -> [u8; 64] {
    let mut context = Context::new(&SHA512);
    context.update(input.as_ref());
    let result = context.finish();
    let digest = result.as_ref();
    let mut output = [0u8; 64];
    output.copy_from_slice(digest);
    output
}
