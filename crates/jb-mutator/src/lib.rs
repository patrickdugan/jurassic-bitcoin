use jb_model::TestCase;
use rand::Rng;

pub fn mutate_testcase<R: Rng>(seed: &TestCase, rng: &mut R) -> TestCase {
    let is_txhex_fuzz_target = seed
        .core_template
        .as_ref()
        .map(|t| t.kind == "testmempoolaccept_tx_hex")
        .unwrap_or(false);
    if !is_txhex_fuzz_target {
        return seed.clone();
    }

    let mut tc = seed.clone();
    let mut bytes = hex::decode(&tc.tx_hex).unwrap_or_default();
    if bytes.is_empty() {
        bytes.push(0);
    }
    let idx = rng.gen_range(0..bytes.len());
    bytes[idx] ^= 1 << rng.gen_range(0..8);

    if rng.gen_bool(0.25) {
        bytes.truncate(bytes.len().saturating_sub(1));
    }
    if rng.gen_bool(0.25) {
        bytes.push((rng.next_u32() & 0xFF) as u8);
    }

    tc.tx_hex = hex::encode(bytes);
    tc.id = format!("{}-mut-{:08x}", seed.id, rng.next_u32());
    tc
}
