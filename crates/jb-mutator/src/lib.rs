use jb_model::TestCase;
use rand::Rng;

pub struct MutationResult {
    pub testcase: TestCase,
    pub mutations_applied: Vec<String>,
}

pub fn mutate_testcase<R: Rng>(seed: &TestCase, rng: &mut R) -> TestCase {
    mutate_testcase_with_trace(seed, rng).testcase
}

pub fn mutate_testcase_with_trace<R: Rng>(seed: &TestCase, rng: &mut R) -> MutationResult {
    let is_txhex_fuzz_target = seed
        .core_template
        .as_ref()
        .map(|t| t.kind == "testmempoolaccept_tx_hex")
        .unwrap_or(false);
    if !is_txhex_fuzz_target {
        return MutationResult {
            testcase: seed.clone(),
            mutations_applied: vec!["none(non-txhex-template)".to_string()],
        };
    }

    let mut tc = seed.clone();
    let mut bytes = hex::decode(&tc.tx_hex).unwrap_or_default();
    if bytes.is_empty() {
        bytes.push(0);
    }
    let mut mutations_applied = Vec::new();

    let mut did_structured = false;
    if let Some(layout) = parse_tx_layout(&bytes) {
        let choice = rng.gen_range(0..3);
        match choice {
            0 if !layout.sequence_offsets.is_empty() => {
                let idx = rng.gen_range(0..layout.sequence_offsets.len());
                let off = layout.sequence_offsets[idx];
                mutate_u32_field(&mut bytes, off, rng);
                mutations_applied.push("mutate_sequence".to_string());
                did_structured = true;
            }
            1 => {
                mutate_u32_field(&mut bytes, layout.locktime_offset, rng);
                mutations_applied.push("mutate_locktime".to_string());
                did_structured = true;
            }
            2 if !layout.witness_len_offsets.is_empty() => {
                let idx = rng.gen_range(0..layout.witness_len_offsets.len());
                let off = layout.witness_len_offsets[idx];
                mutate_varint_prefix_byte(&mut bytes, off, rng);
                mutations_applied.push("mutate_witness_len_prefix".to_string());
                did_structured = true;
            }
            _ => {}
        }
    }
    if !did_structured {
        let idx = rng.gen_range(0..bytes.len());
        bytes[idx] ^= 1 << rng.gen_range(0..8);
        mutations_applied.push("mutate_random_bitflip".to_string());
    }

    if rng.gen_bool(0.25) {
        bytes.truncate(bytes.len().saturating_sub(1));
        mutations_applied.push("truncate_tail".to_string());
    }
    if rng.gen_bool(0.25) {
        bytes.push((rng.next_u32() & 0xFF) as u8);
        mutations_applied.push("append_byte".to_string());
    }

    tc.tx_hex = hex::encode(bytes);
    tc.id = format!("{}-mut-{:08x}", seed.id, rng.next_u32());
    MutationResult {
        testcase: tc,
        mutations_applied,
    }
}

#[derive(Debug, Clone)]
struct TxLayout {
    sequence_offsets: Vec<usize>,
    witness_len_offsets: Vec<usize>,
    locktime_offset: usize,
}

fn parse_tx_layout(tx: &[u8]) -> Option<TxLayout> {
    if tx.len() < 10 {
        return None;
    }
    let mut i = 0usize;
    i += 4; // version
    let has_witness = tx.get(i) == Some(&0x00) && tx.get(i + 1) == Some(&0x01);
    if has_witness {
        i += 2;
    }

    let vin_count = read_varint(tx, &mut i)? as usize;
    let mut sequence_offsets = Vec::with_capacity(vin_count);
    for _ in 0..vin_count {
        i = i.checked_add(32)?; // txid
        i = i.checked_add(4)?; // vout
        let script_len = read_varint(tx, &mut i)? as usize;
        i = i.checked_add(script_len)?;
        let seq_off = i;
        i = i.checked_add(4)?;
        sequence_offsets.push(seq_off);
        if i > tx.len() {
            return None;
        }
    }

    let vout_count = read_varint(tx, &mut i)? as usize;
    for _ in 0..vout_count {
        i = i.checked_add(8)?; // amount
        let spk_len = read_varint(tx, &mut i)? as usize;
        i = i.checked_add(spk_len)?;
        if i > tx.len() {
            return None;
        }
    }

    let mut witness_len_offsets = Vec::new();
    if has_witness {
        for _ in 0..vin_count {
            let item_count = read_varint(tx, &mut i)? as usize;
            for _ in 0..item_count {
                let len_off = i;
                let item_len = read_varint(tx, &mut i)? as usize;
                i = i.checked_add(item_len)?;
                if i > tx.len() {
                    return None;
                }
                witness_len_offsets.push(len_off);
            }
        }
    }
    if i.checked_add(4)? != tx.len() {
        return None;
    }

    Some(TxLayout {
        sequence_offsets,
        witness_len_offsets,
        locktime_offset: i,
    })
}

fn mutate_u32_field<R: Rng>(bytes: &mut [u8], off: usize, rng: &mut R) {
    if off + 4 > bytes.len() {
        return;
    }
    let current = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    let next = match rng.gen_range(0..4) {
        0 => 0,
        1 => 1,
        2 => 0xffff_fffe,
        _ => 0xffff_ffff,
    };
    let val = if rng.gen_bool(0.5) { next } else { current ^ (1u32 << rng.gen_range(0..31)) };
    bytes[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn mutate_varint_prefix_byte<R: Rng>(bytes: &mut [u8], off: usize, rng: &mut R) {
    if off >= bytes.len() {
        return;
    }
    let choices = [0x00u8, 0x01u8, 0x02u8, 0x4bu8, 0xfdu8];
    bytes[off] = choices[rng.gen_range(0..choices.len())];
}

fn read_varint(tx: &[u8], i: &mut usize) -> Option<u64> {
    let first = *tx.get(*i)?;
    *i += 1;
    match first {
        0x00..=0xfc => Some(first as u64),
        0xfd => {
            let b0 = *tx.get(*i)? as u16;
            let b1 = *tx.get(*i + 1)? as u16;
            *i += 2;
            Some((b1 << 8 | b0) as u64)
        }
        0xfe => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(tx.get(*i..*i + 4)?);
            *i += 4;
            Some(u32::from_le_bytes(arr) as u64)
        }
        0xff => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(tx.get(*i..*i + 8)?);
            *i += 8;
            Some(u64::from_le_bytes(arr))
        }
    }
}
