#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    pub label: String,
    pub sample_height: u32,
}

pub fn flags_for_height(height: u32) -> Vec<String> {
    // Coarse profile bands for a 2009-2013 POC (not full consensus fidelity).
    if height < 173_805 {
        vec!["EPOCH_PRE_BIP16".to_string()]
    } else if height < 224_412 {
        vec!["EPOCH_BIP16_ACTIVE".to_string()]
    } else {
        vec!["EPOCH_BIP34_ACTIVE".to_string()]
    }
}

pub fn epoch_label(height: u32) -> String {
    if height < 173_805 {
        "pre-bip16".to_string()
    } else if height < 224_412 {
        "bip16-era".to_string()
    } else {
        "bip34-era".to_string()
    }
}

pub fn epochs_for_range(start_height: u32, end_height: u32) -> Vec<Epoch> {
    let mut out = Vec::new();
    let mut maybe_push = |h: u32| {
        if h >= start_height && h <= end_height {
            out.push(Epoch {
                label: epoch_label(h),
                sample_height: h,
            });
        }
    };
    maybe_push(100_000);
    maybe_push(200_000);
    maybe_push(250_000);
    if out.is_empty() {
        let mid = start_height + (end_height.saturating_sub(start_height) / 2);
        out.push(Epoch {
            label: epoch_label(mid),
            sample_height: mid,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{epochs_for_range, flags_for_height};

    #[test]
    fn has_flags_by_height() {
        assert_eq!(flags_for_height(100_000), vec!["EPOCH_PRE_BIP16"]);
        assert_eq!(flags_for_height(200_000), vec!["EPOCH_BIP16_ACTIVE"]);
        assert_eq!(flags_for_height(250_000), vec!["EPOCH_BIP34_ACTIVE"]);
    }

    #[test]
    fn returns_epoch_samples() {
        let epochs = epochs_for_range(90_000, 260_000);
        assert!(!epochs.is_empty());
    }
}
