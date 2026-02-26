pub const BIP16_ENFORCEMENT_HEIGHT: u32 = 173_805;
pub const BIP34_BURIED_HEIGHT: u32 = 227_931;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Epoch {
    PreBip16,
    PostBip16PreBip34,
    PostBip34,
}

impl Epoch {
    pub fn label(self) -> &'static str {
        match self {
            Self::PreBip16 => "pre-bip16",
            Self::PostBip16PreBip34 => "post-bip16-pre-bip34",
            Self::PostBip34 => "post-bip34",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextView {
    pub height: u32,
    pub median_time_past: Option<u64>,
    pub block_time: Option<u64>,
    pub epoch: Option<String>,
}

pub fn epoch_for_height(height: u32) -> Epoch {
    if height < BIP16_ENFORCEMENT_HEIGHT {
        Epoch::PreBip16
    } else if height < BIP34_BURIED_HEIGHT {
        Epoch::PostBip16PreBip34
    } else {
        Epoch::PostBip34
    }
}

pub fn flags_for_context(ctx: &ContextView) -> Vec<String> {
    let mut flags = flags_for_height(ctx.height);
    if ctx.median_time_past.is_some() {
        flags.push("HAS_MEDIAN_TIME_PAST".to_string());
    }
    if ctx.block_time.is_some() {
        flags.push("HAS_BLOCK_TIME".to_string());
    }
    if let Some(epoch) = &ctx.epoch {
        flags.push(format!(
            "CTX_EPOCH_{}",
            epoch.to_ascii_uppercase().replace('-', "_")
        ));
    }
    flags
}

pub fn flags_for_height(height: u32) -> Vec<String> {
    match epoch_for_height(height) {
        Epoch::PreBip16 => vec![
            "EPOCH_PRE_BIP16".to_string(),
            "RULESET_P2SH_NOT_ENFORCED".to_string(),
        ],
        Epoch::PostBip16PreBip34 => vec![
            "EPOCH_POST_BIP16_PRE_BIP34".to_string(),
            "RULESET_P2SH_ENFORCED".to_string(),
            "RULESET_BIP34_NOT_ENFORCED".to_string(),
        ],
        Epoch::PostBip34 => vec![
            "EPOCH_POST_BIP34".to_string(),
            "RULESET_P2SH_ENFORCED".to_string(),
            "RULESET_BIP34_ENFORCED".to_string(),
        ],
    }
}

pub fn epoch_label(height: u32) -> String {
    epoch_for_height(height).label().to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        BIP16_ENFORCEMENT_HEIGHT, BIP34_BURIED_HEIGHT, ContextView, Epoch, epoch_for_height,
        flags_for_context, flags_for_height,
    };

    #[test]
    fn has_flags_by_height() {
        assert_eq!(
            flags_for_height(100_000),
            vec!["EPOCH_PRE_BIP16", "RULESET_P2SH_NOT_ENFORCED"]
        );
        assert_eq!(
            flags_for_height(200_000),
            vec![
                "EPOCH_POST_BIP16_PRE_BIP34",
                "RULESET_P2SH_ENFORCED",
                "RULESET_BIP34_NOT_ENFORCED"
            ]
        );
        assert_eq!(
            flags_for_height(250_000),
            vec![
                "EPOCH_POST_BIP34",
                "RULESET_P2SH_ENFORCED",
                "RULESET_BIP34_ENFORCED"
            ]
        );
    }

    #[test]
    fn maps_epoch_boundaries() {
        assert_eq!(
            epoch_for_height(BIP16_ENFORCEMENT_HEIGHT - 1),
            Epoch::PreBip16
        );
        assert_eq!(
            epoch_for_height(BIP16_ENFORCEMENT_HEIGHT),
            Epoch::PostBip16PreBip34
        );
        assert_eq!(epoch_for_height(BIP34_BURIED_HEIGHT), Epoch::PostBip34);
    }

    #[test]
    fn context_flags_include_time_hints() {
        let flags = flags_for_context(&ContextView {
            height: 227_931,
            median_time_past: Some(1),
            block_time: Some(2),
            epoch: Some("post-bip34".to_string()),
        });
        assert!(flags.iter().any(|f| f == "HAS_MEDIAN_TIME_PAST"));
        assert!(flags.iter().any(|f| f == "HAS_BLOCK_TIME"));
        assert!(flags.iter().any(|f| f == "CTX_EPOCH_POST_BIP34"));
    }
}
