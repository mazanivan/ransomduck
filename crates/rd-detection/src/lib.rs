use rd_common::{Incident, ProcessInfo, ResponseLevel, Signal, Action, ActionType};
use std::path::PathBuf;
use uuid::Uuid;

/// Compute a 0–100 risk score from a list of signals.
pub fn compute_score(signals: &[Signal], context_multiplier: f64) -> u8 {
    let raw: f64 = signals.iter().map(|s| s.weight * s.confidence).sum();
    let scaled = raw * context_multiplier * 100.0;
    scaled.clamp(0.0, 100.0).round() as u8
}

/// Map a risk score to the appropriate response level.
pub fn response_level(score: u8) -> ResponseLevel {
    match score {
        0..=39 => ResponseLevel::Monitor,
        40..=74 => ResponseLevel::Restrict,
        _ => ResponseLevel::Contain,
    }
}

/// Build a full incident from a set of correlated signals.
///
/// In this first slice the only automatic actions are `Log` and `Alert`.
pub fn build_incident(
    process: ProcessInfo,
    affected_paths: Vec<PathBuf>,
    signals: Vec<Signal>,
    context_multiplier: f64,
) -> Incident {
    let score = compute_score(&signals, context_multiplier);
    let level = response_level(score);

    let incident_id = Uuid::new_v4();
    let actions = vec![
        Action::new(incident_id, ActionType::Log, true, None),
        Action::new(incident_id, ActionType::Alert, true, None),
    ];

    Incident::new(score, level, signals, affected_paths, process, actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rd_common::{SignalType, Signal};

    fn sample_signal(signal_type: SignalType, weight: f64, confidence: f64) -> Signal {
        Signal::new(
            Uuid::new_v4(),
            "test-rule",
            signal_type,
            weight,
            confidence,
            "test signal",
        )
    }

    #[test]
    fn canary_modified_alone_is_level_2() {
        let signals = vec![sample_signal(SignalType::CanaryModified, 0.40, 1.0)];
        let score = compute_score(&signals, 1.10); // unknown process
        assert_eq!(score, 44);
        assert_eq!(response_level(score), ResponseLevel::Restrict);
    }

    #[test]
    fn signed_backup_touching_canary_stays_level_1() {
        let signals = vec![sample_signal(SignalType::CanaryModified, 0.40, 1.0)];
        let score = compute_score(&signals, 0.80); // signed / allowlisted process
        assert_eq!(score, 32);
        assert_eq!(response_level(score), ResponseLevel::Monitor);
    }

    #[test]
    fn canary_plus_vss_deletion_hits_level_3() {
        let signals = vec![
            sample_signal(SignalType::CanaryModified, 0.40, 1.0),
            sample_signal(SignalType::VssShadowDeletion, 0.50, 0.95),
        ];
        let score = compute_score(&signals, 1.10);
        assert!(score >= 75);
        assert_eq!(response_level(score), ResponseLevel::Contain);
    }

    #[test]
    fn empty_signal_list_is_safe() {
        let score = compute_score(&[], 1.10);
        assert_eq!(score, 0);
        assert_eq!(response_level(score), ResponseLevel::Monitor);
    }
}
