use std::sync::Mutex;

use aws_lc_rs::constant_time::verify_slices_are_equal;

pub use crate::error::LedgerError;

/// Genesis `prev_hash` anchor for sequence 0 of an [`AuditLedger`].
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// Canonical version tag inside serialized [`LedgerEntry`] event bytes.
pub const LEDGER_DOMAIN_TAG: &[u8] = b"LOCKSMITH-LEDGER-V1";

/// Input fields for appending a redacted structured audit event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEventInput<'a> {
    pub timestamp_ms: u64,
    pub kind: &'a str,
    pub actor: &'a str,
    pub summary: &'a str,
}

fn validate_field_len(field_name: &'static str, value: &str) -> Result<u16, LedgerError> {
    if value.is_empty() {
        return Err(LedgerError::EmptyField { field: field_name });
    }
    u16::try_from(value.len()).map_err(|_| LedgerError::FieldTooLarge {
        field: field_name,
        len: value.len(),
    })
}

fn validate_and_frame_field(
    out: &mut Vec<u8>,
    field_name: &'static str,
    value: &str,
) -> Result<(), LedgerError> {
    let len_u16 = validate_field_len(field_name, value)?;
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn stream_field_to_hasher(
    hasher: &mut blake3::Hasher,
    field_name: &'static str,
    value: &str,
) -> Result<(), LedgerError> {
    let len_u16 = validate_field_len(field_name, value)?;
    hasher.update(&len_u16.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

fn stream_entry_hash(
    prev_hash: &[u8; 32],
    sequence: u64,
    timestamp_ms: u64,
    kind: &str,
    actor: &str,
    summary: &str,
) -> Result<[u8; 32], LedgerError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_hash);
    hasher.update(LEDGER_DOMAIN_TAG);
    hasher.update(&sequence.to_be_bytes());
    hasher.update(&timestamp_ms.to_be_bytes());
    stream_field_to_hasher(&mut hasher, "kind", kind)?;
    stream_field_to_hasher(&mut hasher, "actor", actor)?;
    stream_field_to_hasher(&mut hasher, "summary", summary)?;
    Ok(*hasher.finalize().as_bytes())
}

fn encode_canonical_event(
    sequence: u64,
    timestamp_ms: u64,
    kind: &str,
    actor: &str,
    summary: &str,
) -> Result<Vec<u8>, LedgerError> {
    let mut out = Vec::with_capacity(
        LEDGER_DOMAIN_TAG.len() + 8 + 8 + 6 + kind.len() + actor.len() + summary.len(),
    );
    out.extend_from_slice(LEDGER_DOMAIN_TAG);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    validate_and_frame_field(&mut out, "kind", kind)?;
    validate_and_frame_field(&mut out, "actor", actor)?;
    validate_and_frame_field(&mut out, "summary", summary)?;
    Ok(out)
}

/// Immutable hash-chained audit ledger record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub kind: String,
    pub actor: String,
    pub summary: String,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl LedgerEntry {
    /// Deterministically encodes `(sequence, timestamp_ms, kind, actor, summary)`
    /// into canonical length-prefixed event bytes.
    pub fn canonical_event_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        encode_canonical_event(
            self.sequence,
            self.timestamp_ms,
            &self.kind,
            &self.actor,
            &self.summary,
        )
    }

    /// Computes `BLAKE3(prev_hash || canonical_event_bytes)` by streaming directly
    /// into `blake3::Hasher::update` without heap-allocating a concatenated buffer.
    #[must_use]
    pub fn compute_entry_hash(prev_hash: &[u8; 32], canonical_event_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(prev_hash);
        hasher.update(canonical_event_bytes);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug)]
struct LedgerState {
    entries: Vec<LedgerEntry>,
    head_hash: [u8; 32],
}

/// Thread-safe append-only `BLAKE3` hash-chained event ledger.
#[derive(Debug)]
pub struct AuditLedger {
    state: Mutex<LedgerState>,
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLedger {
    /// Creates an empty [`AuditLedger`] anchored at [`GENESIS_PREV_HASH`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(LedgerState {
                entries: Vec::new(),
                head_hash: GENESIS_PREV_HASH,
            }),
        }
    }

    /// Appends a new event to the hash chain and returns the committed [`LedgerEntry`].
    pub fn append(&self, event: LedgerEventInput<'_>) -> Result<LedgerEntry, LedgerError> {
        let mut guard = self.state.lock().map_err(|_| LedgerError::StateCorrupted)?;
        let sequence =
            u64::try_from(guard.entries.len()).map_err(|_| LedgerError::StateCorrupted)?;
        let prev_hash = guard.head_hash;

        let entry_hash = stream_entry_hash(
            &prev_hash,
            sequence,
            event.timestamp_ms,
            event.kind,
            event.actor,
            event.summary,
        )?;

        let entry = LedgerEntry {
            sequence,
            timestamp_ms: event.timestamp_ms,
            kind: event.kind.to_owned(),
            actor: event.actor.to_owned(),
            summary: event.summary.to_owned(),
            prev_hash,
            entry_hash,
        };

        guard.head_hash = entry_hash;
        guard.entries.push(entry.clone());
        Ok(entry)
    }

    /// Returns a cloned snapshot of all committed entries.
    pub fn entries_snapshot(&self) -> Result<Vec<LedgerEntry>, LedgerError> {
        let guard = self.state.lock().map_err(|_| LedgerError::StateCorrupted)?;
        Ok(guard.entries.clone())
    }

    /// Returns the latest committed `entry_hash` (or [`GENESIS_PREV_HASH`] if empty).
    pub fn head_hash(&self) -> Result<[u8; 32], LedgerError> {
        let guard = self.state.lock().map_err(|_| LedgerError::StateCorrupted)?;
        Ok(guard.head_hash)
    }

    /// Verifies the full ledger starting from [`GENESIS_PREV_HASH`].
    pub fn verify_all(&self) -> Result<(), LedgerError> {
        let guard = self.state.lock().map_err(|_| LedgerError::StateCorrupted)?;
        Self::verify_slice(&GENESIS_PREV_HASH, &guard.entries)
    }

    /// Verifies integrity and hash linkage across any contiguous slice of [`LedgerEntry`] records.
    pub fn verify_slice(
        expected_prev_hash: &[u8; 32],
        entries: &[LedgerEntry],
    ) -> Result<(), LedgerError> {
        let Some(first) = entries.first() else {
            return Ok(());
        };

        let start_seq = first.sequence;
        let mut running_prev = *expected_prev_hash;

        for (offset, entry) in entries.iter().enumerate() {
            let offset_u64 = u64::try_from(offset).map_err(|_| LedgerError::StateCorrupted)?;
            let expected_seq = start_seq
                .checked_add(offset_u64)
                .ok_or(LedgerError::StateCorrupted)?;

            if entry.sequence != expected_seq {
                return Err(LedgerError::SequenceDiscontinuity {
                    expected: expected_seq,
                    actual: entry.sequence,
                });
            }

            if verify_slices_are_equal(&entry.prev_hash, &running_prev).is_err() {
                return Err(LedgerError::PrevHashMismatch {
                    sequence: entry.sequence,
                });
            }

            let recomputed = stream_entry_hash(
                &entry.prev_hash,
                entry.sequence,
                entry.timestamp_ms,
                &entry.kind,
                &entry.actor,
                &entry.summary,
            )?;
            if verify_slices_are_equal(&entry.entry_hash, &recomputed).is_err() {
                return Err(LedgerError::EntryHashTampered {
                    sequence: entry.sequence,
                });
            }

            running_prev = entry.entry_hash;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_verifies_full_and_partial_slices() {
        let ledger = AuditLedger::new();
        let e0 = ledger
            .append(LedgerEventInput {
                timestamp_ms: 100,
                kind: "daemon.start",
                actor: "ring1",
                summary: "initialized",
            })
            .unwrap();
        let e1 = ledger
            .append(LedgerEventInput {
                timestamp_ms: 200,
                kind: "nonce.burn",
                actor: "cid:4",
                summary: "burned single-use nonce",
            })
            .unwrap();
        let e2 = ledger
            .append(LedgerEventInput {
                timestamp_ms: 300,
                kind: "egress.splice",
                actor: "cid:4",
                summary: "spliced TLS 1.3 request to api.anthropic.com",
            })
            .unwrap();

        assert_eq!(e0.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(e1.prev_hash, e0.entry_hash);
        assert_eq!(e2.prev_hash, e1.entry_hash);
        assert!(ledger.verify_all().is_ok());

        let snapshot = ledger.entries_snapshot().unwrap();
        assert!(AuditLedger::verify_slice(&e0.entry_hash, &snapshot[1..=2]).is_ok());
    }

    #[test]
    fn detects_mutation_and_deletion_in_ledger_slice() {
        let ledger = AuditLedger::new();
        for idx in 0..4u64 {
            ledger
                .append(LedgerEventInput {
                    timestamp_ms: 1_000 + idx,
                    kind: "proxy.auth",
                    actor: "cid:9",
                    summary: "authorized",
                })
                .unwrap();
        }

        let mut entries = ledger.entries_snapshot().unwrap();
        entries[2].summary = "forged".to_owned();
        assert_eq!(
            AuditLedger::verify_slice(&GENESIS_PREV_HASH, &entries).unwrap_err(),
            LedgerError::EntryHashTampered { sequence: 2 }
        );

        let intact = ledger.entries_snapshot().unwrap();
        let deleted_middle = vec![intact[0].clone(), intact[2].clone()];
        assert_eq!(
            AuditLedger::verify_slice(&GENESIS_PREV_HASH, &deleted_middle).unwrap_err(),
            LedgerError::SequenceDiscontinuity {
                expected: 1,
                actual: 2
            }
        );
    }
}
