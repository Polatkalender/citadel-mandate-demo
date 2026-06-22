//! Minimal tamper-evident audit log.
//!
//! Each entry chains the previous one: `entry_hash = sha256(prev_hash || summary)`.
//! Mutating or dropping any entry breaks the chain, which [`AuditLog::verify`]
//! detects. This is a SIMPLIFIED illustration — the production audit chain adds
//! a Merkle tree and hybrid post-quantum (Ed25519 + ML-DSA-65) signatures.

use crate::sha256;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub seq: u64,
    pub summary: String,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

#[derive(Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    head: [u8; 32],
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a record and return its sequence number.
    pub fn append(&mut self, summary: impl Into<String>) -> u64 {
        let summary = summary.into();
        let entry_hash = chain(&self.head, &summary);
        let seq = self.entries.len() as u64 + 1;
        self.entries.push(AuditEntry {
            seq,
            summary,
            prev_hash: self.head,
            entry_hash,
        });
        self.head = entry_hash;
        seq
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Current chain head (the "root"), hex-encoded.
    pub fn head_hex(&self) -> String {
        crate::hex(&self.head)
    }

    /// Recompute the chain and confirm no entry was altered or dropped.
    pub fn verify(&self) -> bool {
        let mut prev = [0u8; 32];
        for e in &self.entries {
            if e.prev_hash != prev || chain(&prev, &e.summary) != e.entry_hash {
                return false;
            }
            prev = e.entry_hash;
        }
        true
    }
}

fn chain(prev: &[u8; 32], summary: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + summary.len());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(summary.as_bytes());
    sha256(&buf)
}
