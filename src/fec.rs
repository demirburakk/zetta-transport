use bytes::{Bytes, BytesMut};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Advanced Reed-Solomon Forward Error Correction (FEC) engine.
pub struct FecEngine;

impl FecEngine {
    /// Builds parity shards using XOR (default fallback for position-independent recovery).
    /// Advanced `build_parity_rs` is available for multi-parity scenarios.
    pub fn build_parity(shards: &[Bytes]) -> Bytes {
        Self::build_parity_xor(shards)
    }

    /// Builds parity shards using Reed-Solomon.
    /// Expects 4 data shards. Returns 1 parity shard.
    #[allow(dead_code)]
    pub fn build_parity_rs(shards: &[Bytes]) -> Bytes {
        if shards.is_empty() {
            return Bytes::new();
        }

        let max_len = shards.iter().map(|s| s.len()).max().unwrap_or(0);
        
        let mut rs_shards: Vec<Vec<u8>> = shards
            .iter()
            .map(|s| {
                let mut buf = vec![0u8; max_len];
                buf[..s.len()].copy_from_slice(s);
                buf
            })
            .collect();

        // We pad data shards to 4 if we received less.
        while rs_shards.len() < 4 {
            rs_shards.push(vec![0u8; max_len]);
        }

        // 4 Data, 1 Parity
        let rs = ReedSolomon::new(4, 1).expect("Failed to init ReedSolomon");
        rs_shards.push(vec![0u8; max_len]); // Parity placeholder
        
        rs.encode(&mut rs_shards).expect("Failed to encode RS");

        Bytes::from(rs_shards.pop().unwrap())
    }

    /// Recovers a missing packet using XOR parity (position-independent).
    pub fn recover(available_shards: &[Bytes], parity: &Bytes) -> Bytes {
        let mut all_shards = available_shards.to_vec();
        all_shards.push(parity.clone());
        Self::build_parity_xor(&all_shards)
    }

    /// Recovers missing shards using Reed-Solomon.
    /// Expects exactly 5 slots (4 data + 1 parity). Missing slots should be None.
    #[allow(dead_code)]
    pub fn recover_rs(mut rs_shards: Vec<Option<Vec<u8>>>) -> Result<(), reed_solomon_erasure::Error> {
        let rs = ReedSolomon::new(4, 1)?;
        rs.reconstruct(&mut rs_shards)
    }

    fn build_parity_xor(shards: &[Bytes]) -> Bytes {
        if shards.is_empty() {
            return Bytes::new();
        }

        let max_len = shards.iter().map(|s| s.len()).max().unwrap_or(0);
        let mut parity = BytesMut::zeroed(max_len);

        for shard in shards {
            for (i, &byte) in shard.iter().enumerate() {
                parity[i] ^= byte;
            }
        }

        parity.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_recovery() {
        let shard1 = Bytes::from(&b"hello"[..]);
        let shard2 = Bytes::from(&b"world"[..]);
        let shard3 = Bytes::from(&b"zetta"[..]);

        let shards = vec![shard1.clone(), shard2.clone(), shard3.clone()];
        let parity = FecEngine::build_parity_xor(&shards);

        let available = vec![shard1.clone(), shard3.clone()];
        let recovered = FecEngine::recover(&available, &parity);

        assert_eq!(&recovered[..shard2.len()], &shard2[..]);
    }

    #[test]
    fn test_fec_variable_length() {
        let shard1 = Bytes::from(&b"short"[..]);
        let shard2 = Bytes::from(&b"longer payload"[..]);
        let shards = vec![shard1.clone(), shard2.clone()];
        
        let parity = FecEngine::build_parity_xor(&shards);
        assert_eq!(parity.len(), 14);

        let available = vec![shard1.clone()];
        let recovered = FecEngine::recover(&available, &parity);
        
        assert_eq!(&recovered[..shard2.len()], &shard2[..]);
    }
}
