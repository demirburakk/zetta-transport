mod context;
pub(crate) mod header_protection;
mod key_derivation;
pub(crate) mod keypair;

pub(crate) use context::CryptoContext;

pub(crate) trait CryptoEngine: Send + Sync {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> crate::error::Result<[u8; 16]>;

    fn decrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
        use_prev_key: bool,
    ) -> crate::error::Result<()>;

    fn trial_decrypt_and_rotate(
        &mut self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> crate::error::Result<()>;

    fn apply_header_protection(&self, packet: &mut [u8], pn_offset: usize) -> crate::error::Result<()>;
    fn remove_header_protection(&self, packet: &mut [u8], pn_offset: usize) -> crate::error::Result<()>;

    fn rotate_keys(&mut self);
    fn epoch(&self) -> u64;
}
