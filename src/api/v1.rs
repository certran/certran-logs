use winter_maybe_async::{maybe_async, maybe_async_trait};

use crate::ctlog::v1::{
    cert::DecodedEntry,
    model::{
        AddChainResponse, GetEntriesResponse, GetEntryAndProofResponse, GetProofByHashResponse,
        GetRootsResponse, GetSthConsistencyResponse, GetSthResponse,
    },
};

#[maybe_async_trait]
pub trait CtLogApiV1 {
    type Error: std::error::Error + Send + Sync;

    /// Add Chain to Log
    /// ---
    /// path: `ct/v1/add-chain`
    ///
    /// [RFC 6962 4.1](https://datatracker.ietf.org/doc/html/rfc6962#section-4.1)
    #[maybe_async]
    fn add_chain(&self, _chain: Vec<String>) -> Result<AddChainResponse, Self::Error> {
        let path = "ct/v1/add-chain".to_string();
        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Add PreCertChain to Log
    /// ---
    /// path: `ct/v1/add-pre-chain`
    ///
    /// [RFC 6962 4.2](https://datatracker.ietf.org/doc/html/rfc6962#section-4.2)
    #[maybe_async]
    fn add_pre_chain(&self, _chain: Vec<String>) -> Result<AddChainResponse, Self::Error> {
        let path = "ct/v1/add-pre-chain".to_string();
        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Retrieve Latest Signed Tree Head
    /// ---
    /// path: `ct/v1/get-sth`
    ///
    /// [RFC 6962 4.3](https://datatracker.ietf.org/doc/html/rfc6962#section-4.3)
    #[maybe_async]
    fn get_sth(&self) -> Result<GetSthResponse, Self::Error> {
        let path = "ct/v1/get-sth".to_string();
        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Retrieve Merkle Consistency Proof between Two Signed Tree Heads
    /// ---
    /// path: `ct/v1/get-sth-consistency?first={first}&second={second}`
    ///
    /// [RFC 6962 4.4](https://datatracker.ietf.org/doc/html/rfc6962#section-4.4)
    #[maybe_async]
    fn get_sth_consistency(
        &self,
        _first: u64,
        _second: u64,
    ) -> Result<GetSthConsistencyResponse, Self::Error> {
        let path = "ct/v1/get-sth-consistency?first={first}&second={second}".to_string();

        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Retrieve Merkle Audit Proof from Log by Leaf Hash
    /// ---
    /// path: `ct/v1/get-proof-by-hash?hash={hash}&tree_size={tree_size}`
    ///
    /// [RFC 6962 4.5](https://datatracker.ietf.org/doc/html/rfc6962#section-4.5)
    #[maybe_async]
    fn get_proof_by_hash(
        &self,
        _hash: &str,
        _tree_size: u64,
    ) -> Result<GetProofByHashResponse, Self::Error> {
        let path = "ct/v1/get-proof-by-hash?hash={hash}&tree_size={tree_size}".to_string();

        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Retrieve Entries from Log
    /// ---
    /// path: `ct/v1/get-entries?start={start}&end={end}`
    ///
    /// [RFC 6962 4.6](https://datatracker.ietf.org/doc/html/rfc6962#section-4.6)
    #[maybe_async]
    fn get_entries(&self, _start: u64, _end: u64) -> Result<GetEntriesResponse, Self::Error> {
        let path = "ct/v1/get-entries?start={start}&end={end}".to_string();

        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Retrieve Entries from Log and decode them
    /// ---
    /// path: `ct/v1/get-entries?start={start}&end={end}`
    ///
    /// [RFC 6962 4.6](https://datatracker.ietf.org/doc/html/rfc6962#section-4.6)
    #[maybe_async]
    fn get_entries_decoded(
        &self,
        _start: u64,
        _end: u64,
    ) -> Result<Vec<DecodedEntry>, Self::Error> {
        let path = "ct/v1/get-entries?start={start}&end={end}".to_string();

        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Retrieve Accepted Root Certificates
    /// ---
    /// path: `ct/v1/get-roots`
    ///
    /// [RFC 6962 4.7](https://datatracker.ietf.org/doc/html/rfc6962#section-4.7)
    #[maybe_async]
    fn get_roots(&self) -> Result<GetRootsResponse, Self::Error> {
        let path = "ct/v1/get-roots".to_string();

        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }

    /// Retrieve Entry + Merkle Audit Proof from Log
    /// ---
    /// path: `ct/v1/get-entry-and-proof?leaf_index={leaf_index}&tree_size={tree_size}`
    ///
    /// [RFC 6962 4.8](https://datatracker.ietf.org/doc/html/rfc6962#section-4.8)
    #[maybe_async]
    fn get_entry_and_proof(
        &self,
        _leaf_index: u64,
        _tree_size: u64,
    ) -> Result<GetEntryAndProofResponse, Self::Error> {
        let path =
            "ct/v1/get-entry-and-proof?leaf_index={leaf_index}&tree_size={tree_size}".to_string();

        unimplemented!(
            "This is a blueprint implementation of {}. Users of this crate should implement this appropriately.",
            path
        )
    }
}
