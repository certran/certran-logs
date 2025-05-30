#[cfg(not(feature = "async"))]
mod internal_sync_api {
    use crate::ctlog::v1::{
        cert::DecodedEntry,
        model::{
            AddChainResponse, GetEntriesResponse, GetEntryAndProofResponse, GetProofByHashResponse,
            GetRootsResponse, GetSthConsistencyResponse, GetSthResponse,
        },
    };

    pub trait CtLogApiV1Trait {
        type Error: std::error::Error + Send + Sync + 'static;

        /// Add Chain to Log
        /// ---
        /// path: `ct/v1/add-chain`
        ///
        /// [RFC 6962 4.1](https://datatracker.ietf.org/doc/html/rfc6962#section-4.1)
        fn add_chain(&self, _chain: Vec<String>) -> Result<AddChainResponse, Self::Error>
        where
            Self: Send;

        /// Add PreCertChain to Log
        /// ---
        /// path: `ct/v1/add-pre-chain`
        ///
        /// [RFC 6962 4.2](https://datatracker.ietf.org/doc/html/rfc6962#section-4.2)
        fn add_pre_chain(&self, _chain: Vec<String>) -> Result<AddChainResponse, Self::Error>
        where
            Self: Send;

        /// Retrieve Latest Signed Tree Head
        /// ---
        /// path: `ct/v1/get-sth`
        ///
        /// [RFC 6962 4.3](https://datatracker.ietf.org/doc/html/rfc6962#section-4.3)
        fn get_sth(&self) -> Result<GetSthResponse, Self::Error>;

        /// Retrieve Merkle Consistency Proof between Two Signed Tree Heads
        /// ---
        /// path: `ct/v1/get-sth-consistency?first={first}&second={second}`
        ///
        /// [RFC 6962 4.4](https://datatracker.ietf.org/doc/html/rfc6962#section-4.4)
        fn get_sth_consistency(
            &self,
            _first: u64,
            _second: u64,
        ) -> Result<GetSthConsistencyResponse, Self::Error>;

        /// Retrieve Merkle Audit Proof from Log by Leaf Hash
        /// ---
        /// path: `ct/v1/get-proof-by-hash?hash={hash}&tree_size={tree_size}`
        ///
        /// [RFC 6962 4.5](https://datatracker.ietf.org/doc/html/rfc6962#section-4.5)
        fn get_proof_by_hash(
            &self,
            _hash: &str,
            _tree_size: u64,
        ) -> Result<GetProofByHashResponse, Self::Error>;

        /// Retrieve Entries from Log
        /// ---
        /// path: `ct/v1/get-entries?start={start}&end={end}`
        ///
        /// [RFC 6962 4.6](https://datatracker.ietf.org/doc/html/rfc6962#section-4.6)
        fn get_entries(&self, _start: u64, _end: u64) -> Result<GetEntriesResponse, Self::Error>;

        /// Retrieve Entries from Log and decode them
        /// ---
        /// path: `ct/v1/get-entries?start={start}&end={end}`
        ///
        /// [RFC 6962 4.6](https://datatracker.ietf.org/doc/html/rfc6962#section-4.6)
        fn get_entries_decoded(
            &self,
            _start: u64,
            _end: u64,
        ) -> Result<Vec<DecodedEntry>, Self::Error>;

        /// Retrieve Accepted Root Certificates
        /// ---
        /// path: `ct/v1/get-roots`
        ///
        /// [RFC 6962 4.7](https://datatracker.ietf.org/doc/html/rfc6962#section-4.7)
        fn get_roots(&self) -> Result<GetRootsResponse, Self::Error>;

        /// Retrieve Entry + Merkle Audit Proof from Log
        /// ---
        /// path: `ct/v1/get-entry-and-proof?leaf_index={leaf_index}&tree_size={tree_size}`
        ///
        /// [RFC 6962 4.8](https://datatracker.ietf.org/doc/html/rfc6962#section-4.8)
        fn get_entry_and_proof(
            &self,
            _leaf_index: u64,
            _tree_size: u64,
        ) -> Result<GetEntryAndProofResponse, Self::Error>;
    }
}

#[cfg(feature = "async")]
mod internal_async_api {
    use async_trait::async_trait;

    use crate::ctlog::v1::{
        cert::DecodedEntry,
        model::{
            AddChainResponse, GetEntriesResponse, GetEntryAndProofResponse, GetProofByHashResponse,
            GetRootsResponse, GetSthConsistencyResponse, GetSthResponse,
        },
    };

    #[async_trait]
    pub trait CtLogApiV1Trait {
        type Error: std::error::Error + Send + Sync + 'static;

        /// Add Chain to Log
        /// ---
        /// path: `ct/v1/add-chain`
        ///
        /// [RFC 6962 4.1](https://datatracker.ietf.org/doc/html/rfc6962#section-4.1)
        async fn add_chain(&self, _chain: Vec<String>) -> Result<AddChainResponse, Self::Error>;

        /// Add PreCertChain to Log
        /// ---
        /// path: `ct/v1/add-pre-chain`
        ///
        /// [RFC 6962 4.2](https://datatracker.ietf.org/doc/html/rfc6962#section-4.2)
        async fn add_pre_chain(&self, _chain: Vec<String>)
        -> Result<AddChainResponse, Self::Error>;

        /// Retrieve Latest Signed Tree Head
        /// ---
        /// path: `ct/v1/get-sth`
        ///
        /// [RFC 6962 4.3](https://datatracker.ietf.org/doc/html/rfc6962#section-4.3)
        async fn get_sth(&self) -> Result<GetSthResponse, Self::Error>;

        /// Retrieve Merkle Consistency Proof between Two Signed Tree Heads
        /// ---
        /// path: `ct/v1/get-sth-consistency?first={first}&second={second}`
        ///
        /// [RFC 6962 4.4](https://datatracker.ietf.org/doc/html/rfc6962#section-4.4)
        async fn get_sth_consistency(
            &self,
            _first: u64,
            _second: u64,
        ) -> Result<GetSthConsistencyResponse, Self::Error>;

        /// Retrieve Merkle Audit Proof from Log by Leaf Hash
        /// ---
        /// path: `ct/v1/get-proof-by-hash?hash={hash}&tree_size={tree_size}`
        ///
        /// [RFC 6962 4.5](https://datatracker.ietf.org/doc/html/rfc6962#section-4.5)
        async fn get_proof_by_hash(
            &self,
            _hash: &str,
            _tree_size: u64,
        ) -> Result<GetProofByHashResponse, Self::Error>;

        /// Retrieve Entries from Log
        /// ---
        /// path: `ct/v1/get-entries?start={start}&end={end}`
        ///
        /// [RFC 6962 4.6](https://datatracker.ietf.org/doc/html/rfc6962#section-4.6)
        async fn get_entries(
            &self,
            _start: u64,
            _end: u64,
        ) -> Result<GetEntriesResponse, Self::Error>;

        /// Retrieve Entries from Log and decode them
        /// ---
        /// path: `ct/v1/get-entries?start={start}&end={end}`
        ///
        /// [RFC 6962 4.6](https://datatracker.ietf.org/doc/html/rfc6962#section-4.6)
        async fn get_entries_decoded(
            &self,
            _start: u64,
            _end: u64,
        ) -> Result<Vec<DecodedEntry>, Self::Error>;

        /// Retrieve Accepted Root Certificates
        /// ---
        /// path: `ct/v1/get-roots`
        ///
        /// [RFC 6962 4.7](https://datatracker.ietf.org/doc/html/rfc6962#section-4.7)
        async fn get_roots(&self) -> Result<GetRootsResponse, Self::Error>;

        /// Retrieve Entry + Merkle Audit Proof from Log
        /// ---
        /// path: `ct/v1/get-entry-and-proof?leaf_index={leaf_index}&tree_size={tree_size}`
        ///
        /// [RFC 6962 4.8](https://datatracker.ietf.org/doc/html/rfc6962#section-4.8)
        async fn get_entry_and_proof(
            &self,
            _leaf_index: u64,
            _tree_size: u64,
        ) -> Result<GetEntryAndProofResponse, Self::Error>;
    }
}

#[cfg(not(feature = "async"))]
pub use internal_sync_api::CtLogApiV1Trait as CtLogApiV1;

#[cfg(feature = "async")]
pub use internal_async_api::CtLogApiV1Trait as CtLogApiV1;
