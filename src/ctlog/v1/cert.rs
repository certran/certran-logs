use base64::{Engine, prelude::BASE64_STANDARD};
use std::fmt;

use ouroboros::self_referencing;
use x509_parser::prelude::*;

use crate::error::{BinaryParsingError, CtLogError};

use super::{
    model::Entry,
    util::{read_exact_bytes, read_u8, read_u16_be, read_u24_be, read_u64_be, read_vec},
};

#[cfg(feature = "debug-fmt")]
use chrono::TimeZone;

#[cfg(feature = "debug-fmt")]
use oid_registry::{OidRegistry, format_oid};

#[cfg(feature = "debug-fmt")]
use super::util::{print_x509_extension, print_x509_ski};

#[self_referencing(pub_extras)]
#[derive(Debug)]
pub struct WrapX509Certificate {
    raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub certificate: X509Certificate<'this>,
}

impl WrapX509Certificate {
    pub fn try_from_der(v: &[u8]) -> Result<Self, BinaryParsingError> {
        Ok(WrapX509CertificateBuilder {
            raw: v.to_vec(),
            certificate_builder: |raw: &Vec<u8>| X509Certificate::from_der(raw).unwrap().1,
        }
        .build())
    }
}

#[cfg(feature = "debug-fmt")]
impl fmt::Display for WrapX509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certificate = self.borrow_certificate();
        writeln!(f, "Certificate:")?;
        writeln!(f, "  Data:")?;
        writeln!(f, "    Version: {}", certificate.version())?;
        writeln!(
            f,
            "    Serial Number: {} ({})",
            certificate.serial,
            certificate.raw_serial_as_string()
        )?;
        writeln!(
            f,
            "  Signature Algorithm: {}",
            format_oid(
                certificate.signature_algorithm.oid(),
                &OidRegistry::default().with_all_crypto()
            )
        )?;
        writeln!(f, "    Issuer: {}", certificate.issuer())?;
        writeln!(f, "    Validity:")?;
        writeln!(f, "      Not Before: {}", certificate.validity().not_before)?;
        writeln!(f, "      Not After : {}", certificate.validity().not_after)?;
        writeln!(f, "    Subject: {}", certificate.subject())?;
        writeln!(f, "    Subject Public Key Info:")?;
        print_x509_ski(f, certificate.public_key(), 6)?;

        if !certificate.extensions().is_empty() {
            writeln!(f, "    X509v3 extensions:")?;
            for extension in certificate.extensions() {
                print_x509_extension(f, &extension.oid, extension, 6)?;
            }
        }

        Ok(())
    }
}

#[self_referencing(pub_extras)]
#[derive(Debug)]
pub struct WrapTbsCertificate {
    raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub certificate: TbsCertificate<'this>,
}

impl WrapTbsCertificate {
    pub fn try_from_der(v: &[u8]) -> Result<Self, BinaryParsingError> {
        Ok(WrapTbsCertificateBuilder {
            raw: v.to_vec(),
            certificate_builder: |raw: &Vec<u8>| TbsCertificate::from_der(raw).unwrap().1,
        }
        .build())
    }
}

#[cfg(feature = "debug-fmt")]
impl fmt::Display for WrapTbsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certificate = self.borrow_certificate();

        writeln!(f, "Certificate:")?;
        writeln!(f, "  Data:")?;
        writeln!(f, "    Version: {}", certificate.version())?;
        writeln!(
            f,
            "    Serial Number: {} ({})",
            certificate.serial,
            certificate.raw_serial_as_string()
        )?;
        writeln!(
            f,
            "  Signature Algorithm: {}",
            format_oid(
                certificate.signature.oid(),
                &OidRegistry::default().with_all_crypto()
            )
        )?;
        writeln!(f, "    Issuer: {}", certificate.issuer())?;
        writeln!(f, "    Validity:")?;
        writeln!(f, "      Not Before: {}", certificate.validity().not_before)?;
        writeln!(f, "      Not After : {}", certificate.validity().not_after)?;
        writeln!(f, "    Subject: {}", certificate.subject())?;
        writeln!(f, "    Subject Public Key Info:")?;
        print_x509_ski(f, certificate.public_key(), 6)?;

        if !certificate.extensions().is_empty() {
            writeln!(f, "    X509v3 extensions:")?;
            for extension in certificate.extensions() {
                print_x509_extension(f, &extension.oid, extension, 6)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

impl LogEntryType {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let id = read_u16_be(input)?;
        match id {
            0 => Ok(LogEntryType::X509Entry),
            1 => Ok(LogEntryType::PrecertEntry),
            _ => Err(BinaryParsingError::InvalidSequence(format!(
                "Invalid LogEntryType id: {}",
                id
            ))),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ASN1Cert {
    pub length: u32,
    pub certificate: Box<WrapX509Certificate>,
}

impl ASN1Cert {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let length = read_u24_be(input)?;
        let cert_data = read_exact_bytes(input, length as usize)?;

        let wrapped_cert = WrapX509Certificate::try_from_der(cert_data)?;

        Ok(ASN1Cert {
            length,
            certificate: Box::new(wrapped_cert),
        })
    }
}

#[cfg(feature = "debug-fmt")]
impl fmt::Display for ASN1Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.certificate.fmt(f)
    }
}

#[derive(Debug)]
pub struct ASN1CertChain {
    pub length: u32,
    pub certificates: Vec<ASN1Cert>,
}

impl ASN1CertChain {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let total_chain_length = read_u24_be(input)?;
        let mut certs_data_slice = read_exact_bytes(input, total_chain_length as usize)?;
        let mut certificates = Vec::new();

        let mut consumed_len = 0;
        while consumed_len < total_chain_length {
            let init_len = certs_data_slice.len();
            if init_len == 0 {
                if consumed_len < total_chain_length {
                    return Err(BinaryParsingError::InsufficientData);
                }

                break;
            }

            let cert = ASN1Cert::parse(&mut certs_data_slice)?;
            consumed_len += (init_len - certs_data_slice.len()) as u32;
            certificates.push(cert);
        }
        if consumed_len != total_chain_length {
            return Err(BinaryParsingError::InvalidSequence(format!(
                "Invalid ASN1CertChain length: {}",
                consumed_len
            )));
        }

        Ok(ASN1CertChain {
            length: total_chain_length,
            certificates,
        })
    }
}

#[derive(Debug)]
pub struct PrecertChainEntry {
    pub pre_certificate: ASN1Cert,
    pub precertificate_chain: ASN1CertChain,
}

impl PrecertChainEntry {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let pre_cert = ASN1Cert::parse(input)?;
        let pre_cert_chain = ASN1CertChain::parse(input)?;
        Ok(PrecertChainEntry {
            pre_certificate: pre_cert,
            precertificate_chain: pre_cert_chain,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Version {
    V1 = 0,
}

impl Version {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let id = read_u8(input)?;
        match id {
            0 => Ok(Version::V1),
            _ => Err(BinaryParsingError::InvalidSequence(format!(
                "Unknown Version id: {}",
                id
            ))),
        }
    }
}

#[derive(Debug)]
pub struct IssuerKeyHash([u8; 32]);

impl IssuerKeyHash {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let bytes = read_exact_bytes(input, 32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(IssuerKeyHash(arr))
    }
}

impl fmt::LowerHex for IssuerKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PreCert {
    pub issuer_key_hash: IssuerKeyHash,
    pub length: u32,
    pub tbs_certificate: Box<WrapTbsCertificate>,
}

impl PreCert {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let iss_key_hash = IssuerKeyHash::parse(input)?;
        let length = read_u24_be(input)?;
        let tbs_data = read_exact_bytes(input, length as usize)?;

        let wrapped_tbs_cert = WrapTbsCertificate::try_from_der(tbs_data)?;

        Ok(PreCert {
            issuer_key_hash: iss_key_hash,
            length,
            tbs_certificate: Box::new(wrapped_tbs_cert),
        })
    }
}

#[cfg(feature = "debug-fmt")]
impl fmt::Display for PreCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.tbs_certificate.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct CtExtensions {
    pub length: u16,
    pub extensions: Vec<u8>,
}

impl CtExtensions {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let length = read_u16_be(input)?;
        let ext_data = read_vec(input, length as usize)?;
        Ok(CtExtensions {
            length,
            extensions: ext_data.to_vec(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MerkleLeafType {
    TimestampedEntry = 0,
}

impl MerkleLeafType {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let id = read_u8(input)?;
        match id {
            0 => Ok(MerkleLeafType::TimestampedEntry),
            _ => Err(BinaryParsingError::InvalidSequence(format!(
                "Unknown MerkleLeafType id: {}",
                id
            ))),
        }
    }
}

#[derive(Debug)]
pub enum TimestampedEntrySignedInner {
    X509(ASN1Cert),
    Precert(PreCert),
}

impl TimestampedEntrySignedInner {
    pub fn parse(input: &mut &[u8], entry_type: &LogEntryType) -> Result<Self, BinaryParsingError> {
        match entry_type {
            LogEntryType::X509Entry => {
                ASN1Cert::parse(input).map(TimestampedEntrySignedInner::X509)
            }
            LogEntryType::PrecertEntry => {
                PreCert::parse(input).map(TimestampedEntrySignedInner::Precert)
            }
        }
    }
}

#[derive(Debug)]
pub struct TimestampedEntry {
    pub timestamp: u64,
    pub entry_type: LogEntryType,
    pub signed_entry: TimestampedEntrySignedInner,
    pub extensions: CtExtensions,
}

impl TimestampedEntry {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let timestamp = read_u64_be(input)?;
        let entry_type = LogEntryType::parse(input)?;

        let signed_entry = TimestampedEntrySignedInner::parse(input, &entry_type)?;
        let ext = CtExtensions::parse(input)?;

        Ok(TimestampedEntry {
            timestamp,
            entry_type,
            signed_entry,
            extensions: ext,
        })
    }
}

#[derive(Debug)]
pub struct MerkleTreeLeaf {
    pub version: Version,
    pub leaf_type: MerkleLeafType,
    pub timestamped_entry: TimestampedEntry,
}

impl MerkleTreeLeaf {
    pub fn parse(input: &mut &[u8]) -> Result<Self, BinaryParsingError> {
        let ver = Version::parse(input)?;
        let leaf_type = MerkleLeafType::parse(input)?;
        let timestamped_entry = TimestampedEntry::parse(input)?;

        Ok(MerkleTreeLeaf {
            version: ver,
            leaf_type,
            timestamped_entry,
        })
    }
}

#[derive(Debug)]
pub enum DecodedEntryInner {
    X509(ASN1CertChain),
    Precert(PrecertChainEntry),
}

/// A structure representing a log entry (parsed from the response of /ct/v1/get-entries).
#[derive(Debug)]
pub struct DecodedEntry {
    pub leaf: MerkleTreeLeaf,
    pub extra_data: DecodedEntryInner,
    pub raw_leaf: Vec<u8>,
}

impl TryFrom<&Entry> for DecodedEntry {
    type Error = CtLogError;

    fn try_from(entry: &Entry) -> Result<Self, CtLogError> {
        let decoded_leaf_bytes: Vec<u8> = BASE64_STANDARD.decode(entry.leaf_input.clone())?;

        let mut leaf_in_slice = decoded_leaf_bytes.as_slice();
        let leaf = MerkleTreeLeaf::parse(&mut leaf_in_slice)?;

        if !leaf_in_slice.is_empty() {
            return Err(BinaryParsingError::InvalidSequence(format!(
                "Trailing data after parsing MerkleTreeLeaf: {} bytes left",
                leaf_in_slice.len()
            ))
            .into());
        }

        let extra_data_decoded = BASE64_STANDARD.decode(&entry.extra_data)?;
        let mut extra_data_slice = extra_data_decoded.as_slice();

        let extra_data = match leaf.timestamped_entry.entry_type {
            LogEntryType::X509Entry => {
                let cert_chain = ASN1CertChain::parse(&mut extra_data_slice)?;
                DecodedEntryInner::X509(cert_chain)
            }
            LogEntryType::PrecertEntry => {
                let precert_chain = PrecertChainEntry::parse(&mut extra_data_slice)?;
                DecodedEntryInner::Precert(precert_chain)
            }
        };

        if !extra_data_slice.is_empty() {
            return Err(BinaryParsingError::InvalidSequence(format!(
                "Trailing data after parsing extra_data: {} bytes left",
                extra_data_slice.len()
            ))
            .into());
        }

        Ok(Self {
            leaf,
            extra_data,
            raw_leaf: decoded_leaf_bytes,
        })
    }
}

#[cfg(feature = "debug-fmt")]
impl fmt::Display for DecodedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Timestamp={} ({}) ",
            self.leaf.timestamped_entry.timestamp,
            chrono::Utc
                .timestamp_millis_opt(self.leaf.timestamped_entry.timestamp as i64)
                .unwrap()
        )?;

        match (
            &self.leaf.timestamped_entry.entry_type,
            &self.leaf.timestamped_entry.signed_entry,
        ) {
            (LogEntryType::X509Entry, TimestampedEntrySignedInner::X509(certificate)) => {
                writeln!(f, "X.509 certificate:")?;
                writeln!(f, "{certificate}")?;

                // TODO: print the chain
            }
            (LogEntryType::PrecertEntry, TimestampedEntrySignedInner::Precert(certificate)) => {
                writeln!(
                    f,
                    "pre-certificate from issuer with keyhash {:x}:",
                    certificate.issuer_key_hash
                )?;
                writeln!(f, "{certificate}")?;

                // TODO: print the chain
            }
            _ => unreachable!(),
        }

        Ok(())
    }
}
