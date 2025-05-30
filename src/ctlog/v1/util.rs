use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt};

#[cfg(feature = "debug-fmt")]
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

#[cfg(feature = "debug-fmt")]
use oid_registry::{Oid, OidRegistry, format_oid};

#[cfg(feature = "debug-fmt")]
use x509_parser::{
    prelude::{GeneralName, ParsedExtension, X509Extension, x509::SubjectPublicKeyInfo},
    utils::format_serial,
};

use crate::error::BinaryParsingError;

pub fn read_u8(input: &mut &[u8]) -> Result<u8, BinaryParsingError> {
    if input.is_empty() {
        return Err(BinaryParsingError::InsufficientData);
    }

    let val = input[0];
    *input = &input[1..];
    Ok(val)
}

pub fn read_u16_be(input: &mut &[u8]) -> Result<u16, BinaryParsingError> {
    if input.len() < 2 {
        return Err(BinaryParsingError::InsufficientData);
    }

    let mut cursor = Cursor::new(&input[..2]);
    let val = cursor.read_u16::<BigEndian>()?;
    *input = &input[2..];
    Ok(val)
}

pub fn read_u24_be(input: &mut &[u8]) -> Result<u32, BinaryParsingError> {
    if input.len() < 3 {
        return Err(BinaryParsingError::InsufficientData);
    }

    let val = u32::from_be_bytes([0, input[0], input[1], input[2]]);
    *input = &input[3..];
    Ok(val)
}

pub fn read_u64_be(input: &mut &[u8]) -> Result<u64, BinaryParsingError> {
    if input.len() < 8 {
        return Err(BinaryParsingError::InsufficientData);
    }

    let mut cursor = Cursor::new(&input[..8]);
    let val = cursor.read_u64::<BigEndian>()?;
    *input = &input[8..];
    Ok(val)
}

pub fn read_exact_bytes<'a>(
    input: &mut &'a [u8],
    len: usize,
) -> Result<&'a [u8], BinaryParsingError> {
    if input.len() < len {
        return Err(BinaryParsingError::InsufficientData);
    }
    let (data, rest) = input.split_at(len);
    *input = rest;
    Ok(data)
}

pub fn read_vec(input: &mut &[u8], len: usize) -> Result<Vec<u8>, BinaryParsingError> {
    read_exact_bytes(input, len).map(|data| data.to_vec())
}

#[cfg(feature = "debug-fmt")]
pub fn print_x509_ski(
    f: &mut fmt::Formatter<'_>,
    public_key: &SubjectPublicKeyInfo,
    indent: usize,
) -> fmt::Result {
    writeln!(
        f,
        "{:indent$}Public Key Algorithm: {}",
        "",
        format_oid(
            public_key.algorithm.oid(),
            &OidRegistry::default().with_all_crypto()
        ),
        indent = indent,
    )?;

    Ok(())
}

#[cfg(feature = "debug-fmt")]
pub fn print_x509_extension(
    f: &mut fmt::Formatter<'_>,
    _oid: &Oid,
    extension: &X509Extension,
    indent: usize,
) -> fmt::Result {
    match extension.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            writeln!(
                f,
                "{:indent$}X509v3 Authority Key Identifier:",
                "",
                indent = indent
            )?;
            if let Some(key_id) = &aki.key_identifier {
                writeln!(
                    f,
                    "{:indent$}KeyIdentifier: {:x}",
                    "",
                    key_id,
                    indent = indent + 2,
                )?;
            }
            if let Some(issuer) = &aki.authority_cert_issuer {
                for name in issuer {
                    writeln!(
                        f,
                        "{:indent$}Cert Issuer: {}",
                        "",
                        name,
                        indent = indent + 2
                    )?;
                }
            }
            if let Some(serial) = &aki.authority_cert_serial {
                writeln!(
                    f,
                    "{:indent$}Cert Serial: {}",
                    "",
                    format_serial(serial),
                    indent = indent + 2,
                )?;
            }
        }
        ParsedExtension::BasicConstraints(bc) => {
            writeln!(
                f,
                "{:indent$}X509v3 CA:\n{:indent2$}{}",
                "",
                "",
                bc.ca,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        ParsedExtension::CRLDistributionPoints(points) => {
            writeln!(
                f,
                "{:indent$}X509v3 CRL Distribution Points:",
                "",
                indent = indent
            )?;

            for point in points.iter() {
                if let Some(name) = &point.distribution_point {
                    writeln!(
                        f,
                        "{:indent$}Full Name: {:?}",
                        "",
                        name,
                        indent = indent + 2
                    )?;
                }
                if let Some(reasons) = &point.reasons {
                    writeln!(f, "{:indent$}Reasons: {}", "", reasons, indent = indent + 2)?;
                }
                if let Some(crl_issuer) = &point.crl_issuer {
                    write!(f, "{:indent$}CRL Issuer: ", "", indent = indent + 2)?;
                    for gn in crl_issuer {
                        write!(f, "{} ", gn)?;
                    }
                    writeln!(f)?;
                }
                writeln!(f)?;
            }
        }
        ParsedExtension::KeyUsage(ku) => {
            writeln!(
                f,
                "{:indent$}X509v3 Key Usage:\n{:indent2$}{}",
                "",
                "",
                ku,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        ParsedExtension::NSCertType(ty) => {
            writeln!(
                f,
                "{:indent$}Netscape Cert Type:\n{:indent2$}{}",
                "",
                "",
                ty,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        ParsedExtension::SubjectAlternativeName(san) => {
            for name in &san.general_names {
                let s = match name {
                    GeneralName::DNSName(s) => {
                        format!("DNS:{}", s)
                    }
                    GeneralName::IPAddress(b) => {
                        let ip = match b.len() {
                            4 => {
                                let b = <[u8; 4]>::try_from(*b).unwrap();
                                let ip = Ipv4Addr::from(b);
                                format!("{}", ip)
                            }
                            16 => {
                                let b = <[u8; 16]>::try_from(*b).unwrap();
                                let ip = Ipv6Addr::from(b);
                                format!("{}", ip)
                            }
                            l => format!("invalid (len={})", l),
                        };
                        format!("IP Address:{}", ip)
                    }
                    _ => {
                        format!("{:?}", name)
                    }
                };
                writeln!(
                    f,
                    "{:indent$}X509v3 Subject Alternative Name:\n{:indent2$}{}",
                    "",
                    "",
                    s,
                    indent = indent,
                    indent2 = indent + 2
                )?;
            }
        }
        ParsedExtension::SubjectKeyIdentifier(id) => {
            writeln!(
                f,
                "{:indent$}X509v3 Subject Key Identifier:\n{:indent2$}{:x}",
                "",
                "",
                id,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
        x => {
            writeln!(
                f,
                "{:indent$}X509v3 Unknown Extension:\n{:indent2$}{:?}",
                "",
                "",
                x,
                indent = indent,
                indent2 = indent + 2
            )?;
        }
    }
    Ok(())
}
