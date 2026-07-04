use rand::{RngCore, rngs::OsRng};
use rcgen::{DistinguishedName, DnType, DnValue, SerialNumber};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::error::{AppError, AppResult};

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn now_unix() -> i64 {
    now().unix_timestamp()
}

pub fn days_from_now(days: i64) -> OffsetDateTime {
    now() + Duration::days(days)
}

pub fn fingerprint_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// RFC 5280은 인증서 serialNumber를 20 octet 이하로 제한한다.
/// 16바이트 난수를 쓰고 최상위 비트를 내려 양수 INTEGER로 인코딩되도록 한다.
pub fn new_serial() -> (SerialNumber, String) {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    if bytes.iter().all(|b| *b == 0) {
        bytes[15] = 1;
    }
    (SerialNumber::from_slice(&bytes), hex::encode(bytes))
}

pub fn serial_from_hex(serial_hex: &str) -> AppResult<SerialNumber> {
    let bytes = hex::decode(serial_hex)
        .map_err(|_| AppError::BadRequest(format!("잘못된 인증서 serial hex: {serial_hex}")))?;
    Ok(SerialNumber::from(bytes))
}

pub fn parse_distinguished_name(input: &str) -> AppResult<DistinguishedName> {
    let mut dn = DistinguishedName::new();
    for part in input.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            AppError::BadRequest(format!("DN 항목 형식이 잘못되었습니다: {trimmed}"))
        })?;
        let ty = match key.trim().to_ascii_uppercase().as_str() {
            "CN" => DnType::CommonName,
            "O" => DnType::OrganizationName,
            "OU" => DnType::OrganizationalUnitName,
            "C" => DnType::CountryName,
            "L" => DnType::LocalityName,
            "ST" | "S" => DnType::StateOrProvinceName,
            other => {
                return Err(AppError::BadRequest(format!(
                    "아직 지원하지 않는 DN 속성입니다: {other}"
                )));
            }
        };
        dn.push(ty, value.trim());
    }
    Ok(dn)
}

pub fn format_distinguished_name(dn: &DistinguishedName) -> String {
    dn.iter()
        .map(|(ty, value)| format!("{}={}", dn_type_label(ty), dn_value_to_string(value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn dn_type_label(ty: &DnType) -> String {
    match ty {
        DnType::CountryName => "C".to_string(),
        DnType::LocalityName => "L".to_string(),
        DnType::StateOrProvinceName => "ST".to_string(),
        DnType::OrganizationName => "O".to_string(),
        DnType::OrganizationalUnitName => "OU".to_string(),
        DnType::CommonName => "CN".to_string(),
        DnType::CustomDnType(oid) => oid.iter().map(u64::to_string).collect::<Vec<_>>().join("."),
        _ => format!("{ty:?}"),
    }
}

fn dn_value_to_string(value: &DnValue) -> String {
    match value {
        DnValue::Utf8String(value) => value.clone(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_dn() {
        let dn = parse_distinguished_name("CN=device-1,O=Example,C=KR").unwrap();
        assert_eq!(format_distinguished_name(&dn), "CN=device-1,O=Example,C=KR");
    }

    #[test]
    fn serial_is_within_rfc5280_limit() {
        let (serial, serial_hex) = new_serial();
        assert!(serial.len() <= 20);
        assert_eq!(serial_hex.len(), 32);
    }
}
