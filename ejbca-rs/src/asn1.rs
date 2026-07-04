use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerTagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerTag {
    pub class: DerTagClass,
    pub constructed: bool,
    pub number: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DerElement<'a> {
    pub tag: DerTag,
    pub content: &'a [u8],
    pub full: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerError {
    Empty,
    Truncated,
    IndefiniteLength,
    NonMinimalLength,
    LengthOverflow,
    TrailingData,
    UnsupportedHighTag,
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerError::Empty => write!(f, "DER 입력이 비어 있습니다"),
            DerError::Truncated => write!(f, "DER 입력이 잘렸습니다"),
            DerError::IndefiniteLength => write!(f, "DER indefinite length는 허용하지 않습니다"),
            DerError::NonMinimalLength => write!(f, "DER length가 최소 인코딩이 아닙니다"),
            DerError::LengthOverflow => write!(f, "DER length가 처리 가능한 범위를 넘었습니다"),
            DerError::TrailingData => write!(f, "DER 최상위 객체 뒤에 추가 데이터가 있습니다"),
            DerError::UnsupportedHighTag => write!(f, "DER high-tag-number가 너무 큽니다"),
        }
    }
}

pub fn parse_single(input: &[u8]) -> Result<DerElement<'_>, DerError> {
    let (element, rest) = parse_element(input)?;
    if rest.is_empty() {
        Ok(element)
    } else {
        Err(DerError::TrailingData)
    }
}

pub fn parse_children(input: &[u8]) -> Result<Vec<DerElement<'_>>, DerError> {
    let mut rest = input;
    let mut children = Vec::new();
    while !rest.is_empty() {
        let (element, next) = parse_element(rest)?;
        children.push(element);
        rest = next;
    }
    Ok(children)
}

pub fn parse_element(input: &[u8]) -> Result<(DerElement<'_>, &[u8]), DerError> {
    if input.is_empty() {
        return Err(DerError::Empty);
    }
    if input.len() < 2 {
        return Err(DerError::Truncated);
    }

    let first = input[0];
    let class = match first >> 6 {
        0 => DerTagClass::Universal,
        1 => DerTagClass::Application,
        2 => DerTagClass::ContextSpecific,
        _ => DerTagClass::Private,
    };
    let constructed = first & 0x20 != 0;
    let mut pos = 1;
    let mut number = u64::from(first & 0x1f);
    if number == 0x1f {
        number = 0;
        let mut tag_octets = 0;
        loop {
            if pos >= input.len() {
                return Err(DerError::Truncated);
            }
            let byte = input[pos];
            pos += 1;
            tag_octets += 1;
            if tag_octets > 9 {
                return Err(DerError::UnsupportedHighTag);
            }
            number = number
                .checked_mul(128)
                .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
                .ok_or(DerError::UnsupportedHighTag)?;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    if pos >= input.len() {
        return Err(DerError::Truncated);
    }
    let first_len = input[pos];
    pos += 1;
    let length = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let len_octets = usize::from(first_len & 0x7f);
        if len_octets == 0 {
            return Err(DerError::IndefiniteLength);
        }
        if len_octets > std::mem::size_of::<usize>() || pos + len_octets > input.len() {
            return Err(DerError::Truncated);
        }
        if input[pos] == 0 {
            return Err(DerError::NonMinimalLength);
        }
        let mut value = 0usize;
        for byte in &input[pos..pos + len_octets] {
            value = value
                .checked_mul(256)
                .and_then(|current| current.checked_add(usize::from(*byte)))
                .ok_or(DerError::LengthOverflow)?;
        }
        if value < 128 {
            return Err(DerError::NonMinimalLength);
        }
        pos += len_octets;
        value
    };

    let end = pos.checked_add(length).ok_or(DerError::LengthOverflow)?;
    if end > input.len() {
        return Err(DerError::Truncated);
    }

    Ok((
        DerElement {
            tag: DerTag {
                class,
                constructed,
                number,
            },
            content: &input[pos..end],
            full: &input[..end],
        },
        &input[end..],
    ))
}

pub fn is_universal_sequence(element: &DerElement<'_>) -> bool {
    element.tag.class == DerTagClass::Universal
        && element.tag.constructed
        && element.tag.number == 16
}

pub fn der_sequence(content: Vec<u8>) -> Vec<u8> {
    der_tlv(0x30, content)
}

pub fn der_explicit_context(tag: u8, content: Vec<u8>) -> Vec<u8> {
    der_tlv(0xa0 | (tag & 0x1f), content)
}

pub fn der_context_primitive(tag: u8, content: Vec<u8>) -> Vec<u8> {
    der_tlv(0x80 | (tag & 0x1f), content)
}

pub fn der_context_constructed(tag: u8, content: Vec<u8>) -> Vec<u8> {
    der_tlv(0xa0 | (tag & 0x1f), content)
}

pub fn der_enum(value: u8) -> Vec<u8> {
    der_tlv(0x0a, vec![value])
}

pub fn der_bool(value: bool) -> Vec<u8> {
    der_tlv(0x01, vec![if value { 0xff } else { 0x00 }])
}

pub fn der_integer_from_i64(value: i64) -> Vec<u8> {
    if value == 0 {
        return der_tlv(0x02, vec![0]);
    }
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    der_tlv(0x02, bytes)
}

pub fn der_integer_bytes_positive(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes;
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    let mut content = if value.is_empty() {
        vec![0]
    } else {
        value.to_vec()
    };
    if content.first().is_some_and(|byte| byte & 0x80 != 0) {
        content.insert(0, 0);
    }
    der_tlv(0x02, content)
}

pub fn der_octet_string(content: Vec<u8>) -> Vec<u8> {
    der_tlv(0x04, content)
}

pub fn der_bit_string(content: Vec<u8>) -> Vec<u8> {
    let mut value = Vec::with_capacity(content.len() + 1);
    value.push(0);
    value.extend(content);
    der_tlv(0x03, value)
}

pub fn der_generalized_time(value: &str) -> Vec<u8> {
    der_tlv(0x18, value.as_bytes().to_vec())
}

pub fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    if arcs.len() >= 2 {
        content.push((arcs[0] * 40 + arcs[1]) as u8);
        for arc in &arcs[2..] {
            encode_base128(*arc, &mut content);
        }
    }
    der_tlv(0x06, content)
}

pub fn decode_oid_content(content: &[u8]) -> Result<Vec<u64>, DerError> {
    if content.is_empty() {
        return Err(DerError::Truncated);
    }
    let first = content[0];
    let mut arcs = vec![u64::from(first / 40), u64::from(first % 40)];
    let mut value = 0u64;
    let mut in_arc = false;
    for byte in &content[1..] {
        in_arc = true;
        value = value
            .checked_mul(128)
            .and_then(|current| current.checked_add(u64::from(byte & 0x7f)))
            .ok_or(DerError::LengthOverflow)?;
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            in_arc = false;
        }
    }
    if in_arc {
        return Err(DerError::Truncated);
    }
    Ok(arcs)
}

pub fn der_tlv(tag: u8, content: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + content.len() + 5);
    out.push(tag);
    encode_length(content.len(), &mut out);
    out.extend(content);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let length_bytes = &bytes[first_non_zero..];
    out.push(0x80 | length_bytes.len() as u8);
    out.extend(length_bytes);
}

fn encode_base128(mut value: u64, out: &mut Vec<u8>) {
    let mut stack = [0u8; 10];
    let mut pos = stack.len();
    stack[pos - 1] = (value & 0x7f) as u8;
    pos -= 1;
    value >>= 7;
    while value > 0 {
        stack[pos - 1] = ((value & 0x7f) as u8) | 0x80;
        pos -= 1;
        value >>= 7;
    }
    out.extend(&stack[pos..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_sequence_children() {
        let root = parse_single(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00]).unwrap();
        assert!(is_universal_sequence(&root));
        let children = parse_children(root.content).unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].tag.number, 2);
        assert_eq!(children[1].tag.number, 5);
    }

    #[test]
    fn rejects_trailing_data() {
        assert_eq!(
            parse_single(&[0x05, 0x00, 0x00]).unwrap_err(),
            DerError::TrailingData
        );
    }

    #[test]
    fn rejects_indefinite_length() {
        assert_eq!(
            parse_single(&[0x30, 0x80, 0x00, 0x00]).unwrap_err(),
            DerError::IndefiniteLength
        );
    }

    #[test]
    fn encodes_and_decodes_oid() {
        let oid = der_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]);
        let parsed = parse_single(&oid).unwrap();
        assert_eq!(
            decode_oid_content(parsed.content).unwrap(),
            vec![1, 3, 6, 1, 5, 5, 7, 48, 1, 1]
        );
    }

    #[test]
    fn encodes_positive_integer_with_sign_padding() {
        assert_eq!(
            der_integer_bytes_positive(&[0x80]),
            vec![0x02, 0x02, 0x00, 0x80]
        );
    }
}
