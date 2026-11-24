//! Strict RFC 4648 standard Base64 encoding and decoding (standard library only).

use crate::UpdaterError;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes raw bytes into standard RFC 4648 Base64 with `=` padding.
pub(crate) fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes a strict RFC 4648 standard Base64 string.
///
/// Rejects whitespace, URL-safe `-`/`_` characters, unpadded lengths (`len % 4 != 0`),
/// misplaced padding `=`, and non-zero canonical trailing padding bits.
pub(crate) fn decode(input: &str) -> Result<Vec<u8>, UpdaterError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(UpdaterError::InvalidBase64(format!(
            "Base64 length {} is not a multiple of 4",
            bytes.len()
        )));
    }

    let num_chunks = bytes.len() / 4;
    let mut out = Vec::with_capacity(num_chunks * 3);

    for (chunk_idx, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let is_last = chunk_idx + 1 == num_chunks;
        let v0 = decode_data_char(chunk[0])?;
        let v1 = decode_data_char(chunk[1])?;

        match (chunk[2], chunk[3]) {
            (b'=', b'=') => {
                if !is_last {
                    return Err(UpdaterError::InvalidBase64(
                        "padding '=' may only appear in the final Base64 quantum".to_string(),
                    ));
                }
                // RFC 4648 §3.5: the 4 unused trailing bits of `v1` must be zero.
                if (v1 & 0x0F) != 0 {
                    return Err(UpdaterError::InvalidBase64(
                        "non-zero trailing padding bits in Base64 input".to_string(),
                    ));
                }
                out.push((v0 << 2) | (v1 >> 4));
            }
            (b'=', _) => {
                return Err(UpdaterError::InvalidBase64(
                    "invalid Base64 padding sequence '=X'".to_string(),
                ));
            }
            (c2, b'=') => {
                if !is_last {
                    return Err(UpdaterError::InvalidBase64(
                        "padding '=' may only appear in the final Base64 quantum".to_string(),
                    ));
                }
                let v2 = decode_data_char(c2)?;
                // RFC 4648 §3.5: the 2 unused trailing bits of `v2` must be zero.
                if (v2 & 0x03) != 0 {
                    return Err(UpdaterError::InvalidBase64(
                        "non-zero trailing padding bits in Base64 input".to_string(),
                    ));
                }
                out.push((v0 << 2) | (v1 >> 4));
                out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
            }
            (c2, c3) => {
                let v2 = decode_data_char(c2)?;
                let v3 = decode_data_char(c3)?;
                out.push((v0 << 2) | (v1 >> 4));
                out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
    }

    Ok(out)
}

fn decode_data_char(b: u8) -> Result<u8, UpdaterError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Err(UpdaterError::InvalidBase64(
            "unexpected '=' in Base64 data position".to_string(),
        )),
        _ => Err(UpdaterError::InvalidBase64(format!(
            "invalid Base64 byte 0x{b:02X}"
        ))),
    }
}
