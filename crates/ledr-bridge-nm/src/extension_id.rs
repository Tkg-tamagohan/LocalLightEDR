//! Deterministic Chrome extension ID derivation from SPKI DER public keys (`L-20`).

use anyhow::{bail, Result};

/// Native Messaging host identifier shared by `ledr-bridge-nm`, browser manifests, and `ledr-ui`.
pub const NATIVE_HOST_NAME: &str = "com.localedr.bridge";

/// Pinned Chrome extension ID derived from the repository's fixed RSA-2048 public key (`L-20`).
pub const DEFAULT_CHROME_EXTENSION_ID: &str = "ecelachfiiiiiibpjeomfncgpegbpanh";

/// Returns `true` if `id` is a valid 32-character Chrome extension ID (`[a-p]{32}`).
pub fn is_valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'a'..=b'p'))
}

/// Validates `id` and formats its Chrome Native Messaging origin string.
pub fn chrome_extension_origin(id: &str) -> Result<String> {
    if !is_valid_extension_id(id) {
        bail!(
            "invalid Chrome extension ID '{id}': expected 32 lowercase characters in 'a'..='p'"
        );
    }
    Ok(format!("chrome-extension://{id}/"))
}

/// Derives Chrome's 32-character extension ID (`[a-p]{32}`) from an X.509 SPKI DER public key.
#[cfg_attr(not(test), allow(dead_code))]
pub fn derive_extension_id_from_der(spki_der: &[u8]) -> Result<String> {
    if spki_der.is_empty() {
        bail!("SPKI DER public key must not be empty");
    }
    let digest = sha256(spki_der);
    let mut out = String::with_capacity(32);
    for &byte in &digest[..16] {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out.push((b'a' + hi) as char);
        out.push((b'a' + lo) as char);
    }
    Ok(out)
}

/// Decodes a Base64-encoded SPKI DER public key (as stored in `manifest.json` `"key"`) and derives
/// the corresponding Chrome extension ID.
#[cfg_attr(not(test), allow(dead_code))]
pub fn derive_extension_id_from_base64_key(key_b64: &str) -> Result<String> {
    let der = decode_base64(key_b64)?;
    derive_extension_id_from_der(&der)
}

/// Computes a FIPS 180-4 SHA-256 digest without external crate dependencies.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 9).div_ceil(64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in w[..16].iter_mut().enumerate() {
            let off = i * 4;
            *word = u32::from_be_bytes([
                block[off],
                block[off + 1],
                block[off + 2],
                block[off + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Decodes standard Base64 (RFC 4648, ignoring ASCII whitespace) without external crates.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() {
        bail!("Base64 input is empty");
    }
    if !clean.len().is_multiple_of(4) {
        bail!("invalid Base64 length {}: must be a multiple of 4", clean.len());
    }

    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    let (quartets, _) = clean.as_chunks::<4>();
    let num_chunks = quartets.len();
    for (chunk_idx, chunk) in quartets.iter().enumerate() {
        let is_last = chunk_idx + 1 == num_chunks;
        let a = decode_b64_char(chunk[0])?;
        let b = decode_b64_char(chunk[1])?;

        match (chunk[2], chunk[3]) {
            (b'=', b'=') => {
                if !is_last {
                    bail!("unexpected Base64 padding '=' before final quartet");
                }
                out.push((a << 2) | (b >> 4));
            }
            (c3, b'=') => {
                if !is_last {
                    bail!("unexpected Base64 padding '=' before final quartet");
                }
                let c = decode_b64_char(c3)?;
                out.push((a << 2) | (b >> 4));
                out.push(((b & 0x0f) << 4) | (c >> 2));
            }
            (b'=', _) => {
                bail!("invalid Base64 padding in third quartet byte");
            }
            (c3, c4) => {
                let c = decode_b64_char(c3)?;
                let d = decode_b64_char(c4)?;
                out.push((a << 2) | (b >> 4));
                out.push(((b & 0x0f) << 4) | (c >> 2));
                out.push(((c & 0x03) << 6) | d);
            }
        }
    }
    Ok(out)
}

#[cfg_attr(not(test), allow(dead_code))]
fn decode_b64_char(ch: u8) -> Result<u8> {
    match ch {
        b'A'..=b'Z' => Ok(ch - b'A'),
        b'a'..=b'z' => Ok(ch - b'a' + 26),
        b'0'..=b'9' => Ok(ch - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        other => bail!("invalid Base64 byte 0x{other:02X}"),
    }
}
