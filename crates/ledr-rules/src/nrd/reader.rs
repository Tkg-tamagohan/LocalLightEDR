//! Bounded, cooperatively cancellable file and stream readers for NRD feeds.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::cancel::NrdCancelToken;

pub(crate) const NRD_FILE_READ_CHUNK_BYTES: usize = 64 * 1024;
const NRD_DOWNLOAD_CANCELLED_ERR: &str = "NRD feed download cancelled";
const NRD_FEED_READ_ERR_PREFIX: &str = "failed to read NRD feed: ";

/// Reads a bounded local NRD feed file in 64 KiB chunks while cooperatively checking `cancel`
/// before and after every chunk read.
pub(crate) fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    cancel: &NrdCancelToken,
) -> Result<(Vec<u8>, bool), String> {
    if cancel.is_cancelled() {
        return Err(NRD_DOWNLOAD_CANCELLED_ERR.to_string());
    }
    let file = File::open(path).map_err(|err| {
        if cancel.is_cancelled() {
            NRD_DOWNLOAD_CANCELLED_ERR.to_string()
        } else {
            format!("failed to open NRD feed file `{}`: {err}", path.display())
        }
    })?;
    read_bounded_reader_cancellable(file, max_bytes, cancel).map_err(|err| {
        if err == NRD_DOWNLOAD_CANCELLED_ERR {
            err
        } else if let Some(detail) = err.strip_prefix(NRD_FEED_READ_ERR_PREFIX) {
            format!("failed to read NRD feed file `{}`: {detail}", path.display())
        } else {
            format!("failed to read NRD feed file `{}`: {err}", path.display())
        }
    })
}

/// Reads from `reader` in bounded 64 KiB chunks up to `max_bytes`, checking `cancel` before and
/// after each `read()` call (and before retrying `ErrorKind::Interrupted`). When input exceeds
/// `max_bytes`, trims any partial trailing line via [`trim_partial_trailing_line`].
pub(crate) fn read_bounded_reader_cancellable<R: Read>(
    mut reader: R,
    max_bytes: usize,
    cancel: &NrdCancelToken,
) -> Result<(Vec<u8>, bool), String> {
    if cancel.is_cancelled() {
        return Err(NRD_DOWNLOAD_CANCELLED_ERR.to_string());
    }

    let cap = max_bytes.max(1);
    let chunk_cap = NRD_FILE_READ_CHUNK_BYTES.min(cap.saturating_add(1));
    let mut chunk = vec![0u8; chunk_cap];
    let mut body = Vec::new();
    let mut truncated = false;

    loop {
        let remaining_budget = cap.saturating_sub(body.len());
        let want = if remaining_budget == 0 {
            1
        } else {
            remaining_budget.saturating_add(1).min(chunk.len())
        };

        if cancel.is_cancelled() {
            return Err(NRD_DOWNLOAD_CANCELLED_ERR.to_string());
        }

        let read_result = {
            let _read_guard = cancel.enter_blocking_read();
            reader.read(&mut chunk[..want])
        };

        let n = match read_result {
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                if cancel.is_cancelled() {
                    return Err(NRD_DOWNLOAD_CANCELLED_ERR.to_string());
                }
                continue;
            }
            Err(err) => {
                if cancel.is_cancelled() {
                    return Err(NRD_DOWNLOAD_CANCELLED_ERR.to_string());
                }
                return Err(format!("{NRD_FEED_READ_ERR_PREFIX}{err}"));
            }
        };

        if cancel.is_cancelled() {
            return Err(NRD_DOWNLOAD_CANCELLED_ERR.to_string());
        }

        if n == 0 {
            break;
        }
        if remaining_budget == 0 {
            trim_partial_trailing_line(&mut body);
            truncated = true;
            break;
        }
        if n > remaining_budget {
            body.extend_from_slice(&chunk[..remaining_budget]);
            trim_partial_trailing_line(&mut body);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    Ok((body, truncated))
}

fn trim_partial_trailing_line(buf: &mut Vec<u8>) {
    if let Some(pos) = buf.iter().rposition(|&b| b == b'\n') {
        buf.truncate(pos + 1);
    } else {
        // The entire truncated buffer is an incomplete single line; discard it so parsers
        // never ingest a corrupted half-domain.
        buf.clear();
    }
}

/// Reads chunks from a streaming source via `next_chunk(max_to_read)` until EOF (`Ok(None)`) or
/// `max_bytes` is exceeded. When truncated, trims any partial trailing line (clearing the buffer
/// if no newline was seen) so NRD parsers never ingest a half-domain.
#[cfg(test)]
pub(crate) fn read_bounded_chunks<F>(
    max_bytes: usize,
    next_chunk: F,
) -> Result<(Vec<u8>, bool), String>
where
    F: FnMut(usize) -> Result<Option<Vec<u8>>, String>,
{
    read_bounded_chunks_cancellable(max_bytes, &NrdCancelToken::new(), next_chunk)
}

/// Cancellable variant of [`read_bounded_chunks`].
pub(crate) fn read_bounded_chunks_cancellable<F>(
    max_bytes: usize,
    cancel: &NrdCancelToken,
    mut next_chunk: F,
) -> Result<(Vec<u8>, bool), String>
where
    F: FnMut(usize) -> Result<Option<Vec<u8>>, String>,
{
    let cap = max_bytes.max(1);
    let mut body = Vec::new();
    let mut truncated = false;

    loop {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        let remaining_budget = cap.saturating_sub(body.len());
        let want = if remaining_budget == 0 {
            1
        } else {
            remaining_budget.saturating_add(1).min(16_384)
        };
        let Some(chunk) = next_chunk(want)? else {
            break;
        };
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        if chunk.is_empty() {
            break;
        }
        if remaining_budget == 0 {
            trim_partial_trailing_line(&mut body);
            truncated = true;
            break;
        }
        if body.len().saturating_add(chunk.len()) > cap {
            let take = cap.saturating_sub(body.len());
            body.extend_from_slice(&chunk[..take]);
            trim_partial_trailing_line(&mut body);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok((body, truncated))
}
