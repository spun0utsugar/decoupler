use crate::ir::{ByteSpan, DecompressedStreamInfo};
use crate::scoring::shannon_entropy;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Hard cap on any single decompressed buffer (64 MB).
pub const MAX_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;
/// Maximum allowed expansion ratio (`decompressed_len / compressed_len <= 200.0`).
pub const MAX_EXPANSION_RATIO: f64 = 200.0;

/// Configuration for the Bounded Recursive Stream Carver & Decompressor.
#[derive(Debug, Clone)]
pub struct CarverConfig {
    /// Minimum Shannon entropy to trigger raw Deflate carving (default: `7.20`, aggressive: `6.80`).
    pub deflate_entropy_threshold: f64,
    /// Minimum contiguous high-entropy byte run length required (default: `64`).
    pub min_high_entropy_run: usize,
    /// Maximum recursion depth for nested compressed streams (default: `3`, aggressive: `5`).
    pub max_recursion_depth: usize,
    /// Sliding window coarse step size in bytes for high-entropy raw Deflate probing (default: `32`, aggressive: `16`).
    pub scan_step: usize,
    /// Enable forensic aggressive mode (also accepts valid CMF/FLG modulo-31 `0x78` zlib headers beyond the 4 standard ones).
    pub aggressive: bool,
    /// Log diagnostic messages for unpacked and discarded candidate streams.
    pub verbose: bool,
}

impl Default for CarverConfig {
    fn default() -> Self {
        Self {
            deflate_entropy_threshold: 7.20,
            min_high_entropy_run: 64,
            max_recursion_depth: 3,
            scan_step: 32,
            aggressive: false,
            verbose: false,
        }
    }
}

impl CarverConfig {
    pub fn with_aggressive(mut self) -> Self {
        self.deflate_entropy_threshold = 6.80;
        self.max_recursion_depth = 5;
        self.scan_step = 16;
        self.aggressive = true;
        self
    }
}

/// Represents an unpacked in-memory child buffer ready for structural scanning.
#[derive(Debug, Clone)]
pub struct CarvedStream {
    pub info: DecompressedStreamInfo,
    pub host_root_span: ByteSpan,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionCodec {
    Zlib,
    Gzip,
    RawDeflate,
}

impl CompressionCodec {
    fn as_str(&self) -> &'static str {
        match self {
            CompressionCodec::Zlib => "ZLIB_RFC1950",
            CompressionCodec::Gzip => "GZIP_RFC1952",
            CompressionCodec::RawDeflate => "RAW_DEFLATE",
        }
    }

    fn short_tag(&self) -> &'static str {
        match self {
            CompressionCodec::Zlib => "zlib",
            CompressionCodec::Gzip => "gzip",
            CompressionCodec::RawDeflate => "raw",
        }
    }
}

/// Distinguishes between an invalid compressed stream vs. a stream whose header/blocks
/// decoded but failed final Adler-32 / CRC-32 checksum verification.
#[derive(Debug, Clone)]
pub enum DecompressError {
    ChecksumMismatch(String),
    InvalidStream(String),
    SizeCapExceeded(String),
}

impl DecompressError {
    pub fn category(&self) -> &'static str {
        match self {
            DecompressError::ChecksumMismatch(_) => "HEADER_OK_CHECKSUM_MISMATCH",
            DecompressError::InvalidStream(_) => "INVALID_COMPRESSED_STREAM",
            DecompressError::SizeCapExceeded(_) => "DECOMPRESSION_BOMB_CAP_EXCEEDED",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            DecompressError::ChecksumMismatch(s)
            | DecompressError::InvalidStream(s)
            | DecompressError::SizeCapExceeded(s) => s,
        }
    }
}

/// Check if `(b0, b1)` is a valid RFC 1950 zlib header:
/// - Standard common pairs: `0x78 0x01` (no/low), `0x78 0x5E` (fast/level 2-5),
///   `0x78 0x9C` (default/level 6), `0x78 0xDA` (best/level 9).
/// - In aggressive mode, also accepts any `0x78` (32K window Deflate, CM=8, CINFO=7)
///   where `((0x78 << 8) | b1) % 31 == 0` and preset dictionary bit `FDICT` (bit 5) is 0.
#[inline]
pub fn is_zlib_header(b0: u8, b1: u8, aggressive: bool) -> bool {
    if b0 != 0x78 {
        return false;
    }
    if b1 == 0x01 || b1 == 0x5E || b1 == 0x9C || b1 == 0xDA {
        return true;
    }
    if aggressive {
        let fdict = (b1 & 0x20) != 0;
        let fcheck_ok = ((b0 as u16) * 256 + (b1 as u16)) % 31 == 0;
        return !fdict && fcheck_ok;
    }
    false
}

/// Recursively carves and decompresses `zlib` (RFC 1950), `gzip` (RFC 1952), and length-prefixed
/// `raw Deflate` chunks up to `cfg.max_recursion_depth` while enforcing 64 MB and 200:1 bomb limits.
pub fn carve_compressed_streams(
    root_data: &[u8],
    cfg: &CarverConfig,
) -> (Vec<CarvedStream>, Vec<(usize, usize)>) {
    let mut carved_streams = Vec::new();
    let mut root_claimed_spans = Vec::new();

    carve_recursive(
        root_data,
        "root",
        1,
        None,
        cfg,
        &mut carved_streams,
        &mut root_claimed_spans,
    );

    (carved_streams, root_claimed_spans)
}

fn carve_recursive(
    buf: &[u8],
    parent_lineage: &str,
    depth: usize,
    root_span_override: Option<ByteSpan>,
    cfg: &CarverConfig,
    out_streams: &mut Vec<CarvedStream>,
    root_claimed_spans: &mut Vec<(usize, usize)>,
) {
    if depth > cfg.max_recursion_depth || buf.len() < 10 {
        return;
    }

    let n = buf.len();
    let mut local_index = 0usize;
    let mut consumed_intervals: Vec<(usize, usize)> = Vec::new();

    let is_consumed = |off: usize, intervals: &[(usize, usize)]| -> bool {
        intervals.iter().any(|&(s, e)| off >= s && off < e)
    };

    // Pass 1: Fast sliding-window / coarse-step scan + magic byte scan (`0x78` for zlib, `0x1F 0x8B` for gzip),
    // and coarse-step (`cfg.scan_step`) high-entropy window refinement for length-prefixed Raw Deflate.
    let mut i = 0usize;
    let step = cfg.scan_step.max(4);

    while i + 8 <= n {
        if is_consumed(i, &consumed_intervals) {
            i += 1;
            continue;
        }

        let b0 = buf[i];
        let b1 = buf[i + 1];

        // A. Check zlib headers (0x78 0x01, 0x78 0x5E, 0x78 0x9C, 0x78 0xDA, plus modulo-31 in aggressive mode)
        if is_zlib_header(b0, b1, cfg.aggressive) {
            if let Some(end_off) = attempt_magic_stream(
                buf,
                i,
                CompressionCodec::Zlib,
                parent_lineage,
                depth,
                &mut local_index,
                root_span_override,
                cfg,
                out_streams,
                root_claimed_spans,
                &mut consumed_intervals,
            ) {
                i = end_off;
                continue;
            }
        }
        // B. Check gzip header (0x1F 0x8B 0x08 [flags <= 0x1F])
        else if b0 == 0x1F && b1 == 0x8B && i + 10 <= n && buf[i + 2] == 0x08 && buf[i + 3] <= 0x1F {
            if let Some(end_off) = attempt_magic_stream(
                buf,
                i,
                CompressionCodec::Gzip,
                parent_lineage,
                depth,
                &mut local_index,
                root_span_override,
                cfg,
                out_streams,
                root_claimed_spans,
                &mut consumed_intervals,
            ) {
                i = end_off;
                continue;
            }
        }
        // C. Coarse-step high-entropy window check for length-prefixed Raw Deflate:
        // Only evaluate Shannon entropy at multiples of `step` (or 4-byte aligned boundaries right after a consumed stream).
        let last_end = consumed_intervals.last().map(|&(_, e)| e).unwrap_or(0);
        let should_probe = (i % step == 0)
            || (i == ((last_end + 3) & !3))
            || (i == ((last_end + 7) & !3));
        if i >= 4 && i + cfg.min_high_entropy_run <= n && should_probe {
            let win_end = (i + 512).min(n);
            let win_ent = shannon_entropy(&buf[i..win_end]);
            if win_ent >= cfg.deflate_entropy_threshold {
                // Refine locally around this high-entropy window
                let refine_start = i.saturating_sub(step).max(4);
                let refine_end = (i + step).min(n.saturating_sub(cfg.min_high_entropy_run));
                let mut r_off = refine_start;
                let mut unpacked_end = None;

                while r_off <= refine_end {
                    if !is_consumed(r_off, &consumed_intervals) && !is_consumed(r_off - 4, &consumed_intervals) {
                        if let Some(end_off) = attempt_raw_deflate_with_length_prefix(
                            buf,
                            r_off,
                            parent_lineage,
                            depth,
                            &mut local_index,
                            root_span_override,
                            cfg,
                            out_streams,
                            root_claimed_spans,
                            &mut consumed_intervals,
                        ) {
                            unpacked_end = Some(end_off);
                            break;
                        }
                    }
                    r_off += 1;
                }

                if let Some(end_off) = unpacked_end {
                    i = end_off;
                    continue;
                }
            }
        }

        i += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn attempt_magic_stream(
    buf: &[u8],
    stream_off: usize,
    codec: CompressionCodec,
    parent_lineage: &str,
    depth: usize,
    local_index: &mut usize,
    root_span_override: Option<ByteSpan>,
    cfg: &CarverConfig,
    out_streams: &mut Vec<CarvedStream>,
    root_claimed_spans: &mut Vec<(usize, usize)>,
    consumed_intervals: &mut Vec<(usize, usize)>,
) -> Option<usize> {
    let comp_slice = &buf[stream_off..];
    match try_bounded_decompress(comp_slice, codec) {
        Ok((decomp_bytes, consumed_len)) if decomp_bytes.len() >= 16 => {
            let actual_comp_len = consumed_len.max(1);
            let ratio = (decomp_bytes.len() as f64) / (actual_comp_len as f64);

            if ratio > MAX_EXPANSION_RATIO {
                if cfg.verbose {
                    eprintln!(
                        "[carver-warn] Aborted {} stream at {:#x} (lineage={}): expansion ratio {:.1}:1 exceeds {:.0}:1 limit",
                        codec.as_str(),
                        stream_off,
                        parent_lineage,
                        ratio,
                        MAX_EXPANSION_RATIO
                    );
                }
                return None;
            }

            let end_off = stream_off + actual_comp_len;
            consumed_intervals.push((stream_off, end_off));
            register_carved_child(
                decomp_bytes,
                codec,
                stream_off,
                actual_comp_len,
                stream_off,
                actual_comp_len,
                parent_lineage,
                depth,
                local_index,
                root_span_override,
                cfg,
                out_streams,
                root_claimed_spans,
            );
            Some(end_off)
        }
        Ok(_) => None,
        Err(err) => {
            if cfg.verbose {
                eprintln!(
                    "[carver-debug] Discarded candidate {} at {:#x} (lineage={}, reason={}): {}",
                    codec.as_str(),
                    stream_off,
                    parent_lineage,
                    err.category(),
                    err.message()
                );
            }
            None
        }
    }
}

/// Evaluates a candidate raw Deflate stream at `stream_off` preceded by a 4-byte integer at `stream_off - 4`.
/// Tries both Little-Endian and Big-Endian interpretations of the 4-byte prefix:
///   1. Prefix as compressed byte length OR expected decompressed byte length.
///   2. Requires that the resulting decompressed length or consumed compressed length matches the
///      4-byte prefix within 20% (or exact match), and prefers the endianness with the tighter match.
#[allow(clippy::too_many_arguments)]
fn attempt_raw_deflate_with_length_prefix(
    buf: &[u8],
    stream_off: usize,
    parent_lineage: &str,
    depth: usize,
    local_index: &mut usize,
    root_span_override: Option<ByteSpan>,
    cfg: &CarverConfig,
    out_streams: &mut Vec<CarvedStream>,
    root_claimed_spans: &mut Vec<(usize, usize)>,
    consumed_intervals: &mut Vec<(usize, usize)>,
) -> Option<usize> {
    if stream_off < 4 || stream_off + cfg.min_high_entropy_run > buf.len() {
        return None;
    }

    let rem = buf.len() - stream_off;
    let val_le = LittleEndian::read_u32(&buf[stream_off - 4..stream_off]) as usize;
    let val_be = BigEndian::read_u32(&buf[stream_off - 4..stream_off]) as usize;

    // Check that either LE or BE length is plausible (16 bytes ..= 64 MB)
    let le_plausible = (16..=MAX_DECOMPRESSED_BYTES).contains(&val_le);
    let be_plausible = (16..=MAX_DECOMPRESSED_BYTES).contains(&val_be);
    if !le_plausible && !be_plausible {
        return None;
    }

    // Check high-entropy run on the compressed stream window
    let sample_len = rem.min(512).max(cfg.min_high_entropy_run);
    let ent = shannon_entropy(&buf[stream_off..stream_off + sample_len]);
    if ent < cfg.deflate_entropy_threshold {
        return None;
    }

    // Try bounded raw Deflate decompression once on the remaining slice, then validate against both LE and BE prefixes
    let max_in = rem.min(MAX_DECOMPRESSED_BYTES);
    match try_bounded_decompress(&buf[stream_off..stream_off + max_in], CompressionCodec::RawDeflate) {
        Ok((decomp_bytes, consumed_len)) if decomp_bytes.len() >= 16 => {
            let actual_comp = consumed_len.max(1);
            let actual_decomp = decomp_bytes.len();
            let ratio = (actual_decomp as f64) / (actual_comp as f64);
            if ratio > MAX_EXPANSION_RATIO {
                return None;
            }

            // Compute relative error against prefix (allowing prefix to represent either expected decompressed size OR compressed block size)
            let match_error = |prefix_val: usize| -> Option<f64> {
                if !(16..=MAX_DECOMPRESSED_BYTES).contains(&prefix_val) {
                    return None;
                }
                let err_decomp = (actual_decomp as f64 - prefix_val as f64).abs() / (prefix_val as f64);
                let err_comp = if prefix_val <= rem {
                    (actual_comp as f64 - prefix_val as f64).abs() / (prefix_val as f64)
                } else {
                    f64::INFINITY
                };
                let best_err = err_decomp.min(err_comp);
                // Must be within 20% (<= 0.20) of the 4-byte length integer
                if best_err <= 0.20 {
                    Some(best_err)
                } else {
                    None
                }
            };

            let err_le = match_error(val_le);
            let err_be = match_error(val_be);

            let best_match = match (err_le, err_be) {
                (Some(ele), Some(ebe)) => Some(if ele <= ebe { (val_le, "LE", ele) } else { (val_be, "BE", ebe) }),
                (Some(ele), None) => Some((val_le, "LE", ele)),
                (None, Some(ebe)) => Some((val_be, "BE", ebe)),
                (None, None) => None,
            };

            if let Some((matched_len, endian_tag, rel_err)) = best_match {
                if cfg.verbose {
                    println!(
                        "[carver] Raw Deflate at {:#x} matched 4-byte {} length prefix {} (rel_err={:.1}%)",
                        stream_off,
                        endian_tag,
                        matched_len,
                        rel_err * 100.0
                    );
                }
                let claim_start = stream_off - 4;
                let claim_len = actual_comp + 4;
                let end_off = stream_off + actual_comp;
                consumed_intervals.push((claim_start, end_off));
                register_carved_child(
                    decomp_bytes,
                    CompressionCodec::RawDeflate,
                    stream_off,
                    actual_comp,
                    claim_start,
                    claim_len,
                    parent_lineage,
                    depth,
                    local_index,
                    root_span_override,
                    cfg,
                    out_streams,
                    root_claimed_spans,
                );
                return Some(end_off);
            }
            None
        }
        Ok(_) => None,
        Err(err) => {
            if cfg.verbose {
                eprintln!(
                    "[carver-debug] Discarded candidate RAW_DEFLATE at {:#x} (lineage={}, reason={}): {}",
                    stream_off,
                    parent_lineage,
                    err.category(),
                    err.message()
                );
            }
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn register_carved_child(
    decomp_bytes: Vec<u8>,
    codec: CompressionCodec,
    stream_off: usize,
    actual_comp_len: usize,
    claim_start: usize,
    claim_len: usize,
    parent_lineage: &str,
    depth: usize,
    local_index: &mut usize,
    root_span_override: Option<ByteSpan>,
    cfg: &CarverConfig,
    out_streams: &mut Vec<CarvedStream>,
    root_claimed_spans: &mut Vec<(usize, usize)>,
) {
    let idx = *local_index;
    *local_index += 1;

    // Virtual stream identity includes parent offset, zero-based per-parent counter, and compression tag (`zlib`, `gzip`, `raw`)
    let stream_id = if parent_lineage == "root" {
        format!(
            "parent_offset:{:#x}/decompressed_{}_{}",
            stream_off,
            idx,
            codec.short_tag()
        )
    } else {
        format!(
            "{}/parent_offset:{:#x}/decompressed_{}_{}",
            parent_lineage,
            stream_off,
            idx,
            codec.short_tag()
        )
    };

    let host_span = root_span_override.unwrap_or(ByteSpan::new(claim_start, claim_len));
    if depth == 1 {
        root_claimed_spans.push((claim_start, claim_start + claim_len));
    }

    let mut hasher = Sha256::new();
    hasher.update(&decomp_bytes);
    let sha256 = hex::encode(hasher.finalize());
    let ratio = (decomp_bytes.len() as f64) / (actual_comp_len.max(1) as f64);

    let info = DecompressedStreamInfo {
        stream_id: stream_id.clone(),
        parent_lineage: parent_lineage.to_string(),
        depth,
        codec: codec.as_str().to_string(),
        host_offset: stream_off,
        compressed_length: actual_comp_len,
        decompressed_length: decomp_bytes.len(),
        expansion_ratio: (ratio * 100.0).round() / 100.0,
        sha256,
    };

    if cfg.verbose {
        println!(
            "[carver] Unpacked {} stream '{}' (depth={}, {} B -> {} B, ratio={:.2}:1)",
            info.codec,
            info.stream_id,
            info.depth,
            info.compressed_length,
            info.decompressed_length,
            info.expansion_ratio
        );
    }

    let child_buf = decomp_bytes.clone();
    out_streams.push(CarvedStream {
        info,
        host_root_span: host_span,
        data: decomp_bytes,
    });

    // Immediately feed child buffer into the recursive carver (respecting `cfg.max_recursion_depth`)
    carve_recursive(
        &child_buf,
        &stream_id,
        depth + 1,
        Some(host_span),
        cfg,
        out_streams,
        root_claimed_spans,
    );
}

/// Streaming decompression capped at `MAX_DECOMPRESSED_BYTES` (64 MB) with explicit classification
/// of checksum errors (Adler-32 / CRC-32) vs. invalid Deflate bitstreams.
fn try_bounded_decompress(
    comp_slice: &[u8],
    codec: CompressionCodec,
) -> Result<(Vec<u8>, usize), DecompressError> {
    let cap = (MAX_DECOMPRESSED_BYTES + 1) as u64;
    let mut out = Vec::new();

    let classify_io_err = |e: std::io::Error| -> DecompressError {
        let msg = e.to_string();
        let lower = msg.to_lowercase();
        if lower.contains("checksum")
            || lower.contains("crc")
            || lower.contains("adler")
            || lower.contains("corrupt gzip")
        {
            DecompressError::ChecksumMismatch(msg)
        } else {
            DecompressError::InvalidStream(msg)
        }
    };

    let consumed = match codec {
        CompressionCodec::Zlib => {
            let mut dec = ZlibDecoder::new(comp_slice);
            (&mut dec)
                .take(cap)
                .read_to_end(&mut out)
                .map_err(classify_io_err)?;
            dec.total_in() as usize
        }
        CompressionCodec::Gzip => {
            let mut dec = GzDecoder::new(comp_slice);
            (&mut dec)
                .take(cap)
                .read_to_end(&mut out)
                .map_err(classify_io_err)?;
            comp_slice.len()
        }
        CompressionCodec::RawDeflate => {
            let mut dec = DeflateDecoder::new(comp_slice);
            (&mut dec)
                .take(cap)
                .read_to_end(&mut out)
                .map_err(classify_io_err)?;
            dec.total_in() as usize
        }
    };

    if out.len() > MAX_DECOMPRESSED_BYTES {
        return Err(DecompressError::SizeCapExceeded(format!(
            "Decompressed payload exceeds 64 MB hard cap ({} bytes)",
            out.len()
        )));
    }

    Ok((out, consumed.max(1)))
}
