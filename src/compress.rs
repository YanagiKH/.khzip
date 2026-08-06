use crate::model::{Codec, CompressionMode, CustomCompression};
use anyhow::{Context, Result};
use std::io::{Cursor, Read, Write};
use xz2::{read::XzDecoder, write::XzEncoder};

pub fn choose_codec(data: &[u8], mode: CompressionMode) -> Codec {
    match mode {
        CompressionMode::Fast => Codec::Zstd,
        CompressionMode::Balanced | CompressionMode::Custom => {
            if looks_like_text(data) {
                Codec::Brotli
            } else {
                Codec::Zstd
            }
        }
        CompressionMode::Extreme => {
            if looks_like_text(data) {
                Codec::Brotli
            } else {
                Codec::Lzma2
            }
        }
    }
}

pub fn compress(
    data: &[u8],
    codec: Codec,
    mode: CompressionMode,
    custom: &CustomCompression,
) -> Result<Vec<u8>> {
    let output = match codec {
        Codec::None => data.to_vec(),
        Codec::Zstd => {
            let level = match mode {
                CompressionMode::Fast => 1,
                CompressionMode::Balanced => 6,
                CompressionMode::Extreme => 19,
                CompressionMode::Custom => custom.zstd_level,
            };
            zstd::stream::encode_all(Cursor::new(data), level).context("zstd compression failed")?
        }
        Codec::Brotli => {
            let quality = match mode {
                CompressionMode::Fast => 3,
                CompressionMode::Balanced => 6,
                CompressionMode::Extreme => 11,
                CompressionMode::Custom => custom.brotli_quality.min(11),
            };
            let mut output = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut output, 64 * 1024, quality, 22);
                writer
                    .write_all(data)
                    .context("brotli compression failed")?;
            }
            output
        }
        Codec::Lzma2 => {
            let level = match mode {
                CompressionMode::Fast => 1,
                CompressionMode::Balanced => 6,
                CompressionMode::Extreme => 9,
                CompressionMode::Custom => custom.lzma_level.min(9),
            };
            let mut encoder = XzEncoder::new(Vec::new(), level);
            encoder
                .write_all(data)
                .context("LZMA2 compression failed")?;
            encoder.finish().context("LZMA2 finalization failed")?
        }
    };

    if output.len() + 32 >= data.len() {
        Ok(data.to_vec())
    } else {
        Ok(output)
    }
}

pub fn decompress(data: &[u8], codec: Codec, expected_len: usize) -> Result<Vec<u8>> {
    let output = match codec {
        Codec::None => data.to_vec(),
        Codec::Zstd => {
            zstd::stream::decode_all(Cursor::new(data)).context("zstd decompression failed")?
        }
        Codec::Brotli => {
            let mut decoder = brotli::Decompressor::new(Cursor::new(data), 64 * 1024);
            let mut output = Vec::with_capacity(expected_len);
            decoder
                .read_to_end(&mut output)
                .context("brotli decompression failed")?;
            output
        }
        Codec::Lzma2 => {
            let mut decoder = XzDecoder::new(Cursor::new(data));
            let mut output = Vec::with_capacity(expected_len);
            decoder
                .read_to_end(&mut output)
                .context("LZMA2 decompression failed")?;
            output
        }
    };
    anyhow::ensure!(output.len() == expected_len, "decompressed length mismatch");
    Ok(output)
}

pub fn looks_like_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = &data[..data.len().min(32 * 1024)];
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    let total = text.chars().count().max(1);
    printable * 100 / total >= 95
}
