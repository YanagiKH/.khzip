use anyhow::{ensure, Result};
use std::io::Read;

#[derive(Debug, Clone, Copy)]
pub struct ChunkConfig {
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

impl ChunkConfig {
    pub fn validate(self) -> Result<Self> {
        ensure!(
            self.min >= 64 * 1024,
            "minimum chunk size must be at least 64 KiB"
        );
        ensure!(
            self.min < self.avg,
            "minimum chunk size must be smaller than average"
        );
        ensure!(
            self.avg < self.max,
            "average chunk size must be smaller than maximum"
        );
        ensure!(
            self.max <= 64 * 1024 * 1024,
            "maximum chunk size must not exceed 64 MiB"
        );
        Ok(self)
    }
}

pub fn stream_chunks<R, F>(reader: &mut R, config: ChunkConfig, mut consume: F) -> Result<()>
where
    R: Read,
    F: FnMut(&[u8]) -> Result<()>,
{
    let config = config.validate()?;
    let mut buffer = Vec::with_capacity(config.max + 64 * 1024);
    let mut scratch = vec![0_u8; 64 * 1024];
    let mut eof = false;

    loop {
        while !eof && buffer.len() < config.max {
            let read = reader.read(&mut scratch)?;
            if read == 0 {
                eof = true;
            } else {
                buffer.extend_from_slice(&scratch[..read]);
            }
        }

        if buffer.is_empty() {
            break;
        }

        let cut = cut_point(&buffer, config, eof);
        consume(&buffer[..cut])?;
        buffer.drain(..cut);
    }
    Ok(())
}

fn cut_point(data: &[u8], config: ChunkConfig, eof: bool) -> usize {
    if data.len() <= config.min {
        return data.len();
    }

    let scan_limit = data.len().min(config.max);
    let normal = config.avg.min(scan_limit);
    let bits = config
        .avg
        .next_power_of_two()
        .trailing_zeros()
        .clamp(8, 30);
    let strict_mask = (1_u64 << (bits + 1).min(62)) - 1;
    let loose_mask = (1_u64 << bits.saturating_sub(1).max(1)) - 1;
    let table = gear_table();
    let mut hash = 0_u64;

    for index in config.min..normal {
        hash = hash
            .rotate_left(1)
            .wrapping_add(table[data[index] as usize]);
        if hash & strict_mask == 0 {
            return index + 1;
        }
    }
    for index in normal..scan_limit {
        hash = hash
            .rotate_left(1)
            .wrapping_add(table[data[index] as usize]);
        if hash & loose_mask == 0 {
            return index + 1;
        }
    }

    if eof {
        scan_limit
    } else {
        config.max
    }
}

fn gear_table() -> [u64; 256] {
    let mut table = [0_u64; 256];
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    for value in &mut table {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *value = z ^ (z >> 31);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn preserves_all_input_bytes() {
        let data = vec![42_u8; 3 * 1024 * 1024 + 17];
        let mut rebuilt = Vec::new();
        stream_chunks(
            &mut Cursor::new(&data),
            ChunkConfig {
                min: 64 * 1024,
                avg: 256 * 1024,
                max: 1024 * 1024,
            },
            |chunk| {
                rebuilt.extend_from_slice(chunk);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(data, rebuilt);
    }
}
