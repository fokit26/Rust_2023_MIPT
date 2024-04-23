#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use anyhow::{ensure, Result};

use crate::gzip::{CompressionMethod, MemberReader};

mod bit_reader;
mod deflate;
mod gzip;
mod huffman_coding;
mod tracking_writer;

pub fn decompress<R: BufRead, W: Write>(mut input: R, mut output: W) -> Result<()> {
    while !input.fill_buf()?.is_empty() {
        let member_reader = MemberReader::new(input);
        let (header, mut deflate_reader) = member_reader.into_deflate_reader()?;
        ensure!(
            header.compression_method == CompressionMethod::Deflate,
            "unsupported compression method"
        );
        while let Some(block) = deflate_reader.next_block() {
            let block = block?;
            output.write_all(&block)?;
        }
        let (reader, writer) = deflate_reader.into_inners();
        input = reader;
        let footer = MemberReader::read_footer(&mut input)?;
        ensure!(
            writer.byte_count() == footer.data_size as usize,
            "length check failed"
        );
        ensure!(writer.crc32() == footer.data_crc32, "crc32 check failed");
    }
    Ok(())
}
