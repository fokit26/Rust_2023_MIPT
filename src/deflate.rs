#![forbid(unsafe_code)]

use std::iter::repeat;
use std::{convert::TryFrom, io::BufRead, mem};

use anyhow::{bail, ensure, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::bit_reader::BitReader;
use crate::huffman_coding::{
    decode_litlen_distance_trees, DistanceToken, HuffmanCoding, LitLenToken,
};
use crate::tracking_writer::TrackingWriter;

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct BlockHeader {
    pub is_final: bool,
    pub compression_type: CompressionType,
}

#[derive(Debug)]
pub enum CompressionType {
    Uncompressed = 0,
    FixedTree = 1,
    DynamicTree = 2,
    Reserved = 3,
}

impl TryFrom<u16> for CompressionType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => CompressionType::Uncompressed,
            1 => CompressionType::FixedTree,
            2 => CompressionType::DynamicTree,
            3 => CompressionType::Reserved,
            _ => bail!("Invalid compression type!"),
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

pub struct DeflateReader<T> {
    bit_reader: BitReader<T>,
    tracker: TrackingWriter<Vec<u8>>,
    is_avail: bool,
}

impl<T: BufRead> DeflateReader<T> {
    pub fn new(bit_reader: BitReader<T>) -> Self {
        Self {
            bit_reader,
            tracker: TrackingWriter::new(Vec::new()),
            is_avail: true,
        }
    }

    pub fn next_block(&mut self) -> Option<Result<Vec<u8>>> {
        if self.is_avail {
            Some(self.read_block())
        } else {
            None
        }
    }

    fn read_block(&mut self) -> Result<Vec<u8>> {
        self.is_avail = self.bit_reader.read_bits(1)?.bits() == 0;
        let compression_type: CompressionType = self.bit_reader.read_bits(2)?.bits().try_into()?;
        match compression_type {
            CompressionType::Uncompressed => {
                let rdr = self.bit_reader.borrow_reader_from_boundary();
                let len = rdr.read_u16::<LittleEndian>()?;
                let not_len = rdr.read_u16::<LittleEndian>()?;
                ensure!(len == !not_len, "nlen check failed");
                for _i in 0..len {
                    self.tracker.write_u8(rdr.read_u8()?)?;
                }
            }
            CompressionType::FixedTree => {
                let litlen_lengths: Vec<u8> = repeat(8).take(144)
                    .chain(repeat(9).take(112))
                    .chain(repeat(7).take(24))
                    .chain(repeat(8).take(8))
                    .collect();
                let distance_lengts: Vec<u8> = repeat(5).take(32).collect();
                let litlen_coding = HuffmanCoding::<LitLenToken>::from_lengths(&litlen_lengths)?;
                let distance_coding =
                    HuffmanCoding::<DistanceToken>::from_lengths(&distance_lengts)?;

                loop {
                    let token = litlen_coding.read_symbol(&mut self.bit_reader)?;
                    match token {
                        LitLenToken::EndOfBlock => {
                            break;
                        }
                        LitLenToken::Literal(byte) => {
                            self.tracker.write_u8(byte)?;
                        }
                        LitLenToken::Length {
                            base: length_base,
                            extra_bits: length_extra_bits,
                        } => {
                            let length_extra_bits =
                                self.bit_reader.read_bits(length_extra_bits)?.bits();
                            let distance_token =
                                distance_coding.read_symbol(&mut self.bit_reader)?;
                            let distance_base = distance_token.base;
                            let distance_extra_bits =
                                self.bit_reader.read_bits(distance_token.extra_bits)?.bits();
                            let length = match length_base {
                                257..=264 => length_base - 254,
                                265..=268 => 11 + (length_base - 265) * 2,
                                269..=272 => 19 + (length_base - 269) * 4,
                                273..=276 => 35 + (length_base - 273) * 8,
                                277..=280 => 67 + (length_base - 277) * 16,
                                281..=284 => 131 + (length_base - 281) * 32,
                                285 => 258,
                                _ => bail!("invalid length base!"),
                            } + length_extra_bits;
                            let distance = match distance_base {
                                0..=3 => distance_base + 1,
                                4..=5 => 5 + (distance_base - 4) * 2,
                                6..=7 => 9 + (distance_base - 6) * 4,
                                8..=9 => 17 + (distance_base - 8) * 8,
                                10..=11 => 33 + (distance_base - 10) * 16,
                                12..=13 => 65 + (distance_base - 12) * 32,
                                14..=15 => 129 + (distance_base - 14) * 64,
                                16..=17 => 257 + (distance_base - 16) * 128,
                                18..=19 => 513 + (distance_base - 18) * 256,
                                20..=21 => 1025 + (distance_base - 20) * 512,
                                22..=23 => 2049 + (distance_base - 22) * 1024,
                                24..=25 => 4097 + (distance_base - 24) * 2048,
                                26..=27 => 8193 + (distance_base - 26) * 4096,
                                28..=29 => 16385 + (distance_base - 28) * 8192,
                                _ => bail!("invalid distance base!"),
                            } + distance_extra_bits;
                            self.tracker
                                .write_previous(distance as usize, length as usize)?;
                        }
                    }
                }
            }
            CompressionType::DynamicTree => {
                let (litlen_coding, distance_coding) =
                    decode_litlen_distance_trees(&mut self.bit_reader)?;
                loop {
                    let token = litlen_coding.read_symbol(&mut self.bit_reader)?;
                    match token {
                        LitLenToken::EndOfBlock => {
                            break;
                        }
                        LitLenToken::Literal(byte) => {
                            self.tracker.write_u8(byte)?;
                        }
                        LitLenToken::Length {
                            base: length_base,
                            extra_bits: length_extra_bits,
                        } => {
                            let length_extra_bits =
                                self.bit_reader.read_bits(length_extra_bits)?.bits();
                            let distance_token =
                                distance_coding.read_symbol(&mut self.bit_reader)?;
                            let distance_base = distance_token.base;
                            let distance_extra_bits =
                                self.bit_reader.read_bits(distance_token.extra_bits)?.bits();
                            let length = match length_base {
                                257..=264 => length_base - 254,
                                265..=268 => 11 + (length_base - 265) * 2,
                                269..=272 => 19 + (length_base - 269) * 4,
                                273..=276 => 35 + (length_base - 273) * 8,
                                277..=280 => 67 + (length_base - 277) * 16,
                                281..=284 => 131 + (length_base - 281) * 32,
                                285 => 258,
                                _ => bail!("invalid length base!"),
                            } + length_extra_bits;
                            let distance = match distance_base {
                                0..=3 => distance_base + 1,
                                4..=5 => 5 + (distance_base - 4) * 2,
                                6..=7 => 9 + (distance_base - 6) * 4,
                                8..=9 => 17 + (distance_base - 8) * 8,
                                10..=11 => 33 + (distance_base - 10) * 16,
                                12..=13 => 65 + (distance_base - 12) * 32,
                                14..=15 => 129 + (distance_base - 14) * 64,
                                16..=17 => 257 + (distance_base - 16) * 128,
                                18..=19 => 513 + (distance_base - 18) * 256,
                                20..=21 => 1025 + (distance_base - 20) * 512,
                                22..=23 => 2049 + (distance_base - 22) * 1024,
                                24..=25 => 4097 + (distance_base - 24) * 2048,
                                26..=27 => 8193 + (distance_base - 26) * 4096,
                                28..=29 => 16385 + (distance_base - 28) * 8192,
                                _ => bail!("invalid distance base!"),
                            } + distance_extra_bits;
                            self.tracker
                                .write_previous(distance as usize, length as usize)?;
                        }
                    }
                }
            }
            CompressionType::Reserved => {
                bail!("unsupported block type")
            }
        }

        Ok(mem::take(self.tracker.get_mut_ref_inner()))
    }

    pub fn into_inners(self) -> (T, TrackingWriter<Vec<u8>>) {
        (self.bit_reader.into_inner(), self.tracker)
    }
}

// TODO: your code goes here.
