#![forbid(unsafe_code)]

use std::{collections::HashMap, convert::TryFrom, io::BufRead};

use anyhow::{bail, Context, Result};

use crate::bit_reader::{BitReader, BitSequence};

////////////////////////////////////////////////////////////////////////////////

pub fn decode_litlen_distance_trees<T: BufRead>(
    bit_reader: &mut BitReader<T>,
) -> Result<(HuffmanCoding<LitLenToken>, HuffmanCoding<DistanceToken>)> {
    // See RFC 1951, section 3.2.7.
    let litlen_size = bit_reader.read_bits(5)?.bits() + 257;
    let distance_size = bit_reader.read_bits(5)?.bits() + 1;
    let codelen_size = bit_reader.read_bits(4)?.bits() + 4;

    let mut code_lengths = Vec::<u8>::new();
    code_lengths.resize(19, 0);
    const MAP: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    for i in 0..codelen_size {
        code_lengths[MAP[i as usize]] = bit_reader.read_bits(3)?.bits() as u8;
    }

    let code_decoder = HuffmanCoding::<TreeCodeToken>::from_lengths(&code_lengths)?;
    let mut litlen_codes = Vec::with_capacity(litlen_size as usize);
    while litlen_codes.len() < litlen_size as usize {
        let symbol = code_decoder.read_symbol(bit_reader)?;
        match symbol {
            TreeCodeToken::Length(len) => {
                litlen_codes.push(len);
            }
            TreeCodeToken::CopyPrev => {
                let cnt = bit_reader.read_bits(2)?.bits() + 3;
                for _j in 0..cnt {
                    litlen_codes.push(
                        *litlen_codes
                            .last()
                            .context("Trying to repeat empty buffer")?,
                    );
                }
            }
            TreeCodeToken::RepeatZero {
                base,
                extra_bits: _,
            } => match base {
                17 => {
                    let cnt = bit_reader.read_bits(3)?.bits() + 3;
                    for _j in 0..cnt {
                        litlen_codes.push(0);
                    }
                }
                18 => {
                    let cnt = bit_reader.read_bits(7)?.bits() + 11;
                    for _j in 0..cnt {
                        litlen_codes.push(0);
                    }
                }
                _ => unreachable!(),
            },
        }
    }

    let code_decoder = HuffmanCoding::<TreeCodeToken>::from_lengths(&code_lengths)?;
    let mut distance_codes = Vec::with_capacity(distance_size as usize);
    while distance_codes.len() < distance_size as usize {
        let symbol = code_decoder.read_symbol(bit_reader)?;
        match symbol {
            TreeCodeToken::Length(len) => {
                distance_codes.push(len);
            }
            TreeCodeToken::CopyPrev => {
                let cnt = bit_reader.read_bits(2)?.bits() + 3;
                for _j in 0..cnt {
                    distance_codes.push(
                        *distance_codes
                            .last()
                            .context("Trying to repeat empty buffer")?,
                    );
                }
            }
            TreeCodeToken::RepeatZero { base, extra_bits } => match base {
                17 => {
                    let cnt = bit_reader.read_bits(extra_bits)?.bits() + 3;
                    for _j in 0..cnt {
                        distance_codes.push(0);
                    }
                }
                18 => {
                    let cnt = bit_reader.read_bits(extra_bits)?.bits() + 11;
                    for _j in 0..cnt {
                        distance_codes.push(0);
                    }
                }
                _ => unreachable!(),
            },
        }
    }

    Ok((
        HuffmanCoding::<LitLenToken>::from_lengths(&litlen_codes)?,
        HuffmanCoding::<DistanceToken>::from_lengths(&distance_codes)?,
    ))
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug)]
pub enum TreeCodeToken {
    Length(u8),
    CopyPrev,
    RepeatZero { base: u16, extra_bits: u8 },
}

impl TryFrom<HuffmanCodeWord> for TreeCodeToken {
    type Error = anyhow::Error;

    fn try_from(value: HuffmanCodeWord) -> Result<Self> {
        // See RFC 1951, section 3.2.7.
        if (0..=15).contains(&value.0) {
            Ok(Self::Length(value.0 as u8))
        } else if 16 == value.0 {
            Ok(Self::CopyPrev)
        } else if 17 == value.0 {
            Ok(Self::RepeatZero {
                base: value.0,
                extra_bits: 3,
            })
        } else if 18 == value.0 {
            Ok(Self::RepeatZero {
                base: value.0,
                extra_bits: 7,
            })
        } else {
            bail!("Unable to decode TreeCodeToken")
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug)]
pub enum LitLenToken {
    Literal(u8),
    EndOfBlock,
    Length { base: u16, extra_bits: u8 },
}

impl TryFrom<HuffmanCodeWord> for LitLenToken {
    type Error = anyhow::Error;

    fn try_from(value: HuffmanCodeWord) -> Result<Self> {
        // See RFC 1951, section 3.2.5.
        if (0..=255).contains(&value.0) {
            Ok(Self::Literal(value.0 as u8))
        } else if 256 == value.0 {
            Ok(Self::EndOfBlock)
        } else if (257..=285).contains(&value.0) {
            if (257..=264).contains(&value.0) || 285 == value.0 {
                Ok(Self::Length {
                    base: value.0,
                    extra_bits: 0,
                })
            } else {
                Ok(Self::Length {
                    base: value.0,
                    extra_bits: ((value.0 - 261) / 4) as u8,
                })
            }
        } else {
            bail!("Unable to decode LitLetToken")
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug)]
pub struct DistanceToken {
    pub base: u16,
    pub extra_bits: u8,
}

impl TryFrom<HuffmanCodeWord> for DistanceToken {
    type Error = anyhow::Error;

    fn try_from(value: HuffmanCodeWord) -> Result<Self> {
        // See RFC 1951, section 3.2.5.
        if (0..=3).contains(&value.0) {
            Ok(Self {
                base: value.0,
                extra_bits: 0,
            })
        } else if (4..=29).contains(&value.0) {
            Ok(Self {
                base: value.0,
                extra_bits: ((value.0 - 2) / 2) as u8,
            })
        } else {
            bail!("Unable to decode DistanceToken")
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

const MAX_BITS: usize = 15;

pub struct HuffmanCodeWord(pub u16);

pub struct HuffmanCoding<T> {
    map: HashMap<BitSequence, T>,
}

impl<T> HuffmanCoding<T>
where
    T: Copy + TryFrom<HuffmanCodeWord, Error = anyhow::Error>,
{
    #[allow(unused)]
    pub fn new(map: HashMap<BitSequence, T>) -> Self {
        Self { map }
    }

    #[allow(unused)]
    pub fn decode_symbol(&self, seq: BitSequence) -> Option<T> {
        self.map.get(&seq).copied()
    }

    pub fn read_symbol<U: BufRead>(&self, bit_reader: &mut BitReader<U>) -> Result<T> {
        let mut symbol = BitSequence::new(0, 0);
        for _i in 0..MAX_BITS {
            symbol = bit_reader.read_bits(1)?.concat(symbol);
            if let Some(val) = self.map.get(&symbol) {
                return Ok(*val);
            }
        }
        bail!("Unable to read symbol")
    }

    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self> {
        // See RFC 1951, section 3.2.2.
        let mut length_counts = Vec::new();
        length_counts.resize(
            *code_lengths
                .iter()
                .max()
                .context("Unable to find largest code length")? as usize
                + 1,
            0,
        );
        for len in code_lengths {
            length_counts[*len as usize] += 1;
        }
        length_counts[0] = 0;

        let mut code = 0_u16;
        let mut next_codes = Vec::new();
        next_codes.resize(length_counts.len(), 0);
        for i in 1..next_codes.len() {
            code = (code + length_counts[i - 1]) << 1;
            next_codes[i] = code;
        }

        let mut map = HashMap::new();
        for (i, len) in (0..).zip(code_lengths) {
            if *len != 0 {
                map.insert(
                    BitSequence::new(next_codes[*len as usize], *len),
                    HuffmanCodeWord(i).try_into()?,
                );
                next_codes[*len as usize] += 1;
            }
        }

        Ok(Self { map })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Value(u16);

    impl TryFrom<HuffmanCodeWord> for Value {
        type Error = anyhow::Error;

        fn try_from(x: HuffmanCodeWord) -> Result<Self> {
            Ok(Self(x.0))
        }
    }

    #[test]
    fn from_lengths() -> Result<()> {
        let code = HuffmanCoding::<Value>::from_lengths(&[2, 3, 4, 3, 3, 4, 2])?;

        assert_eq!(
            code.decode_symbol(BitSequence::new(0b00, 2)),
            Some(Value(0)),
        );
        assert_eq!(
            code.decode_symbol(BitSequence::new(0b100, 3)),
            Some(Value(1)),
        );
        assert_eq!(
            code.decode_symbol(BitSequence::new(0b1110, 4)),
            Some(Value(2)),
        );
        assert_eq!(
            code.decode_symbol(BitSequence::new(0b101, 3)),
            Some(Value(3)),
        );
        assert_eq!(
            code.decode_symbol(BitSequence::new(0b110, 3)),
            Some(Value(4)),
        );
        assert_eq!(
            code.decode_symbol(BitSequence::new(0b1111, 4)),
            Some(Value(5)),
        );
        assert_eq!(
            code.decode_symbol(BitSequence::new(0b01, 2)),
            Some(Value(6)),
        );

        assert_eq!(code.decode_symbol(BitSequence::new(0b0, 1)), None);
        assert_eq!(code.decode_symbol(BitSequence::new(0b10, 2)), None);
        assert_eq!(code.decode_symbol(BitSequence::new(0b111, 3)), None,);

        Ok(())
    }

    #[test]
    fn read_symbol() -> Result<()> {
        let code = HuffmanCoding::<Value>::from_lengths(&[2, 3, 4, 3, 3, 4, 2])?;
        let mut data: &[u8] = &[0b10111001, 0b11001010, 0b11101101];
        let mut reader = BitReader::new(&mut data);

        assert_eq!(code.read_symbol(&mut reader)?, Value(1));
        assert_eq!(code.read_symbol(&mut reader)?, Value(2));
        assert_eq!(code.read_symbol(&mut reader)?, Value(3));
        assert_eq!(code.read_symbol(&mut reader)?, Value(6));
        assert_eq!(code.read_symbol(&mut reader)?, Value(0));
        assert_eq!(code.read_symbol(&mut reader)?, Value(2));
        assert_eq!(code.read_symbol(&mut reader)?, Value(4));
        assert!(code.read_symbol(&mut reader).is_err());

        Ok(())
    }

    #[test]
    fn from_lengths_with_zeros() -> Result<()> {
        let lengths = [3, 4, 5, 5, 0, 0, 6, 6, 4, 0, 6, 0, 7];
        let code = HuffmanCoding::<Value>::from_lengths(&lengths)?;
        let mut data: &[u8] = &[
            0b00100000, 0b00100001, 0b00010101, 0b10010101, 0b00110101, 0b00011101,
        ];
        let mut reader = BitReader::new(&mut data);

        assert_eq!(code.read_symbol(&mut reader)?, Value(0));
        assert_eq!(code.read_symbol(&mut reader)?, Value(1));
        assert_eq!(code.read_symbol(&mut reader)?, Value(2));
        assert_eq!(code.read_symbol(&mut reader)?, Value(3));
        assert_eq!(code.read_symbol(&mut reader)?, Value(6));
        assert_eq!(code.read_symbol(&mut reader)?, Value(7));
        assert_eq!(code.read_symbol(&mut reader)?, Value(8));
        assert_eq!(code.read_symbol(&mut reader)?, Value(10));
        assert_eq!(code.read_symbol(&mut reader)?, Value(12));
        assert!(code.read_symbol(&mut reader).is_err());

        Ok(())
    }

    #[test]
    fn from_lengths_additional() -> Result<()> {
        let lengths = [
            9, 10, 10, 8, 8, 8, 5, 6, 4, 5, 4, 5, 4, 5, 4, 4, 5, 4, 4, 5, 4, 5, 4, 5, 5, 5, 4, 6, 6,
        ];
        let code = HuffmanCoding::<Value>::from_lengths(&lengths)?;
        let mut data: &[u8] = &[
            0b11111000, 0b10111100, 0b01010001, 0b11111111, 0b00110101, 0b11111001, 0b11011111,
            0b11100001, 0b01110111, 0b10011111, 0b10111111, 0b00110100, 0b10111010, 0b11111111,
            0b11111101, 0b10010100, 0b11001110, 0b01000011, 0b11100111, 0b00000010,
        ];
        let mut reader = BitReader::new(&mut data);

        assert_eq!(code.read_symbol(&mut reader)?, Value(10));
        assert_eq!(code.read_symbol(&mut reader)?, Value(7));
        assert_eq!(code.read_symbol(&mut reader)?, Value(27));
        assert_eq!(code.read_symbol(&mut reader)?, Value(22));
        assert_eq!(code.read_symbol(&mut reader)?, Value(9));
        assert_eq!(code.read_symbol(&mut reader)?, Value(0));
        assert_eq!(code.read_symbol(&mut reader)?, Value(11));
        assert_eq!(code.read_symbol(&mut reader)?, Value(15));
        assert_eq!(code.read_symbol(&mut reader)?, Value(2));
        assert_eq!(code.read_symbol(&mut reader)?, Value(20));
        assert_eq!(code.read_symbol(&mut reader)?, Value(8));
        assert_eq!(code.read_symbol(&mut reader)?, Value(4));
        assert_eq!(code.read_symbol(&mut reader)?, Value(23));
        assert_eq!(code.read_symbol(&mut reader)?, Value(24));
        assert_eq!(code.read_symbol(&mut reader)?, Value(5));
        assert_eq!(code.read_symbol(&mut reader)?, Value(26));
        assert_eq!(code.read_symbol(&mut reader)?, Value(18));
        assert_eq!(code.read_symbol(&mut reader)?, Value(12));
        assert_eq!(code.read_symbol(&mut reader)?, Value(25));
        assert_eq!(code.read_symbol(&mut reader)?, Value(1));
        assert_eq!(code.read_symbol(&mut reader)?, Value(3));
        assert_eq!(code.read_symbol(&mut reader)?, Value(6));
        assert_eq!(code.read_symbol(&mut reader)?, Value(13));
        assert_eq!(code.read_symbol(&mut reader)?, Value(14));
        assert_eq!(code.read_symbol(&mut reader)?, Value(16));
        assert_eq!(code.read_symbol(&mut reader)?, Value(17));
        assert_eq!(code.read_symbol(&mut reader)?, Value(19));
        assert_eq!(code.read_symbol(&mut reader)?, Value(21));

        Ok(())
    }
}
