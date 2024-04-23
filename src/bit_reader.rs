#![forbid(unsafe_code)]

use byteorder::ReadBytesExt;
use std::io::{self, BufRead};

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BitSequence {
    bits: u16,
    len: u8,
}

impl BitSequence {
    pub fn new(bits: u16, len: u8) -> Self {
        BitSequence {
            bits: bits & ((1 << len) - 1),
            len,
        }
    }

    pub fn bits(&self) -> u16 {
        self.bits
    }

    #[allow(unused)]
    pub fn len(&self) -> u8 {
        self.len
    }

    pub fn concat(self, other: Self) -> Self {
        BitSequence {
            bits: self.bits | (other.bits << self.len),
            len: self.len + other.len,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

pub struct BitReader<T> {
    stream: T,
    buffer: u8,
    len: u8,
}

impl<T: BufRead> BitReader<T> {
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            buffer: 0,
            len: 0,
        }
    }

    pub fn read_bits(&mut self, mut len: u8) -> io::Result<BitSequence> {
        let mut ans = BitSequence::new(0, 0);
        while len > 0 {
            if self.len < len {
                ans = ans.concat(BitSequence::new(self.buffer as u16, self.len));
                len -= self.len;
                self.buffer = self.stream.read_u8()?;
                self.len = 8;
            } else {
                ans = ans.concat(BitSequence::new(self.buffer as u16, len));
                (self.buffer, _) = self.buffer.overflowing_shr(len as u32);
                self.len -= len;
                len = 0;
            }
        }

        Ok(ans)
    }

    pub fn borrow_reader_from_boundary(&mut self) -> &mut T {
        self.buffer = 0;
        self.len = 0;
        &mut self.stream
    }

    pub fn into_inner(self) -> T {
        self.stream
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::ReadBytesExt;

    #[test]
    fn read_bits() -> io::Result<()> {
        let data: &[u8] = &[0b01100011, 0b11011011, 0b10101111];
        let mut reader = BitReader::new(data);
        assert_eq!(reader.read_bits(1)?, BitSequence::new(0b1, 1));
        assert_eq!(reader.read_bits(2)?, BitSequence::new(0b01, 2));
        assert_eq!(reader.read_bits(3)?, BitSequence::new(0b100, 3));
        assert_eq!(reader.read_bits(4)?, BitSequence::new(0b1101, 4));
        assert_eq!(reader.read_bits(5)?, BitSequence::new(0b10110, 5));
        assert_eq!(reader.read_bits(8)?, BitSequence::new(0b01011111, 8));
        assert_eq!(
            reader.read_bits(2).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        Ok(())
    }

    #[test]
    fn borrow_reader_from_boundary() -> io::Result<()> {
        let data: &[u8] = &[0b01100011, 0b11011011, 0b10101111];
        let mut reader = BitReader::new(data);
        assert_eq!(reader.read_bits(3)?, BitSequence::new(0b011, 3));
        assert_eq!(reader.borrow_reader_from_boundary().read_u8()?, 0b11011011);
        assert_eq!(reader.read_bits(8)?, BitSequence::new(0b10101111, 8));
        Ok(())
    }
}
