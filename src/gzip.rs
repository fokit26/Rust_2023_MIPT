#![forbid(unsafe_code)]

use std::io::BufRead;

use anyhow::{ensure, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use crc::Crc;

use crate::{bit_reader::BitReader, deflate::DeflateReader};

////////////////////////////////////////////////////////////////////////////////

const ID1: u8 = 0x1f;
const ID2: u8 = 0x8b;

const CM_DEFLATE: u8 = 8;

const FTEXT_OFFSET: u8 = 0;
const FHCRC_OFFSET: u8 = 1;
const FEXTRA_OFFSET: u8 = 2;
const FNAME_OFFSET: u8 = 3;
const FCOMMENT_OFFSET: u8 = 4;

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct MemberHeader {
    pub compression_method: CompressionMethod,
    pub flags: MemberFlags,
    pub modification_time: u32,
    pub extra: Option<Vec<u8>>,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub extra_flags: u8,
    pub os: u8,
}

impl MemberHeader {
    pub fn crc16(&self) -> u16 {
        let crc = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
        let mut digest = crc.digest();

        digest.update(&[ID1, ID2, self.compression_method.into(), self.flags().0]);
        digest.update(&self.modification_time.to_le_bytes());
        digest.update(&[self.extra_flags, self.os]);

        if let Some(extra) = &self.extra {
            digest.update(&(extra.len() as u16).to_le_bytes());
            digest.update(extra);
        }

        if let Some(name) = &self.name {
            digest.update(name.as_bytes());
            digest.update(&[0]);
        }

        if let Some(comment) = &self.comment {
            digest.update(comment.as_bytes());
            digest.update(&[0]);
        }

        (digest.finalize() & 0xffff) as u16
    }

    pub fn flags(&self) -> MemberFlags {
        self.flags
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug, PartialEq, Ord, PartialOrd, Eq)]
pub enum CompressionMethod {
    Deflate,
    Unknown(u8),
}

impl From<u8> for CompressionMethod {
    fn from(value: u8) -> Self {
        match value {
            CM_DEFLATE => Self::Deflate,
            x => Self::Unknown(x),
        }
    }
}

impl From<CompressionMethod> for u8 {
    fn from(method: CompressionMethod) -> u8 {
        match method {
            CompressionMethod::Deflate => CM_DEFLATE,
            CompressionMethod::Unknown(x) => x,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy)]
pub struct MemberFlags(u8);

#[allow(unused)]
impl MemberFlags {
    fn bit(&self, n: u8) -> bool {
        (self.0 >> n) & 1 != 0
    }

    fn set_bit(&mut self, n: u8, value: bool) {
        if value {
            self.0 |= 1 << n;
        } else {
            self.0 &= !(1 << n);
        }
    }

    pub fn is_text(&self) -> bool {
        self.bit(FTEXT_OFFSET)
    }

    pub fn set_is_text(&mut self, value: bool) {
        self.set_bit(FTEXT_OFFSET, value)
    }

    pub fn has_crc(&self) -> bool {
        self.bit(FHCRC_OFFSET)
    }

    pub fn set_has_crc(&mut self, value: bool) {
        self.set_bit(FHCRC_OFFSET, value)
    }

    pub fn has_extra(&self) -> bool {
        self.bit(FEXTRA_OFFSET)
    }

    pub fn set_has_extra(&mut self, value: bool) {
        self.set_bit(FEXTRA_OFFSET, value)
    }

    pub fn has_name(&self) -> bool {
        self.bit(FNAME_OFFSET)
    }

    pub fn set_has_name(&mut self, value: bool) {
        self.set_bit(FNAME_OFFSET, value)
    }

    pub fn has_comment(&self) -> bool {
        self.bit(FCOMMENT_OFFSET)
    }

    pub fn set_has_comment(&mut self, value: bool) {
        self.set_bit(FCOMMENT_OFFSET, value)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct MemberFooter {
    pub data_crc32: u32,
    pub data_size: u32,
}

////////////////////////////////////////////////////////////////////////////////

pub struct MemberReader<T> {
    inner: T,
}

impl<T: BufRead> MemberReader<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn into_deflate_reader(mut self) -> Result<(MemberHeader, DeflateReader<T>)> {
        let id1 = self.inner.read_u8()?;
        let id2 = self.inner.read_u8()?;
        ensure!(id1 == ID1 && id2 == ID2, "wrong id values");
        let cm: CompressionMethod = self.inner.read_u8()?.try_into()?;
        let flags: MemberFlags = MemberFlags(self.inner.read_u8()?);
        let mtime = self.inner.read_u32::<LittleEndian>()?;
        let xfl = self.inner.read_u8()?;
        let os = self.inner.read_u8()?;

        let extra = if flags.has_extra() {
            let len = self.inner.read_u16::<LittleEndian>()?;
            let mut extra: Vec<u8> = Vec::new();
            extra.resize(len as usize, 0);
            let read_len = self.inner.read(extra.as_mut_slice())?;
            ensure!(
                read_len == len as usize,
                "Not enough bytes for extra fields"
            );
            Some(extra)
        } else {
            None
        };

        let name = if flags.has_name() {
            let mut name: Vec<u8> = Vec::new();
            let mut byte;
            while {
                byte = self.inner.read_u8()?;
                byte != 0
            } {
                name.push(byte)
            }
            Some(String::from_utf8(name)?)
        } else {
            None
        };

        let comment = if flags.has_comment() {
            let mut comment: Vec<u8> = Vec::new();
            let mut byte;
            while {
                byte = self.inner.read_u8()?;
                byte != 0
            } {
                comment.push(byte)
            }
            Some(String::from_utf8(comment)?)
        } else {
            None
        };

        let header = MemberHeader {
            compression_method: cm,
            flags,
            modification_time: mtime,
            extra,
            name,
            comment,
            extra_flags: xfl,
            os,
        };

        if header.flags.has_crc() {
            let crc = self.inner.read_u16::<LittleEndian>()?;
            ensure!(header.crc16() == crc, "header crc16 check failed");
        }

        Ok((header, DeflateReader::new(BitReader::new(self.inner))))
    }

    pub fn read_footer(rdr: &mut T) -> Result<MemberFooter> {
        let crc = rdr.read_u32::<LittleEndian>()?;
        let isize = rdr.read_u32::<LittleEndian>()?;
        Ok(MemberFooter {
            data_crc32: crc,
            data_size: isize,
        })
    }
}
