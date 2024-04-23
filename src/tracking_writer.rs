#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Write};

use anyhow::{ensure, Result};
use byteorder::WriteBytesExt;
use crc::{Crc, Digest, CRC_32_ISO_HDLC};

////////////////////////////////////////////////////////////////////////////////

const HISTORY_SIZE: usize = 32768;
static CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

struct RingBuffer(VecDeque<u8>);
impl RingBuffer {
    fn write_slice(&mut self, buf: &[u8]) {
        for byte in buf {
            if self.0.len() >= HISTORY_SIZE {
                self.0.pop_back();
            }
            self.0.push_front(*byte);
        }
    }
}

pub struct TrackingWriter<T> {
    digest: Digest<'static, u32>,
    inner: T,
    byte_n: usize,
    buffer: RingBuffer,
}

impl<T: Write> Write for TrackingWriter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let size = self.inner.write(buf)?;
        // if size != buf.len() {
        //     eprint!("size != buf.len(): {} and {}", size, buf.len());
        // }
        let eff_buf = &buf[0..size];
        self.digest.update(eff_buf);
        self.buffer.write_slice(eff_buf);
        self.byte_n += size;
        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: Write> TrackingWriter<T> {
    pub fn new(inner: T) -> Self {
        Self {
            digest: CRC.digest(),
            inner,
            byte_n: 0,
            buffer: RingBuffer(VecDeque::new()),
        }
    }

    /// Write a sequence of `len` bytes written `dist` bytes ago.
    pub fn write_previous(&mut self, dist: usize, len: usize) -> Result<()> {
        ensure!(dist <= self.byte_n, "Trying to go back in time");
        ensure!(dist <= HISTORY_SIZE, "Trying to rewrite to much history");
        for _i in 0..len {
            self.write_u8(self.buffer.0[dist - 1])?;
        }
        Ok(())
    }

    pub fn byte_count(&self) -> usize {
        self.byte_n
    }

    pub fn crc32(self) -> u32 {
        self.digest.finalize()
    }

    pub fn get_mut_ref_inner(&mut self) -> &mut T {
        &mut self.inner
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;

    #[test]
    fn write() -> Result<()> {
        let mut buf: &mut [u8] = &mut [0u8; 10];
        let mut writer = TrackingWriter::new(&mut buf);

        assert_eq!(writer.write(&[1, 2, 3, 4])?, 4);
        assert_eq!(writer.byte_count(), 4);

        assert_eq!(writer.write(&[4, 8, 15, 16, 23])?, 5);
        assert_eq!(writer.byte_count(), 9);

        assert_eq!(writer.write(&[0, 0, 123])?, 1);
        assert_eq!(writer.byte_count(), 10);

        assert_eq!(writer.write(&[42, 124, 234, 27])?, 0);
        assert_eq!(writer.byte_count(), 10);
        assert_eq!(writer.crc32(), 2992191065);

        Ok(())
    }

    #[test]
    fn write_previous() -> Result<()> {
        let mut buf: &mut [u8] = &mut [0u8; 512];
        let mut writer = TrackingWriter::new(&mut buf);

        for i in 0..=255 {
            writer.write_u8(i)?;
        }

        writer.write_previous(192, 128)?;
        assert_eq!(writer.byte_count(), 384);

        assert!(writer.write_previous(10000, 20).is_err());
        assert_eq!(writer.byte_count(), 384);

        assert!(writer.write_previous(256, 256).is_err());
        assert_eq!(writer.byte_count(), 512);

        assert!(writer.write_previous(1, 1).is_err());
        assert_eq!(writer.byte_count(), 512);
        assert_eq!(writer.crc32(), 2733545866);

        Ok(())
    }

    #[test]
    fn buffer_overflow() -> Result<()> {
        let mut buf: &mut [u8] = &mut [0u8; 512000];
        let mut writer = TrackingWriter::new(&mut buf);

        for i in 0..100000 {
            let i = i as u32;
            writer.write(&[i as u8])?;
            writer.write(&[(i >> 8) as u8])?;
            writer.write(&[(i >> 16) as u8])?;
            writer.write(&[(i >> 24) as u8])?;
        }

        assert_eq!(writer.byte_count(), 400000);

        writer.write_previous(32000, 32000)?;
        assert_eq!(writer.crc32(), 794338957);

        Ok(())
    }

    #[test]
    fn buffer_overrun() -> Result<()> {
        let mut buf: &mut [u8] = &mut [0u8; 512];
        let mut writer = TrackingWriter::new(&mut buf);

        writer.write(b"Aboba or Bebra")?;
        writer.write_previous(2, 8)?;

        assert_eq!(writer.crc32(), 511788579);

        Ok(())
    }
}
