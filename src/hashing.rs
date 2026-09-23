use crate::digest::Digest;
use anyhow::{Context, Result, bail};
use sha1::{Digest as ShaDigest, Sha1};
use sha2::Sha256;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const CHUNK_SIZE: usize = 16 * 1024 * 1024;

fn hash_reader<R: Read>(reader: &mut R) -> Result<Vec<Digest>> {
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let count = reader
            .read(&mut buffer)
            .context("read file while hashing")?;
        if count == 0 {
            break;
        }
        sha1.update(&buffer[..count]);
        sha256.update(&buffer[..count]);
    }
    Ok(vec![
        Digest::Sha1(sha1.finalize().into()),
        Digest::Sha256(sha256.finalize().into()),
    ])
}

pub fn hash_file(path: &Path) -> Result<Vec<Digest>> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    hash_reader(&mut file)
}

fn read_at(file: &mut File, offset: u64, length: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .context("seek PE header")?;
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes).context("read PE header")?;
    Ok(bytes)
}

fn u16_at(file: &mut File, offset: u64) -> Result<u16> {
    Ok(u16::from_le_bytes(
        read_at(file, offset, 2)?.try_into().unwrap(),
    ))
}

fn u32_at(file: &mut File, offset: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(
        read_at(file, offset, 4)?.try_into().unwrap(),
    ))
}

fn hash_range(
    file: &mut File,
    start: u64,
    end: u64,
    sha1: &mut Sha1,
    sha256: &mut Sha256,
) -> Result<()> {
    if end < start {
        bail!("invalid PE hash range");
    }
    file.seek(SeekFrom::Start(start))
        .context("seek PE hash range")?;
    let mut remaining = end - start;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    while remaining > 0 {
        let wanted = remaining.min(CHUNK_SIZE as u64) as usize;
        file.read_exact(&mut buffer[..wanted])
            .context("read PE hash range")?;
        sha1.update(&buffer[..wanted]);
        sha256.update(&buffer[..wanted]);
        remaining -= wanted as u64;
    }
    Ok(())
}

pub fn hash_pe_authenticode(path: &Path) -> Result<Option<Vec<Digest>>> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let file_len = file.metadata().context("stat PE")?.len();
    if file_len < 64 || read_at(&mut file, 0, 2)? != b"MZ" {
        return Ok(None);
    }
    let e_lfanew = u32_at(&mut file, 0x3c)? as u64;
    let pe_header_end = e_lfanew.checked_add(24).context("PE header overflow")?;
    if pe_header_end > file_len {
        bail!("truncated PE header");
    }
    if read_at(&mut file, e_lfanew, 4)? != b"PE\0\0" {
        return Ok(None);
    }
    let optional_size = u16_at(&mut file, e_lfanew + 20)? as u64;
    if optional_size < 0xA4 {
        bail!("PE optional header is too small");
    }
    let optional_start = e_lfanew + 24;
    let optional_end = optional_start
        .checked_add(optional_size)
        .context("optional header overflow")?;
    if optional_end > file_len {
        bail!("truncated PE optional header");
    }

    let checksum = e_lfanew
        .checked_add(0x58)
        .context("checksum offset overflow")?;
    let first_end = checksum;
    let second_start = checksum + 4;
    let cert_entry_start = e_lfanew + optional_size - 0x48;
    let cert_entry_end = e_lfanew + optional_size - 0x40;
    if first_end > file_len || second_start > cert_entry_start || cert_entry_end > file_len {
        bail!("invalid PE Authenticode ranges");
    }
    let cert_offset = u32_at(&mut file, cert_entry_start)? as u64;
    let cert_size = u32_at(&mut file, cert_entry_start + 4)? as u64;
    if cert_size != 0 {
        let cert_end = cert_offset
            .checked_add(cert_size)
            .context("certificate range overflow")?;
        if cert_offset < cert_entry_end || cert_end > file_len {
            bail!("invalid PE certificate range");
        }
    } else if cert_offset != 0 && cert_offset > file_len {
        bail!("invalid PE certificate offset");
    }

    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    hash_range(&mut file, 0, first_end, &mut sha1, &mut sha256)?;
    hash_range(
        &mut file,
        second_start,
        cert_entry_start,
        &mut sha1,
        &mut sha256,
    )?;
    let after_certificate_entry = cert_entry_end;
    if cert_size == 0 {
        hash_range(
            &mut file,
            after_certificate_entry,
            file_len,
            &mut sha1,
            &mut sha256,
        )?;
    } else {
        let cert_end = cert_offset + cert_size;
        if cert_offset > after_certificate_entry {
            hash_range(
                &mut file,
                after_certificate_entry,
                cert_offset,
                &mut sha1,
                &mut sha256,
            )?;
        }
        hash_range(&mut file, cert_end, file_len, &mut sha1, &mut sha256)?;
    }
    Ok(Some(vec![
        Digest::Sha1(sha1.finalize().into()),
        Digest::Sha256(sha256.finalize().into()),
    ]))
}
