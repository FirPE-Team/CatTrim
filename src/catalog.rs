use crate::digest::Digest;
use anyhow::{Context, Result, bail};
use std::{collections::HashSet, fs, path::Path};

const MEMBER2_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0C, 0x01, 0x03];

#[derive(Debug)]
pub struct CatRecord {
    pub path: std::path::PathBuf,
    pub members: HashSet<Digest>,
}

#[derive(Clone, Copy, Debug)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    constructed: bool,
}

fn next_tlv<'a>(data: &'a [u8], offset: &mut usize, end: usize) -> Result<Option<Tlv<'a>>> {
    if *offset == end {
        return Ok(None);
    }
    if *offset > end || end - *offset < 2 {
        bail!("truncated ASN.1 TLV header");
    }
    let tag = data[*offset];
    *offset += 1;
    let length_byte = data[*offset];
    *offset += 1;
    if length_byte == 0x80 {
        bail!("indefinite ASN.1 lengths are not supported");
    }
    let length = if length_byte & 0x80 == 0 {
        length_byte as usize
    } else {
        let count = (length_byte & 0x7F) as usize;
        if count == 0 || count > std::mem::size_of::<usize>() || end - *offset < count {
            bail!("invalid ASN.1 length");
        }
        let mut value = 0usize;
        for byte in &data[*offset..*offset + count] {
            value = value
                .checked_shl(8)
                .and_then(|v| v.checked_add(*byte as usize))
                .context("ASN.1 length overflow")?;
        }
        *offset += count;
        value
    };
    let content_end = (*offset)
        .checked_add(length)
        .context("ASN.1 content overflow")?;
    if content_end > end {
        bail!("ASN.1 content exceeds enclosing value");
    }
    let content = &data[*offset..content_end];
    *offset = content_end;
    Ok(Some(Tlv {
        tag,
        content,
        constructed: tag & 0x20 != 0,
    }))
}

fn collect_octets_after_member_oid(
    data: &[u8],
    start: usize,
    end: usize,
    out: &mut HashSet<Digest>,
) -> Result<bool> {
    let mut offset = start;
    let mut children = Vec::new();
    while offset < end {
        let before = offset;
        let tlv = next_tlv(data, &mut offset, end)?.context("missing ASN.1 value")?;
        children.push((before, tlv));
    }

    let mut found = false;
    for (index, (_, child)) in children.iter().enumerate() {
        if child.tag == 0x06 && child.content == MEMBER2_OID {
            found = true;
            for (_, following) in children.iter().skip(index + 1) {
                if following.constructed {
                    collect_all_octets(following.content, out)?;
                }
            }
        }
    }

    for (index, (_, child)) in children.iter().enumerate() {
        if child.constructed
            && collect_octets_after_member_oid(child.content, 0, child.content.len(), out)?
        {
            found = true;
            for (_, following) in children.iter().skip(index + 1) {
                if following.constructed {
                    collect_all_octets(following.content, out)?;
                }
            }
        }
    }
    Ok(found)
}

fn collect_all_octets(data: &[u8], out: &mut HashSet<Digest>) -> Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let tlv = next_tlv(data, &mut offset, data.len())?.context("missing ASN.1 value")?;
        if tlv.tag == 0x04
            && let Some(digest) = Digest::from_bytes(tlv.content)
        {
            out.insert(digest);
        }
        if tlv.constructed {
            collect_all_octets(tlv.content, out)?;
        }
    }
    Ok(())
}

pub fn parse_cat(path: &Path) -> Result<CatRecord> {
    let data = fs::read(path).with_context(|| format!("read CAT {}", path.display()))?;
    if data.first().copied() != Some(0x30) {
        bail!("CAT does not start with ASN.1 SEQUENCE");
    }
    let mut offset = 0;
    let outer = next_tlv(&data, &mut offset, data.len())?.context("empty CAT")?;
    if outer.tag != 0x30 || offset != data.len() {
        bail!("CAT outer ASN.1 structure is invalid");
    }
    let mut members = HashSet::new();
    if !collect_octets_after_member_oid(outer.content, 0, outer.content.len(), &mut members)? {
        bail!("CATALOG_LIST_MEMBER2 OID was not found");
    }
    if members.is_empty() {
        bail!("CAT contains no usable SHA-1/SHA-256 members");
    }
    Ok(CatRecord {
        path: path.to_path_buf(),
        members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut result = vec![tag, content.len() as u8];
        result.extend_from_slice(content);
        result
    }

    #[test]
    fn extracts_members_and_filters_invalid_digest() {
        let sha1 = [1u8; 20];
        let sha256 = [2u8; 32];
        let zero = [0u8; 20];
        let mut value = Vec::new();
        value.extend(tlv(0x06, MEMBER2_OID));
        let mut members = Vec::new();
        members.extend(tlv(0x04, &sha1));
        members.extend(tlv(0x04, &sha1));
        members.extend(tlv(0x04, &sha256));
        members.extend(tlv(0x04, &zero));
        value.extend(tlv(0x30, &members));
        let data = tlv(0x30, &value);
        let path = std::env::temp_dir().join("invalid_certificate_test.cat");
        fs::write(&path, data).unwrap();
        let record = parse_cat(&path).unwrap();
        assert_eq!(record.members.len(), 2);
        let _ = fs::remove_file(path);
    }
}
