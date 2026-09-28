# CatTrim

[简体中文](README.zh.md) | English

## Introduction

`CatTrim` is a CAT signature checking and cleanup tool for offline Windows PE images.

Based on the file digests recorded in CAT files, it checks the PE and INF files currently present under the image root and finds CAT files that do not cover any existing PE or INF. An “invalid CAT” means that no PE/INF digest matched during the current scan; it does not mean that the CAT's PKCS#7 signature, certificate chain, or certificate validity period failed verification.

## Features

- Recursively scan an offline Windows image;
- Automatically locate:

  ```text
  <IMAGE_ROOT>\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}
  ```

- Parse digests from modern `CATALOG_LIST_MEMBER2` members;
- Import raw SHA-1/SHA-256 digests from legacy members according to these rules:
  - 82-byte UTF-16 wrappers are not imported;
  - 20/32-byte raw digests in `DigestInfo` are imported;
  - when these digests match an existing PE/INF, the legacy CAT is considered valid;
  - otherwise, it is added to the invalid list;
- Use Authenticode SHA-1/SHA-256 for PE files;
- Use whole-file SHA-1/SHA-256 for INF files;
- Support concurrent hash scanning;
- Support scan, copy, move, and permanent delete subcommands.

When scanning images, the following exclusion items under the image root directory are ignored by default:

```text
\$ntfs.log
\hiberfil.sys
\pagefile.sys
\swapfile.sys
\System Volume Information
\RECYCLER
\Windows\CSC
```

Directory exclusions are pruned before traversal, and matching is case-insensitive.

The following operations are not performed:

- Verifying the CAT's own PKCS#7 signature;
- Verifying certificate chains, validity periods, or revocation status;
- Modifying the offline SOFTWARE registry hive;
- There is no online mode, and the current system's CatRoot is never selected automatically;
- Ordinary non-PE/INF files such as fonts, XML, and text files are not included in matching.

## Command-line usage

### Scan

```powershell
CatTrim.exe scan <IMAGE_ROOT> [--jobs <N>] [--log <PATH>]
```

- When `--log` is not specified, stdout outputs only the absolute paths of invalid CAT files, one per line, which is suitable for redirecting directly to a CatLog:

```powershell
CatTrim.exe scan D:\Mount > CatLog.txt
```

- When specified `--log` is specified, paths are written to the file and are not repeated on stdout:

  ```powershell
  CatTrim.exe scan D:\Mount --log D:\Reports\CatLog.txt
  ```

### Copy CAT files

```powershell
CatTrim.exe copy <IMAGE_ROOT> <DEST_DIR> [--select valid|invalid] [--jobs <N>]
```

Example:

```powershell
# Copy valid CAT files
CatTrim.exe copy D:\Mount D:\ValidCat

# Copy invalid CAT files
CatTrim.exe copy D:\Mount D:\InvalidCat --select invalid
```

Behavior:

- Copy valid CAT files by default, or invalid CAT files with `--select invalid`;
- Keep source CAT files unchanged;
- Create the destination directory automatically;
- Do not overwrite an existing file with the same name;
- Continue copying other files after a collision or copy failure, then return exit code 1;
- If scanning has errors, copy the CAT files already classified in the selected set but return exit code 1 because the copied set may be incomplete.

### Move invalid CAT files

```powershell
CatTrim.exe move <IMAGE_ROOT> <DEST_DIR> [--jobs <N>] [--force]
```

Example:

```powershell
CatTrim.exe move D:\Mount D:\InvalidCat
```

Behavior:

- Create the destination directory automatically;
- Do not overwrite files with the same name already in the destination directory;
- Output the number of successful and failed moves to stdout;
- Do not generate a CatLog;
- If parsing or hashing errors occur during scanning, do not modify any files by default. With `--force`, continue moving invalid CAT files already identified even when the scan is incomplete.

### Delete invalid CAT files

```powershell
CatTrim.exe delete <IMAGE_ROOT> [--jobs <N>] [--force] [--clean-registry]
```

Example:

```powershell
# Delete invalid CAT files
CatTrim.exe delete D:\Mount

# Delete invalid CAT files and clean the registry
CatTrim.exe delete D:\Mount --clean-registry
```

Behavior:

- Permanently delete CAT files determined to be invalid by the scan;
- With `--clean-registry`, mount the offline SOFTWARE hive and remove matching CBS package entries from `Packages` and `PackageIndex` (including their values and nested subkeys);
- Output the number of successful and failed deletions to stdout;
- A registry mount, enumeration, deletion, or unmount failure causes the command to fail;
- Do not generate a CatLog;
- If scanning reports errors, do not delete anything by default. `--force` is required to allow deletion while the scan is in an error state.

> Deletion is irreversible. It is recommended to run `scan` first, review its output, and then run `move` or `delete`.

## Exit codes

```text
0  Scan or action completed without errors
1  Parse error, hash error, access error, or copy/move/delete failure
2  Invalid command-line arguments
```

> Notes:
>
> - `scan`: Even if some errors occur, it outputs the invalid CAT files already identified and then returns 1.
> - `copy`: Copies the selected CAT set even when scanning reports errors, but returns 1 because the result may be incomplete.
> - `move` and `delete`: Without `--force`, any scan error causes the command to exit before modifying any files.

## Decision rules

### CAT members

Two types of digests are added to the signature database, with duplicates removed within each CAT. Digests beginning with two `0x00` bytes are discarded.

The OID for a modern member list is `1.3.6.1.4.1.311.12.1.3`. After finding it, the program collects 20-byte SHA-1 and 32-byte SHA-256 digests from the following structures.

Legacy CAT files use OID `1.3.6.1.4.1.311.12.1.2`. The program does not branch based on this OID. A member's file fingerprint may appear in two forms:

- 82-byte UTF-16 text. After conversion to hexadecimal, if its length is not between 40 and 64, it is not imported.
- The raw digest in `DigestInfo`. The common form is `SEQUENCE { SEQUENCE { SHA-1 or SHA-256 OID, NULL }, OCTET STRING }`. An OID, NULL, and OCTET STRING appearing consecutively at the same level are also imported. The OCTET STRING is 20 or 32 bytes long.

Therefore, a legacy CAT can be considered valid: it is valid when a raw digest matches an existing PE or INF, and is added to the invalid list only when no digest matches.

### PE

PE files use the Authenticode hash ranges:

- Skip the checksum field in the PE optional header;
- Skip the certificate block pointed to by the Security Directory;
- Compute SHA-1 and SHA-256 over the remaining file ranges;
- Use chunked reads to process large files.

If the certificate offset is inside the file but the declared certificate length extends past EOF, the bytes from that offset to EOF are still excluded. The file is hashed and participates in matching. stderr records a `Hash warning`, which does not count as a scan error and does not block `move` or `delete`. A certificate offset past EOF, or one that overlaps the checksum or certificate-directory entry, remains a `Hash error`.

### INF

The extension comparison is case-insensitive. For INF files, SHA-1 and SHA-256 are computed over the entire file, without using Authenticode rules.

### Valid and invalid CAT files

Let:

- H(cat) be the set of member digests in a CAT;
- F(image) be the set of digests produced from PE/INF files in the image.

The decision is:

```text
H(cat) and F(image) intersect -> valid CAT
H(cat) and F(image) do not intersect -> invalid CAT
```

ASN.1 files that fail to parse are not added to the invalid list and are counted separately as Parse errors. A structurally complete CAT with no importable digests still enters the invalid list with an empty member set.

## Build

Rust and Cargo are required.

```powershell
cargo build --release
```

The release binary is located at:

```text
target\release\CatTrim.exe
```

## License

MIT License

## Contributing

Issues and pull requests are welcome!

## Reference

[CAT签名批量检查工具](https://bbs.wuyou.net/forum.php?mod=viewthread&tid=423164)
