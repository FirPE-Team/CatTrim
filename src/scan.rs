use crate::{
    catalog::{CatRecord, parse_cat},
    digest::Digest,
    hashing::{hash_file, hash_pe_authenticode},
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

pub const CAT_GUID: &str = "{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";

#[derive(Debug, Default)]
pub struct ScanReport {
    pub cats: Vec<CatRecord>,
    pub valid: Vec<PathBuf>,
    pub invalid: Vec<PathBuf>,
    pub parse_errors: Vec<(PathBuf, String)>,
    pub hash_errors: Vec<(PathBuf, String)>,
    pub hash_warnings: Vec<(PathBuf, String)>,
    pub pe_count: usize,
    pub inf_count: usize,
    pub ignored_count: usize,
}

impl ScanReport {
    pub fn has_errors(&self) -> bool {
        !self.parse_errors.is_empty() || !self.hash_errors.is_empty()
    }
}

pub fn locate_cat_root(image_root: &Path) -> PathBuf {
    image_root
        .join("Windows")
        .join("System32")
        .join("CatRoot")
        .join(CAT_GUID)
}

/// Render a Windows path without the extended-length prefix used internally by
/// filesystem APIs. The prefix is useful for opening long paths, but is noisy
/// and misleading in user-facing diagnostics.
pub fn display_path(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if let Some(rest) = rendered.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = rendered.strip_prefix("\\\\?\\") {
        rest.to_owned()
    } else {
        rendered.into_owned()
    }
}

fn cat_paths(cat_root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(cat_root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk CAT directory {}", cat_root.display()))?;
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("cat"))
        {
            paths.push(entry.path().to_path_buf());
        }
    }
    paths.sort();
    Ok(paths)
}

fn image_files(image_root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let walker = WalkDir::new(image_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_default_image_exclusion(image_root, entry.path()));
    for entry in walker {
        let entry = entry.with_context(|| format!("walk image {}", image_root.display()))?;
        if entry.file_type().is_file() {
            paths.push(entry.path().to_path_buf());
        }
    }
    paths.sort();
    Ok(paths)
}

fn is_default_image_exclusion(image_root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(image_root) else {
        return false;
    };
    let components = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>();

    match components.as_slice() {
        [name] => [
            "$ntfs.log",
            "hiberfil.sys",
            "pagefile.sys",
            "swapfile.sys",
            "System Volume Information",
            "RECYCLER",
        ]
        .iter()
        .any(|excluded| name.eq_ignore_ascii_case(excluded)),
        [windows, csc, ..] => {
            windows.eq_ignore_ascii_case("Windows") && csc.eq_ignore_ascii_case("CSC")
        }
        _ => false,
    }
}

pub fn scan(image_root: &Path, jobs: usize) -> Result<ScanReport> {
    if jobs == 0 {
        anyhow::bail!("--jobs must be greater than zero");
    }
    let cat_root = locate_cat_root(image_root);
    if !cat_root.is_dir() {
        anyhow::bail!("CAT directory does not exist: {}", cat_root.display());
    }
    let cat_paths = cat_paths(&cat_root)?;
    if cat_paths.is_empty() {
        anyhow::bail!(
            "CAT directory contains no .cat files: {}",
            cat_root.display()
        );
    }

    let parsed: Vec<(PathBuf, Result<CatRecord>)> = cat_paths
        .par_iter()
        .map(|path| (path.clone(), parse_cat(path)))
        .collect();
    let mut report = ScanReport::default();
    for (path, result) in parsed {
        match result {
            Ok(record) => report.cats.push(record),
            Err(error) => report.parse_errors.push((path, format!("{error:#}"))),
        }
    }
    report.cats.sort_by(|a, b| a.path.cmp(&b.path));
    report.parse_errors.sort_by(|a, b| a.0.cmp(&b.0));

    let files = image_files(image_root)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .context("create hash thread pool")?;
    let file_results = pool.install(|| {
        files
            .par_iter()
            .map(|path| {
                let is_inf = path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("inf"));
                if is_inf {
                    return (path.clone(), FileHashResult::Inf, hash_file(path), None);
                }
                match hash_pe_authenticode(path) {
                    Ok(Some(hash)) => (
                        path.clone(),
                        FileHashResult::Pe,
                        Ok(hash.digests),
                        hash.warning,
                    ),
                    Ok(None) => (path.clone(), FileHashResult::Ignored, Ok(Vec::new()), None),
                    Err(error) => (path.clone(), FileHashResult::Pe, Err(error), None),
                }
            })
            .collect::<Vec<_>>()
    });

    let mut digest_to_cats: HashMap<Digest, Vec<usize>> = HashMap::new();
    for (index, cat) in report.cats.iter().enumerate() {
        for digest in &cat.members {
            digest_to_cats.entry(*digest).or_default().push(index);
        }
    }
    let mut used = HashSet::new();
    for (path, kind, result, warning) in file_results {
        if let Some(warning) = warning {
            report.hash_warnings.push((path.clone(), warning));
        }
        match result {
            Ok(digests) => {
                match kind {
                    FileHashResult::Pe => report.pe_count += 1,
                    FileHashResult::Inf => report.inf_count += 1,
                    FileHashResult::Ignored => report.ignored_count += 1,
                }
                for digest in digests {
                    if let Some(indices) = digest_to_cats.get(&digest) {
                        used.extend(indices.iter().copied());
                    }
                }
            }
            Err(error) => report.hash_errors.push((path, format!("{error:#}"))),
        }
    }
    report.hash_errors.sort_by(|a, b| a.0.cmp(&b.0));
    report.hash_warnings.sort_by(|a, b| a.0.cmp(&b.0));
    (report.valid, report.invalid) = classify_catalogs(&report.cats, &used);
    Ok(report)
}

fn classify_catalogs(cats: &[CatRecord], used: &HashSet<usize>) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for (index, cat) in cats.iter().enumerate() {
        if used.contains(&index) {
            valid.push(cat.path.clone());
        } else {
            invalid.push(cat.path.clone());
        }
    }
    valid.sort();
    invalid.sort();
    (valid, invalid)
}

enum FileHashResult {
    Pe,
    Inf,
    Ignored,
}

pub fn render_invalid_paths(invalid: &[PathBuf]) -> String {
    let mut text = String::new();
    for item in invalid {
        let absolute = item.canonicalize().unwrap_or_else(|_| item.clone());
        text.push_str(&display_path(&absolute));
        text.push('\n');
    }
    text
}

pub fn write_log(path: &Path, text: &str) -> Result<()> {
    fs::write(path, text).with_context(|| format!("write log {}", path.display()))
}

pub fn write_stdout(text: &str) -> Result<()> {
    use std::io::{self, Write};
    io::stdout()
        .write_all(text.as_bytes())
        .context("write stdout")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_image_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "invalid-certificate-exclusions-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn image_walk_applies_default_dism_exclusions() {
        let root = temporary_image_root();
        let included = root.join("Windows").join("System32").join("kept.dll");
        let csc_file = root.join("Windows").join("CSC").join("cache.dll");
        let volume_file = root.join("System Volume Information").join("tracking.log");
        let recycler_file = root.join("RECYCLER").join("deleted.exe");
        let compression_only = root.join("archive.zip");

        for path in [
            &included,
            &csc_file,
            &volume_file,
            &recycler_file,
            &compression_only,
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"test").unwrap();
        }
        for name in ["$ntfs.log", "hiberfil.sys", "pagefile.sys", "swapfile.sys"] {
            fs::write(root.join(name), b"test").unwrap();
        }

        let files = image_files(&root).unwrap();
        assert!(files.contains(&included));
        assert!(files.contains(&compression_only));
        assert!(!files.contains(&csc_file));
        assert!(!files.contains(&volume_file));
        assert!(!files.contains(&recycler_file));
        assert!(!files.contains(&root.join("$ntfs.log")));
        assert!(!files.contains(&root.join("hiberfil.sys")));
        assert!(!files.contains(&root.join("pagefile.sys")));
        assert!(!files.contains(&root.join("swapfile.sys")));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_classification_separates_used_paths() {
        let cats = vec![
            CatRecord {
                path: PathBuf::from("b.cat"),
                members: HashSet::new(),
            },
            CatRecord {
                path: PathBuf::from("a.cat"),
                members: HashSet::new(),
            },
            CatRecord {
                path: PathBuf::from("c.cat"),
                members: HashSet::new(),
            },
        ];
        let used = HashSet::from([0usize, 2usize]);

        let (valid, invalid) = classify_catalogs(&cats, &used);

        assert_eq!(valid, vec![PathBuf::from("b.cat"), PathBuf::from("c.cat")]);
        assert_eq!(invalid, vec![PathBuf::from("a.cat")]);
    }

    #[test]
    fn display_path_removes_extended_length_prefix() {
        assert_eq!(
            display_path(Path::new(r"\\?\C:\Program Files\app.exe")),
            r"C:\Program Files\app.exe"
        );
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\server\share\app.exe")),
            r"\\server\share\app.exe"
        );
        assert_eq!(
            display_path(Path::new(r"C:\Program Files\app.exe")),
            r"C:\Program Files\app.exe"
        );
    }
}
