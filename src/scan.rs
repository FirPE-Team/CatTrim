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
    pub invalid: Vec<PathBuf>,
    pub parse_errors: Vec<(PathBuf, String)>,
    pub hash_errors: Vec<(PathBuf, String)>,
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
    for entry in WalkDir::new(image_root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk image {}", image_root.display()))?;
        if entry.file_type().is_file() {
            paths.push(entry.path().to_path_buf());
        }
    }
    paths.sort();
    Ok(paths)
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
                    return (path.clone(), FileHashResult::Inf, hash_file(path));
                }
                match hash_pe_authenticode(path) {
                    Ok(Some(hashes)) => (path.clone(), FileHashResult::Pe, Ok(hashes)),
                    Ok(None) => (path.clone(), FileHashResult::Ignored, Ok(Vec::new())),
                    Err(error) => (path.clone(), FileHashResult::Pe, Err(error)),
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
    for (path, kind, result) in file_results {
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
    report.invalid = report
        .cats
        .iter()
        .enumerate()
        .filter(|(index, _)| !used.contains(index))
        .map(|(_, cat)| cat.path.clone())
        .collect();
    report.invalid.sort();
    Ok(report)
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
        let rendered = absolute.to_string_lossy();
        let rendered = rendered.strip_prefix("\\\\?\\").unwrap_or(&rendered);
        text.push_str(rendered);
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
