mod catalog;
mod cli;
mod digest;
mod hashing;
mod registry;
mod scan;

use crate::cli::{CatSelection, Cli, Command, CopyArgs, DeleteArgs, MoveArgs, ScanArgs};
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

/// Canonicalize the path to the offline image root.
fn canonical_image_root(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("invalid image root {}", scan::display_path(path)))
}

/// Print diagnostics about the scan report.
fn print_diagnostics(report: &scan::ScanReport) {
    eprintln!(
        "CAT total: {}",
        report.cats.len() + report.parse_errors.len()
    );
    eprintln!("Valid CAT: {}", report.valid.len());
    eprintln!("Invalid CAT: {}", report.invalid.len());
    eprintln!("Parse errors: {}", report.parse_errors.len());
    eprintln!("Hash warnings: {}", report.hash_warnings.len());
    eprintln!(
        "PE: {}, INF: {}, ignored: {}",
        report.pe_count, report.inf_count, report.ignored_count
    );
    for (path, error) in &report.parse_errors {
        eprintln!("CAT parse error: {}: {}", scan::display_path(path), error);
    }
    for (path, error) in &report.hash_errors {
        eprintln!("Hash error: {}: {}", scan::display_path(path), error);
    }
    for (path, warning) in &report.hash_warnings {
        eprintln!("Hash warning: {}: {}", scan::display_path(path), warning);
    }
}

/// Run the scan command.
fn run_scan(args: ScanArgs) -> Result<bool> {
    let image_root = canonical_image_root(&args.image_root)?;
    let report = scan::scan(&image_root, args.jobs)?;
    let text = scan::render_invalid_paths(&report.invalid);
    if let Some(log) = args.log {
        scan::write_log(&log, &text)?;
        let log = log.canonicalize().unwrap_or(log);
        eprintln!("CatLog: {}", scan::display_path(&log));
    } else {
        scan::write_stdout(&text)?;
    }
    print_diagnostics(&report);
    Ok(!report.has_errors())
}

/// Run the move command.
fn run_move(args: MoveArgs) -> Result<bool> {
    let image_root = canonical_image_root(&args.image_root)?;
    let report = scan::scan(&image_root, args.jobs)?;
    print_diagnostics(&report);
    if report.has_errors() && !args.force {
        eprintln!(
            "Scan errors detected; file operations were not performed. If you accept the risks, please use --force."
        );
        return Ok(false);
    }

    fs::create_dir_all(&args.destination).with_context(|| {
        format!(
            "create move destination {}",
            scan::display_path(&args.destination)
        )
    })?;
    let destination = args.destination.canonicalize().unwrap_or(args.destination);
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    for source in &report.invalid {
        let target = destination.join(source.file_name().context("CAT has no file name")?);
        if target.exists() {
            eprintln!(
                "Move skipped (target exists): {}",
                scan::display_path(&target)
            );
            failed += 1;
            continue;
        }
        match fs::rename(source, &target) {
            Ok(()) => succeeded += 1,
            Err(error) => {
                eprintln!(
                    "Move failed: {} -> {}: {}",
                    scan::display_path(source),
                    scan::display_path(&target),
                    error
                );
                failed += 1;
            }
        }
    }
    println!("Moved: {}, failed: {}", succeeded, failed);
    Ok(!report.has_errors() && failed == 0)
}

/// Run the copy command.
fn run_copy(args: CopyArgs) -> Result<bool> {
    let image_root = canonical_image_root(&args.image_root)?;
    let report = scan::scan(&image_root, args.jobs)?;
    print_diagnostics(&report);

    let sources = match args.select {
        CatSelection::Valid => &report.valid,
        CatSelection::Invalid => &report.invalid,
    };
    let (succeeded, failed) = copy_catalogs(sources, &args.destination)?;
    println!("Copied: {}, failed: {}", succeeded, failed);
    Ok(!report.has_errors() && failed == 0)
}

fn copy_catalogs(sources: &[PathBuf], destination: &Path) -> Result<(usize, usize)> {
    fs::create_dir_all(destination).with_context(|| {
        format!(
            "create copy destination {}",
            scan::display_path(destination)
        )
    })?;
    let destination = destination
        .canonicalize()
        .unwrap_or_else(|_| destination.to_path_buf());
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    for source in sources {
        let target = destination.join(source.file_name().context("CAT has no file name")?);
        if target.exists() {
            eprintln!(
                "Copy skipped (target exists): {}",
                scan::display_path(&target)
            );
            failed += 1;
            continue;
        }
        match fs::copy(source, &target) {
            Ok(_) => succeeded += 1,
            Err(error) => {
                eprintln!(
                    "Copy failed: {} -> {}: {}",
                    scan::display_path(source),
                    scan::display_path(&target),
                    error
                );
                failed += 1;
            }
        }
    }
    Ok((succeeded, failed))
}

/// Run the delete command.
fn run_delete(args: DeleteArgs) -> Result<bool> {
    let image_root = canonical_image_root(&args.image_root)?;
    let report = scan::scan(&image_root, args.jobs)?;
    print_diagnostics(&report);
    if report.has_errors() && !args.force {
        eprintln!(
            "Scan errors detected; file operations were not performed. If you accept the risks, please use --force."
        );
        return Ok(false);
    }

    let mut succeeded = 0usize;
    let mut failed = 0usize;
    for source in &report.invalid {
        match fs::remove_file(source) {
            Ok(()) => succeeded += 1,
            Err(error) => {
                eprintln!("Delete failed: {}: {}", scan::display_path(source), error);
                failed += 1;
            }
        }
    }
    println!("Deleted: {}, failed: {}", succeeded, failed);
    let mut registry_failed = false;
    if args.clean_registry {
        match registry::clean_invalid_cat_entries(&image_root, &report.invalid) {
            Ok(removed) => println!("Registry entries removed: {}", removed),
            Err(error) => {
                eprintln!("Registry cleanup failed: {error:#}");
                registry_failed = true;
            }
        }
    }
    Ok(!report.has_errors() && failed == 0 && !registry_failed)
}

/// Run the CatTrim command.
fn run(cli: Cli) -> Result<bool> {
    match cli.into_command() {
        Command::Scan(args) => run_scan(args),
        Command::Move(args) => run_move(args),
        Command::Copy(args) => run_copy(args),
        Command::Delete(args) => run_delete(args),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn copy_copies_files_without_overwriting_collisions() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("cattrim-copy-{}-{nonce}", std::process::id()));
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        let first = source.join("first.cat");
        let second = source.join("second.cat");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        fs::write(destination.join("second.cat"), b"existing").unwrap();

        let summary = copy_catalogs(&[first, second], &destination).unwrap();

        assert_eq!(summary, (1, 1));
        assert_eq!(fs::read(destination.join("first.cat")).unwrap(), b"first");
        assert_eq!(
            fs::read(destination.join("second.cat")).unwrap(),
            b"existing"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
