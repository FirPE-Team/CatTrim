mod catalog;
mod digest;
mod hashing;
mod scan;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use rayon::current_num_threads;
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Debug, Parser)]
#[command(
    name = "InvalidCertificate",
    about = "Find and remove CAT files that match no PE or INF in an offline image"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan an offline image and emit the invalid CAT paths.
    Scan(ScanArgs),
    /// Move invalid CAT files to a destination directory.
    Move(MoveArgs),
    /// Permanently delete invalid CAT files.
    Delete(DeleteArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(value_name = "IMAGE_ROOT")]
    image_root: PathBuf,
    #[arg(long, default_value_t = default_jobs(), value_parser = parse_jobs)]
    jobs: usize,
    #[arg(long, value_name = "PATH")]
    log: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct MoveArgs {
    #[arg(value_name = "IMAGE_ROOT")]
    image_root: PathBuf,
    #[arg(value_name = "DEST_DIR")]
    destination: PathBuf,
    #[arg(long, default_value_t = default_jobs(), value_parser = parse_jobs)]
    jobs: usize,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct DeleteArgs {
    #[arg(value_name = "IMAGE_ROOT")]
    image_root: PathBuf,
    #[arg(long, default_value_t = default_jobs(), value_parser = parse_jobs)]
    jobs: usize,
    #[arg(long)]
    force: bool,
}

fn parse_jobs(value: &str) -> Result<usize, String> {
    let jobs = value
        .parse::<usize>()
        .map_err(|_| "jobs must be a positive integer".to_owned())?;
    if jobs == 0 {
        Err("jobs must be greater than zero".to_owned())
    } else {
        Ok(jobs)
    }
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or_else(|_| current_num_threads().max(1))
}

fn canonical_image_root(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("invalid image root {}", path.display()))
}

fn print_diagnostics(report: &scan::ScanReport) {
    eprintln!(
        "CAT total: {}",
        report.cats.len() + report.parse_errors.len()
    );
    eprintln!("Valid CAT: {}", report.cats.len() - report.invalid.len());
    eprintln!("Invalid CAT: {}", report.invalid.len());
    eprintln!("Parse errors: {}", report.parse_errors.len());
    eprintln!(
        "PE: {}, INF: {}, ignored: {}",
        report.pe_count, report.inf_count, report.ignored_count
    );
    for (path, error) in &report.parse_errors {
        eprintln!("CAT parse error: {}: {}", path.display(), error);
    }
    for (path, error) in &report.hash_errors {
        eprintln!("Hash error: {}: {}", path.display(), error);
    }
}

fn run_scan(args: ScanArgs) -> Result<bool> {
    let image_root = canonical_image_root(&args.image_root)?;
    let report = scan::scan(&image_root, args.jobs)?;
    let text = scan::render_invalid_paths(&report.invalid);
    if let Some(log) = args.log {
        scan::write_log(&log, &text)?;
        eprintln!("CatLog: {}", log.canonicalize().unwrap_or(log).display());
    } else {
        scan::write_stdout(&text)?;
    }
    print_diagnostics(&report);
    Ok(!report.has_errors())
}

fn run_move(args: MoveArgs) -> Result<bool> {
    let image_root = canonical_image_root(&args.image_root)?;
    let report = scan::scan(&image_root, args.jobs)?;
    print_diagnostics(&report);
    if report.has_errors() && !args.force {
        eprintln!("Scan errors detected; file operations were not performed. If you accept the risks, please use --force.");
        return Ok(false);
    }

    fs::create_dir_all(&args.destination)
        .with_context(|| format!("create move destination {}", args.destination.display()))?;
    let destination = args.destination.canonicalize().unwrap_or(args.destination);
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    for source in &report.invalid {
        let target = destination.join(source.file_name().context("CAT has no file name")?);
        if target.exists() {
            eprintln!("Move skipped (target exists): {}", target.display());
            failed += 1;
            continue;
        }
        match fs::rename(source, &target) {
            Ok(()) => succeeded += 1,
            Err(error) => {
                eprintln!(
                    "Move failed: {} -> {}: {}",
                    source.display(),
                    target.display(),
                    error
                );
                failed += 1;
            }
        }
    }
    println!("Moved: {}, failed: {}", succeeded, failed);
    Ok(!report.has_errors() && failed == 0)
}

fn run_delete(args: DeleteArgs) -> Result<bool> {
    let image_root = canonical_image_root(&args.image_root)?;
    let report = scan::scan(&image_root, args.jobs)?;
    print_diagnostics(&report);
    if report.has_errors() && !args.force {
        eprintln!("Scan errors detected; file operations were not performed. If you accept the risks, please use --force.");
        return Ok(false);
    }

    let mut succeeded = 0usize;
    let mut failed = 0usize;
    for source in &report.invalid {
        match fs::remove_file(source) {
            Ok(()) => succeeded += 1,
            Err(error) => {
                eprintln!("Delete failed: {}: {}", source.display(), error);
                failed += 1;
            }
        }
    }
    println!("Deleted: {}, failed: {}", succeeded, failed);
    Ok(!report.has_errors() && failed == 0)
}

fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Move(args) => run_move(args),
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

    #[test]
    fn parses_subcommands_and_options() {
        let cli = Cli::try_parse_from(["InvalidCertificate", "scan", "image", "--log", "out.txt"])
            .unwrap();
        assert!(matches!(cli.command, Command::Scan(_)));

        let cli = Cli::try_parse_from(["InvalidCertificate", "move", "image", "dest", "--force"])
            .unwrap();
        assert!(matches!(cli.command, Command::Move(_)));

        let cli = Cli::try_parse_from(["InvalidCertificate", "delete", "image"]).unwrap();
        assert!(matches!(cli.command, Command::Delete(_)));
    }

    #[test]
    fn rejects_invalid_option_combinations() {
        assert!(Cli::try_parse_from(["InvalidCertificate", "move", "image"]).is_err());
        assert!(Cli::try_parse_from(["InvalidCertificate", "scan", "image", "--force"]).is_err());
        assert!(
            Cli::try_parse_from(["InvalidCertificate", "scan", "image", "--jobs", "0"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["InvalidCertificate", "move", "image", "dest", "--log", "x",])
                .is_err()
        );
    }
}
