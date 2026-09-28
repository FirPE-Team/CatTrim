use clap::{Args, Parser, Subcommand, ValueEnum};
use rayon::current_num_threads;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "CatTrim",
    about = "Trim unused Windows catalog files from an offline image"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub(crate) fn parse() -> Self {
        <Self as Parser>::parse()
    }

    pub(crate) fn into_command(self) -> Command {
        self.command
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Scan an offline image and emit the invalid CAT paths.
    Scan(ScanArgs),
    /// Move invalid CAT files to a destination directory.
    Move(MoveArgs),
    /// Copy valid or invalid CAT files to a destination directory.
    Copy(CopyArgs),
    /// Permanently delete invalid CAT files.
    Delete(DeleteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    /// Path to the offline image root.
    #[arg(value_name = "IMAGE_ROOT")]
    pub(crate) image_root: PathBuf,
    /// Number of parallel jobs to use.
    #[arg(long, default_value_t = default_jobs(), value_parser = parse_jobs)]
    pub(crate) jobs: usize,
    /// Log to a file.
    #[arg(long, value_name = "PATH")]
    pub(crate) log: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct MoveArgs {
    /// Path to the offline image root.
    #[arg(value_name = "IMAGE_ROOT")]
    pub(crate) image_root: PathBuf,
    /// Destination directory for invalid CAT files.
    #[arg(value_name = "DEST_DIR")]
    pub(crate) destination: PathBuf,
    /// Number of parallel jobs to use.
    #[arg(long, default_value_t = default_jobs(), value_parser = parse_jobs)]
    pub(crate) jobs: usize,
    /// Force move invalid CAT files.
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CopyArgs {
    /// Path to the offline image root.
    #[arg(value_name = "IMAGE_ROOT")]
    pub(crate) image_root: PathBuf,
    /// Destination directory for the selected CAT files.
    #[arg(value_name = "DEST_DIR")]
    pub(crate) destination: PathBuf,
    /// Number of parallel jobs to use.
    #[arg(long, default_value_t = default_jobs(), value_parser = parse_jobs)]
    pub(crate) jobs: usize,
    /// Select valid or invalid CAT files.
    #[arg(long, value_enum, default_value_t = CatSelection::Valid)]
    pub(crate) select: CatSelection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CatSelection {
    Valid,
    Invalid,
}

#[derive(Debug, Args)]
pub(crate) struct DeleteArgs {
    /// Path to the offline image root.
    #[arg(value_name = "IMAGE_ROOT")]
    pub(crate) image_root: PathBuf,
    /// Number of parallel jobs to use.
    #[arg(long, default_value_t = default_jobs(), value_parser = parse_jobs)]
    pub(crate) jobs: usize,
    /// Force delete invalid CAT files.
    #[arg(long)]
    pub(crate) force: bool,
    /// Remove CBS package entries associated with invalid CAT files.
    #[arg(long)]
    pub(crate) clean_registry: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subcommands_and_options() {
        let cli = Cli::try_parse_from(["CatTrim", "scan", "image", "--log", "out.txt"]).unwrap();
        assert!(matches!(cli.command, Command::Scan(_)));

        let cli = Cli::try_parse_from(["CatTrim", "move", "image", "dest", "--force"]).unwrap();
        assert!(matches!(cli.command, Command::Move(_)));

        let cli = Cli::try_parse_from(["CatTrim", "copy", "image", "dest"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Copy(CopyArgs {
                select: CatSelection::Valid,
                ..
            })
        ));

        let cli = Cli::try_parse_from(["CatTrim", "copy", "image", "dest", "--select", "invalid"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Command::Copy(CopyArgs {
                select: CatSelection::Invalid,
                ..
            })
        ));

        let cli = Cli::try_parse_from(["CatTrim", "delete", "image"]).unwrap();
        assert!(matches!(cli.command, Command::Delete(_)));

        let cli = Cli::try_parse_from(["CatTrim", "delete", "image", "--clean-registry"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Delete(DeleteArgs {
                clean_registry: true,
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_option_combinations() {
        assert!(Cli::try_parse_from(["CatTrim", "move", "image"]).is_err());
        assert!(Cli::try_parse_from(["CatTrim", "copy", "image"]).is_err());
        assert!(Cli::try_parse_from(["CatTrim", "extract", "image", "dest"]).is_err());
        assert!(Cli::try_parse_from(["CatTrim", "scan", "image", "--force"]).is_err());
        assert!(Cli::try_parse_from(["CatTrim", "scan", "image", "--jobs", "0"]).is_err());
        assert!(Cli::try_parse_from(["CatTrim", "move", "image", "dest", "--log", "x"]).is_err());
        assert!(Cli::try_parse_from(["CatTrim", "copy", "image", "dest", "--force"]).is_err());
        assert!(
            Cli::try_parse_from(["CatTrim", "copy", "image", "dest", "--select", "unknown",])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["CatTrim", "move", "image", "dest", "--select", "valid",])
                .is_err()
        );
        assert!(Cli::try_parse_from(["CatTrim", "delete", "image", "--select", "valid",]).is_err());
    }
}
