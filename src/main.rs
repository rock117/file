mod magic;
mod text;
mod analyzer;

use std::path::PathBuf;

use clap::{CommandFactory, Parser};

/// Determine file type - a Windows port of the Linux `file` command.
#[derive(Parser, Debug)]
#[command(name = "file", version, about = "Determine type of FILEs", disable_help_flag = true)]
struct Args {
    /// Files to examine
    files: Vec<String>,

    /// Output MIME type string (e.g. 'text/plain; charset=us-ascii')
    #[arg(short = 'i', long = "mime")]
    mime: bool,

    /// Output only the MIME type
    #[arg(long = "mime-type")]
    mime_type: bool,

    /// Output only the MIME encoding
    #[arg(long = "mime-encoding")]
    mime_encoding: bool,

    /// Output a slash-separated list of valid extensions
    #[arg(long = "extension")]
    extension: bool,

    /// Don't follow symbolic links
    #[arg(short = 'h', long = "no-dereference")]
    no_dereference: bool,

    /// Follow symbolic links
    #[arg(short = 'L', long = "dereference")]
    dereference: bool,

    /// Read file names from FILE (one per line)
    #[arg(short = 'f', long = "files-from")]
    files_from: Option<String>,

    /// Read special files (block/char devices)
    #[arg(short = 's', long = "special-files")]
    special_files: bool,

    /// Recursive directory traversal
    #[arg(long = "recursive")]
    recursive: bool,

    /// Output debug information to stderr
    #[arg(short = 'd')]
    debug: bool,

    /// Separator between filename and description
    #[arg(short = 'F', long = "separator", default_value = ": ")]
    separator: String,

    /// Do not prepend filenames to output
    #[arg(short = 'b', long = "brief")]
    brief: bool,

    /// Don't pad filenames
    #[arg(short = 'N', long = "no-pad")]
    no_pad: bool,

    /// Flush stdout after each file
    #[arg(short = 'n', long = "no-buffer")]
    no_buffer: bool,

    /// On filesystem errors, issue error and exit (instead of continuing)
    #[arg(short = 'E')]
    exit_on_error: bool,

    /// Don't stop at first match, keep going
    #[arg(short = 'k', long = "keep-going")]
    keep_going: bool,

    /// Don't translate unprintable characters to \ooo
    #[arg(short = 'r', long = "raw")]
    raw: bool,

    /// Preserve access time of files
    #[arg(short = 'p', long = "preserve-date")]
    preserve_date: bool,

    /// Look inside compressed files
    #[arg(short = 'z', long = "uncompress")]
    uncompress: bool,

    /// Look inside compressed files, report only contents
    #[arg(short = 'Z', long = "uncompress-noreport")]
    uncompress_noreport: bool,

    /// Exclude the named test (apptype, ascii, encoding, compress, elf, json, soft, tar, text, tokens)
    #[arg(short = 'e', long = "exclude", value_name = "TESTNAME")]
    exclude: Vec<String>,

    /// Output a null character after filename (for use with xargs -0)
    #[arg(short = '0', long = "print0")]
    print0: bool,

    /// Set parameter limits (name=value, e.g. bytes=1M, elf_phnum=2K)
    #[arg(short = 'P', long = "parameter", value_name = "NAME=VALUE")]
    parameter: Vec<String>,

    /// Print help information
    #[arg(long = "help")]
    help: bool,
}

#[derive(Clone, Copy)]
enum OutputMode {
    Normal,
    Mime,
    MimeType,
    MimeEncoding,
    Extension,
}

impl OutputMode {
    fn from_args(args: &Args) -> Self {
        if args.extension { Self::Extension }
        else if args.mime { Self::Mime }
        else if args.mime_type { Self::MimeType }
        else if args.mime_encoding { Self::MimeEncoding }
        else { Self::Normal }
    }

    fn format_value(&self, result: &analyzer::FileResult) -> String {
        match self {
            Self::Normal => result.description.clone(),
            Self::Extension => result.extensions.as_deref().unwrap_or("???").to_string(),
            Self::MimeType => result.mime_type.as_deref().unwrap_or("application/octet-stream").to_string(),
            Self::MimeEncoding => result.charset.as_deref().unwrap_or("binary").to_string(),
            Self::Mime => {
                let mime = result.mime_type.as_deref().unwrap_or("application/octet-stream");
                let charset = result.charset.as_deref().unwrap_or("binary");
                if charset == "binary" {
                    mime.to_string()
                } else {
                    format!("{}; charset={}", mime, charset)
                }
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    if args.help {
        let mut cmd = Args::command();
        let _ = cmd.print_help();
        println!();
        return;
    }

    // Parse parameters
    for p in &args.parameter {
        if !p.contains('=') {
            eprintln!("file: invalid parameter '{}': expected name=value", p);
            std::process::exit(1);
        }
    }

    // Handle -f - (read filenames from stdin, streaming)
    if args.files_from.as_deref() == Some("-") {
        use std::io::{BufRead, Write};
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut stdout_lock = stdout.lock();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    let trimmed = l.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let path = PathBuf::from(trimmed);
                    let result = if args.dereference {
                        std::fs::canonicalize(&path)
                            .map(|p| analyzer::analyze_file_opts(&p, &args))
                            .unwrap_or_else(|_| analyzer::analyze_file_opts(&path, &args))
                    } else {
                        analyzer::analyze_file_opts(&path, &args)
                    };
                    print_result(&result, &args);
                    let _ = stdout_lock.flush();
                }
                Err(_) => break,
            }
        }
        return;
    }

    let mut files = args.files.clone();

    // Read file list from --files-from (file path, not stdin)
    if let Some(ref from_file) = args.files_from {
        match std::fs::read_to_string(from_file) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        files.push(trimmed.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("file: cannot open '{}': {}", from_file, e);
                std::process::exit(1);
            }
        }
    }

    // Handle stdin or no arguments
    if files.is_empty() || (files.len() == 1 && files[0] == "-") {
        let result = analyzer::analyze_stdin();
        print_result(&result, &args);
        return;
    }

    let mut had_error = false;

    for file_arg in &files {
        let path = PathBuf::from(file_arg);

        if args.recursive && path.is_dir() {
            if !process_recursive(&path, &args) {
                had_error = true;
                if args.exit_on_error {
                    std::process::exit(1);
                }
            }
        } else {
            // Preserve access time if requested
            let atime: Option<std::time::SystemTime> = if args.preserve_date {
                std::fs::metadata(&path).ok().and_then(|m| m.accessed().ok())
            } else {
                None
            };

            let result = if args.dereference {
                let real_path = match std::fs::canonicalize(&path) {
                    Ok(p) => p,
                    Err(e) => {
                        if args.exit_on_error {
                            eprintln!("file: cannot open '{}': {}", file_arg, e);
                            std::process::exit(1);
                        }
                        had_error = true;
                        continue;
                    }
                };
                analyzer::analyze_file_opts(&real_path, &args)
            } else {
                analyzer::analyze_file_opts(&path, &args)
            };

            // Restore access time
            if let Some(at) = atime {
                let _ = filetime::set_file_atime(&path, filetime::FileTime::from_system_time(at));
            }

            if result.description.starts_with("cannot open")
                || result.description.starts_with("cannot read")
            {
                had_error = true;
                if args.exit_on_error {
                    std::process::exit(1);
                }
            }
            print_result(&result, &args);
        }
    }

    if had_error {
        std::process::exit(1);
    }
}

fn process_recursive(dir: &std::path::Path, args: &Args) -> bool {
    let mut all_ok = true;
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            eprintln!("file: cannot read directory '{}': {}", dir.display(), e);
            return false;
        }
    };
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                eprintln!("file: cannot stat '{}': {}", path.display(), e);
                all_ok = false;
                continue;
            }
        };

        if file_type.is_dir() {
            if !process_recursive(&path, args) {
                all_ok = false;
            }
        } else {
            let result = analyzer::analyze_file_opts(&path, args);
            if result.description.starts_with("cannot open")
                || result.description.starts_with("cannot read")
            {
                all_ok = false;
            }
            print_result(&result, args);
        }
    }
    all_ok
}

fn print_result(result: &analyzer::FileResult, args: &Args) {
    let mode = OutputMode::from_args(args);
    let value = mode.format_value(result);

    if args.brief {
        println!("{}", value);
    } else {
        print!("{}{}{}", result.path, args.separator, value);
        if args.print0 {
            print!("\0");
        }
        println!();
    }
    if args.no_buffer {
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}
