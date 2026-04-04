mod magic;
mod text;
mod analyzer;

use std::path::PathBuf;

use clap::Parser;

/// Determine file type - a Windows port of the Linux `file` command.
#[derive(Parser, Debug)]
#[command(name = "file", version, about = "Determine type of FILEs")]
struct Args {
    /// Files to examine
    files: Vec<String>,

    /// Brief mode: show MIME type only
    #[arg(short = 'i', long = "mime-type")]
    mime_type: bool,

    /// Output MIME encoding
    #[arg(short = 'I', long = "mime-encoding")]
    mime_encoding: bool,

    /// Don't follow symbolic links
    #[arg(short = 'h', long = "no-dereference")]
    no_dereference: bool,

    /// Follow symbolic links
    #[arg(short = 'L', long = "dereference")]
    dereference: bool,

    /// Read file names from FILE (one per line)
    #[arg(short = 'f', long = "files-from")]
    files_from: Option<String>,

    /// Read from stdin as well as named files
    #[arg(short = 's', long = "special-files")]
    special_files: bool,

    /// Recursive directory traversal
    #[arg(short = 'r', long = "recursive")]
    recursive: bool,

    /// Output debug information
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// Separator between filename and description
    #[arg(short = 'F', long = "separator", default_value = ": ")]
    separator: String,

    /// Do not prepend filenames to output
    #[arg(short = 'b', long = "brief")]
    brief: bool,

    /// Verbose mode
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    let mut files = args.files.clone();

    // Read file list from --files-from
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
            }
        } else {
            let result = if args.dereference {
                let real_path = match std::fs::canonicalize(&path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("file: cannot open '{}': {}", file_arg, e);
                        had_error = true;
                        continue;
                    }
                };
                analyzer::analyze_file(&real_path)
            } else {
                analyzer::analyze_file(&path)
            };

            if result.description.starts_with("cannot open")
                || result.description.starts_with("cannot read")
            {
                had_error = true;
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
            let result = analyzer::analyze_file(&path);
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
    if args.mime_type || args.mime_encoding {
        let mime = result.mime_type.as_deref().unwrap_or("application/octet-stream");
        if args.brief {
            println!("{}", mime);
        } else {
            println!("{}{}{}", result.path, args.separator, mime);
        }
        return;
    }

    if args.brief {
        println!("{}", result.description);
    } else {
        println!("{}{}{}", result.path, args.separator, result.description);
    }
}
