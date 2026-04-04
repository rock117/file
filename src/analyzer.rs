/// Core file analyzer - combines magic detection, text analysis, and filesystem checks.

use std::fs;
use std::path::Path;

use crate::magic;
use crate::text;

const READ_SIZE: usize = 64 * 1024; // Read first 64KB for magic detection

#[derive(Debug)]
pub struct FileResult {
    pub path: String,
    pub description: String,
    pub mime_type: Option<String>,
    pub is_text: bool,
}

/// Analyze a single file
pub fn analyze_file(path: &Path) -> FileResult {
    let display_path = path.to_string_lossy().to_string();

    // Check if it's a special file
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let dp = path.display();
            return FileResult {
                path: dp.to_string(),
                description: format!("cannot open: {} ({})", dp, e),
                mime_type: None,
                is_text: false,
            };
        }
    };

    let file_type = metadata.file_type();

    // Handle special file types
    if file_type.is_symlink() {
        let target = fs::read_link(path)
            .map(|t| t.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        return FileResult {
            path: display_path,
            description: format!("symbolic link to '{}'", target),
            mime_type: None,
            is_text: false,
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_block_device() {
            return FileResult {
                path: display_path,
                description: "block special".to_string(),
                mime_type: None,
                is_text: false,
            };
        }
        if file_type.is_char_device() {
            return FileResult {
                path: display_path,
                description: "character special".to_string(),
                mime_type: None,
                is_text: false,
            };
        }
        if file_type.is_fifo() {
            return FileResult {
                path: display_path,
                description: "fifo (named pipe)".to_string(),
                mime_type: None,
                is_text: false,
            };
        }
        if file_type.is_socket() {
            return FileResult {
                path: display_path,
                description: "socket".to_string(),
                mime_type: None,
                is_text: false,
            };
        }
    }

    if file_type.is_dir() {
        return FileResult {
            path: display_path,
            description: "directory".to_string(),
            mime_type: None,
            is_text: false,
        };
    }

    // Empty file
    if metadata.len() == 0 {
        return FileResult {
            path: display_path,
            description: "empty".to_string(),
            mime_type: None,
            is_text: true,
        };
    }

    // Read file header for magic detection
    let data = match read_file_header(path) {
        Some(d) => d,
        None => {
            let dp = path.display();
            return FileResult {
                path: dp.to_string(),
                description: format!("cannot read: {}", dp),
                mime_type: None,
                is_text: false,
            };
        }
    };

    // Try magic number detection first
    if let Some(match_result) = magic::identify_by_magic(&data) {
        // Check if we should add more details for text files identified by magic
        let mut desc = match_result.description.clone();

        // For some formats, add size info
        let size_str = format!(" ({})", text::format_size(metadata.len()));
        if desc.contains("image data") || desc.contains("compressed") || desc.contains("archive") {
            desc = format!("{}{}", desc, size_str);
        }

        return FileResult {
            path: display_path,
            description: desc,
            mime_type: Some(match_result.mime_type),
            is_text: false,
        };
    }

    // Not identified by magic - check if it's text
    if text::is_text(&data) {
        // For text files, prefer extension-based identification when available
        // (source code files are better identified by extension than content heuristics)
        if let Some(ext_match) = magic::guess_by_extension(path) {
            let size_str = format!(" ({})", text::format_size(metadata.len()));
            return FileResult {
                path: display_path,
                description: format!("{}{}", ext_match.description, size_str),
                mime_type: Some(ext_match.mime_type),
                is_text: true,
            };
        }

        // No known extension - use content analysis
        let info = text::analyze_text(&data);
        let desc = text::format_text_description(&info, path);
        let mime = guess_mime_from_text(&info);

        return FileResult {
            path: display_path,
            description: desc,
            mime_type: mime,
            is_text: true,
        };
    }

    // Try extension-based identification as fallback
    if let Some(match_result) = magic::guess_by_extension(path) {
        let size_str = format!(" ({})", text::format_size(metadata.len()));
        return FileResult {
            path: display_path,
            description: format!("{}{}", match_result.description, size_str),
            mime_type: Some(match_result.mime_type),
            is_text: false,
        };
    }

    // Unknown binary file
    FileResult {
        path: display_path,
        description: format!("data ({})", text::format_size(metadata.len())),
        mime_type: Some("application/octet-stream".to_string()),
        is_text: false,
    }
}

/// Read the first READ_SIZE bytes of a file
fn read_file_header(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let file_size = file.metadata().ok()?.len() as usize;
    let read_len = file_size.min(READ_SIZE);
    let mut buf = vec![0u8; read_len];
    // Try exact read first; fall back to partial read
    match file.read_exact(&mut buf) {
        Ok(()) => Some(buf),
        Err(_) => {
            // File might be smaller than expected or read error
            let mut file = fs::File::open(path).ok()?;
            let bytes_read = file.read(&mut buf).ok()?;
            buf.truncate(bytes_read);
            if buf.is_empty() { None } else { Some(buf) }
        }
    }
}

/// Guess MIME type from text analysis results
fn guess_mime_from_text(info: &text::TextInfo) -> Option<String> {
    if let Some(ref lang) = info.language_hint {
        let mime = match lang.as_str() {
            "HTML document" => "text/html",
            "XML document" => "text/xml",
            "JSON data" => "application/json",
            "YAML document" => "text/yaml",
            "TOML document" => "text/x-toml",
            "SQL" => "text/x-sql",
            "Python script" => "text/x-python",
            "shell script" => "text/x-shellscript",
            "Perl script" => "text/x-perl",
            "Ruby script" => "text/x-ruby",
            "PHP script" => "text/x-php",
            "Java source" => "text/x-java",
            "C source" | "C++ source" => "text/x-c",
            "Rust source" => "text/rust",
            "Go source" => "text/x-go",
            "Markdown document" => "text/markdown",
            "Makefile" => "text/x-makefile",
            "Dockerfile" => "text/x-dockerfile",
            "INI configuration" => "text/plain",
            "diff/patch" => "text/x-diff",
            "DOS batch" => "text/x-msdos-batch",
            "PowerShell script" => "text/x-powershell",
            _ => "text/plain",
        };
        return Some(mime.to_string());
    }
    Some("text/plain".to_string())
}

/// Read from stdin (for `file -` usage)
pub fn analyze_stdin() -> FileResult {
    use std::io::Read;
    let mut buf = Vec::new();
    let stdin = std::io::stdin();
    let handle = stdin.lock();
    // Read up to READ_SIZE bytes
    let limited = handle.take(READ_SIZE as u64);
    for byte in limited.bytes() {
        match byte {
            Ok(b) => buf.push(b),
            Err(_) => break,
        }
    }

    if buf.is_empty() {
        return FileResult {
            path: "/dev/stdin".to_string(),
            description: "empty".to_string(),
            mime_type: None,
            is_text: true,
        };
    }

    // Try magic detection
    if let Some(match_result) = magic::identify_by_magic(&buf) {
        return FileResult {
            path: "/dev/stdin".to_string(),
            description: match_result.description,
            mime_type: Some(match_result.mime_type),
            is_text: false,
        };
    }

    // Check if text
    if text::is_text(&buf) {
        let info = text::analyze_text(&buf);
        let mime = guess_mime_from_text(&info);
        let mut parts = Vec::new();
        if let Some(ref lang) = info.language_hint {
            parts.push(lang.clone());
        }
        parts.push(format!("{} Unicode text", info.encoding));
        if info.line_ending == "CRLF" {
            parts.push("with CRLF line terminators".to_string());
        } else if info.line_ending == "no line terminators" {
            parts.push("with no line terminators".to_string());
        }
        return FileResult {
            path: "/dev/stdin".to_string(),
            description: parts.join(", "),
            mime_type: mime,
            is_text: true,
        };
    }

    FileResult {
        path: "/dev/stdin".to_string(),
        description: "data".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
        is_text: false,
    }
}
