/// Core file analyzer - combines magic detection, text analysis, and filesystem checks.

use std::fs;
use std::path::Path;

use crate::magic;
use crate::text;

const READ_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub struct FileResult {
    pub path: String,
    pub description: String,
    pub mime_type: Option<String>,
}

pub fn analyze_file(path: &Path) -> FileResult {
    let display_path = path.to_string_lossy().to_string();

    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let dp = path.display();
            return FileResult {
                path: dp.to_string(),
                description: format!("cannot open: {} ({})", dp, e),
                mime_type: None,
            };
        }
    };

    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        let target = fs::read_link(path)
            .map(|t| t.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        return FileResult {
            path: display_path,
            description: format!("symbolic link to '{}'", target),
            mime_type: None,
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_block_device() {
            return FileResult { path: display_path, description: "block special".to_string(), mime_type: None };
        }
        if file_type.is_char_device() {
            return FileResult { path: display_path, description: "character special".to_string(), mime_type: None };
        }
        if file_type.is_fifo() {
            return FileResult { path: display_path, description: "fifo (named pipe)".to_string(), mime_type: None };
        }
        if file_type.is_socket() {
            return FileResult { path: display_path, description: "socket".to_string(), mime_type: None };
        }
    }

    if file_type.is_dir() {
        return FileResult { path: display_path, description: "directory".to_string(), mime_type: None };
    }

    if metadata.len() == 0 {
        return FileResult { path: display_path, description: "empty".to_string(), mime_type: None };
    }

    let data = match read_file_header(path) {
        Some(d) => d,
        None => {
            let dp = path.display();
            return FileResult { path: dp.to_string(), description: format!("cannot read: {}", dp), mime_type: None };
        }
    };

    // Try magic number detection first
    if let Some(match_result) = magic::identify_by_magic(&data) {
        return FileResult {
            path: display_path,
            description: match_result.description,
            mime_type: Some(match_result.mime_type),
        };
    }

    // Check if it's text
    if text::is_text(&data) {
        // Analyze encoding from content
        let info = text::analyze_text(&data);
        let enc_desc = text::format_encoding(&info.encoding, info.with_bom);

        // Try extension-based type identification
        if let Some(ext_match) = magic::guess_by_extension(path) {
            if ext_match.text_type {
                // Combine type name + encoding + line ending info
                let mut parts = Vec::new();
                if !ext_match.description.is_empty() {
                    parts.push(ext_match.description);
                    parts.push(enc_desc);
                } else {
                    // Plain text (e.g. .txt) - just show encoding
                    parts.push(enc_desc);
                }
                append_line_info(&mut parts, &info);
                return FileResult {
                    path: display_path,
                    description: parts.join(", "),
                    mime_type: Some(ext_match.mime_type),
                };
            }
            // Non-text extension match (shouldn't normally reach here for text files)
            return FileResult {
                path: display_path,
                description: ext_match.description,
                mime_type: Some(ext_match.mime_type),
            };
        }

        // No known extension - use content heuristics
        let desc = text::format_text_description(&info);
        let mime = guess_mime_from_text(&info);
        return FileResult {
            path: display_path,
            description: desc,
            mime_type: mime,
        };
    }

    // Binary: try extension as fallback
    if let Some(match_result) = magic::guess_by_extension(path) {
        return FileResult {
            path: display_path,
            description: match_result.description,
            mime_type: Some(match_result.mime_type),
        };
    }

    FileResult {
        path: display_path,
        description: "data".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
    }
}

fn append_line_info(parts: &mut Vec<String>, info: &text::TextInfo) {
    match info.line_ending.as_str() {
        "CRLF" => parts.push("with CRLF line terminators".to_string()),
        "CR" => parts.push("with CR line terminators".to_string()),
        "no line terminators" => parts.push("with no line terminators".to_string()),
        "mixed" => parts.push("with mixed line terminators".to_string()),
        _ => {}
    }
    if info.has_long_lines {
        parts.push("with very long lines".to_string());
    }
}

fn read_file_header(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let file_size = file.metadata().ok()?.len() as usize;
    let read_len = file_size.min(READ_SIZE);
    let mut buf = vec![0u8; read_len];
    match file.read_exact(&mut buf) {
        Ok(()) => Some(buf),
        Err(_) => {
            let mut file = fs::File::open(path).ok()?;
            let bytes_read = file.read(&mut buf).ok()?;
            buf.truncate(bytes_read);
            if buf.is_empty() { None } else { Some(buf) }
        }
    }
}

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

pub fn analyze_stdin() -> FileResult {
    use std::io::Read;
    let mut buf = Vec::new();
    let stdin = std::io::stdin();
    let handle = stdin.lock();
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
        };
    }

    if let Some(match_result) = magic::identify_by_magic(&buf) {
        return FileResult {
            path: "/dev/stdin".to_string(),
            description: match_result.description,
            mime_type: Some(match_result.mime_type),
        };
    }

    if text::is_text(&buf) {
        let info = text::analyze_text(&buf);
        let desc = text::format_text_description(&info);
        let mime = guess_mime_from_text(&info);
        return FileResult {
            path: "/dev/stdin".to_string(),
            description: desc,
            mime_type: mime,
        };
    }

    FileResult {
        path: "/dev/stdin".to_string(),
        description: "data".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
    }
}
