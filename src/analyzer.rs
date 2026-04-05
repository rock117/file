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
    pub charset: Option<String>,
    pub extensions: Option<String>,
}

/// Analyze file with CLI options context
pub fn analyze_file_opts(path: &Path, args: &crate::Args) -> FileResult {
    let display_path = path.to_string_lossy().to_string();

    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let dp = path.display();
            return FileResult {
                path: dp.to_string(),
                description: format!("cannot open: {} ({})", dp, e),
                mime_type: None,
                charset: None,
                extensions: None,
            };
        }
    };

    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        let target = fs::read_link(path)
            .map(|t| t.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        // Follow symlink to get MIME type of target
        let target_mime = fs::metadata(path).ok().and_then(|m| {
            if m.file_type().is_dir() {
                Some("inode/directory".to_string())
            } else {
                None // will be determined by content analysis below if -L
            }
        });
        return FileResult {
            path: display_path,
            description: format!("symbolic link to '{}'", target),
            mime_type: target_mime,
            charset: None,
            extensions: None,
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_block_device() {
            return FileResult { path: display_path, description: "block special".to_string(), mime_type: Some("inode/blockdevice".to_string()), charset: None, extensions: None };
        }
        if file_type.is_char_device() {
            return FileResult { path: display_path, description: "character special".to_string(), mime_type: Some("inode/chardevice".to_string()), charset: None, extensions: None };
        }
        if file_type.is_fifo() {
            return FileResult { path: display_path, description: "fifo (named pipe)".to_string(), mime_type: Some("inode/fifo".to_string()), charset: None, extensions: None };
        }
        if file_type.is_socket() {
            return FileResult { path: display_path, description: "socket".to_string(), mime_type: Some("inode/socket".to_string()), charset: None, extensions: None };
        }
    }

    if file_type.is_dir() {
        return FileResult {
            path: display_path,
            description: "directory".to_string(),
            mime_type: Some("inode/directory".to_string()),
            charset: None,
            extensions: None,
        };
    }

    if metadata.len() == 0 {
        return FileResult {
            path: display_path,
            description: "empty".to_string(),
            mime_type: Some("application/x-empty".to_string()),
            charset: None,
            extensions: None,
        };
    }

    let data = match read_file_header(path) {
        Some(d) => d,
        None => {
            let dp = path.display();
            return FileResult { path: dp.to_string(), description: format!("cannot read: {}", dp), mime_type: None, charset: None, extensions: None };
        }
    };

    // Try uncompress if -z flag
    let uncompressed_data;
    let effective_data = if args.uncompress || args.uncompress_noreport {
        if let Some(decompressed) = try_decompress(&data) {
            uncompressed_data = decompressed;
            &uncompressed_data as &[u8]
        } else {
            &data as &[u8]
        }
    } else {
        &data as &[u8]
    };

    // Try magic number detection
    if let Some(match_result) = magic::identify_by_magic(effective_data) {
        let desc = if args.uncompress && !args.uncompress_noreport {
            format!("{} (compressed)", match_result.description)
        } else {
            match_result.description
        };
        return FileResult {
            path: display_path,
            description: desc,
            mime_type: Some(match_result.mime_type.clone()),
            charset: if match_result.mime_type.starts_with("text/") {
                Some("us-ascii".to_string())
            } else {
                Some("binary".to_string())
            },
            extensions: get_extensions_for_mime(&match_result.mime_type),
        };
    }

    // Check if it's text
    if text::is_text(effective_data) {
        let info = text::analyze_text(effective_data);
        let charset = detect_charset(&info);
        let enc_desc = text::format_encoding(&info.encoding, info.with_bom);

        // Try extension-based type identification
        if let Some(ext_match) = magic::guess_by_extension(path) {
            if ext_match.text_type {
                let mut parts = Vec::new();
                if !ext_match.description.is_empty() {
                    parts.push(ext_match.description);
                    parts.push(enc_desc);
                } else {
                    parts.push(enc_desc);
                }
                append_line_info(&mut parts, &info);
                return FileResult {
                    path: display_path,
                    description: parts.join(", "),
                    mime_type: Some(ext_match.mime_type.clone()),
                    charset: Some(charset),
                    extensions: get_extensions_for_mime(&ext_match.mime_type),
                };
            }
            return FileResult {
                path: display_path,
                description: ext_match.description,
                mime_type: Some(ext_match.mime_type.clone()),
                charset: Some(charset),
                extensions: get_extensions_for_mime(&ext_match.mime_type),
            };
        }

        // No known extension - use content heuristics
        let desc = text::format_text_description(&info);
        let mime = guess_mime_from_text(&info);
        return FileResult {
            path: display_path,
            description: desc,
            mime_type: mime,
            charset: Some(charset),
            extensions: None,
        };
    }

    // Binary: try extension as fallback
    if let Some(match_result) = magic::guess_by_extension(path) {
        return FileResult {
            path: display_path,
            description: match_result.description,
            mime_type: Some(match_result.mime_type.clone()),
            charset: Some("binary".to_string()),
            extensions: get_extensions_for_mime(&match_result.mime_type),
        };
    }

    FileResult {
        path: display_path,
        description: "data".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
        charset: Some("binary".to_string()),
        extensions: None,
    }
}

/// Legacy analyze_file without CLI context
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
                charset: None,
                extensions: None,
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
            charset: None,
            extensions: None,
        };
    }

    if file_type.is_dir() {
        return FileResult { path: display_path, description: "directory".to_string(), mime_type: Some("inode/directory".to_string()), charset: None, extensions: None };
    }

    if metadata.len() == 0 {
        return FileResult { path: display_path, description: "empty".to_string(), mime_type: Some("application/x-empty".to_string()), charset: None, extensions: None };
    }

    let data = match read_file_header(path) {
        Some(d) => d,
        None => {
            let dp = path.display();
            return FileResult { path: dp.to_string(), description: format!("cannot read: {}", dp), mime_type: None, charset: None, extensions: None };
        }
    };

    if let Some(match_result) = magic::identify_by_magic(&data) {
        return FileResult {
            path: display_path,
            description: match_result.description,
            mime_type: Some(match_result.mime_type),
            charset: Some("binary".to_string()),
            extensions: None,
        };
    }

    if text::is_text(&data) {
        let info = text::analyze_text(&data);
        let enc_desc = text::format_encoding(&info.encoding, info.with_bom);
        let charset = detect_charset(&info);

        if let Some(ext_match) = magic::guess_by_extension(path) {
            if ext_match.text_type {
                let mut parts = Vec::new();
                if !ext_match.description.is_empty() {
                    parts.push(ext_match.description);
                    parts.push(enc_desc);
                } else {
                    parts.push(enc_desc);
                }
                append_line_info(&mut parts, &info);
                return FileResult {
                    path: display_path,
                    description: parts.join(", "),
                    mime_type: Some(ext_match.mime_type),
                    charset: Some(charset),
                    extensions: None,
                };
            }
            return FileResult {
                path: display_path,
                description: ext_match.description,
                mime_type: Some(ext_match.mime_type),
                charset: Some(charset),
                extensions: None,
            };
        }

        let desc = text::format_text_description(&info);
        let mime = guess_mime_from_text(&info);
        return FileResult {
            path: display_path,
            description: desc,
            mime_type: mime,
            charset: Some(charset),
            extensions: None,
        };
    }

    if let Some(match_result) = magic::guess_by_extension(path) {
        return FileResult {
            path: display_path,
            description: match_result.description,
            mime_type: Some(match_result.mime_type),
            charset: Some("binary".to_string()),
            extensions: None,
        };
    }

    FileResult {
        path: display_path,
        description: "data".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
        charset: Some("binary".to_string()),
        extensions: None,
    }
}

fn detect_charset(info: &text::TextInfo) -> String {
    match info.encoding.as_str() {
        "ascii" => "us-ascii".to_string(),
        "utf-8" => "utf-8".to_string(),
        "utf-16le" => "utf-16le".to_string(),
        "utf-16be" => "utf-16be".to_string(),
        _ => "unknown-8bit".to_string(),
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

/// Try to decompress gzip/zlib/bzip2/xz/lz4/zstd data
fn try_decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    // gzip
    if data[0] == 0x1F && data[1] == 0x8B {
        use std::io::Read;
        let decoder = flate2::read::GzDecoder::new(data);
        let mut buf = Vec::new();
        if decoder.take(READ_SIZE as u64).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            return Some(buf);
        }
    }
    // zlib (deflate without gzip header)
    if data.len() > 2 {
        use std::io::Read;
        let decoder = flate2::read::ZlibDecoder::new(data);
        let mut buf = Vec::new();
        if decoder.take(READ_SIZE as u64).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            return Some(buf);
        }
    }
    None
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

fn get_extensions_for_mime(mime: &str) -> Option<String> {
    let exts = match mime {
        "image/png" => "png",
        "image/jpeg" => "jpeg/jpg/jpe/jfif",
        "image/gif" => "gif",
        "image/bmp" => "bmp/dib",
        "image/webp" => "webp",
        "image/tiff" => "tiff/tif",
        "image/svg+xml" => "svg/svgz",
        "image/x-icon" => "ico",
        "image/heif" => "heic/heif",
        "image/avif" => "avif",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/gzip" => "gz/gzip",
        "application/x-bzip2" => "bz2",
        "application/x-xz" => "xz",
        "application/x-7z-compressed" => "7z",
        "application/x-rar" => "rar",
        "application/x-tar" => "tar/gtar",
        "application/zstd" => "zst",
        "application/x-lz4" => "lz4",
        "application/java-vm" => "class",
        "application/wasm" => "wasm",
        "application/json" => "json",
        "text/html" => "html/htm",
        "text/xml" => "xml/xsl/xsd",
        "text/css" => "css",
        "text/javascript" => "js/jsm/mjs",
        "text/x-python" => "py/pyw",
        "text/rust" => "rs",
        "text/x-c" => "c/h",
        "text/x-c++" => "cpp/cc/cxx/hpp/hh/hxx",
        "text/x-java" => "java",
        "text/x-go" => "go",
        "text/x-ruby" => "rb",
        "text/x-php" => "php",
        "text/x-shellscript" => "sh/bash",
        "text/x-perl" => "pl/pm",
        "text/x-sql" => "sql",
        "text/markdown" => "md/markdown",
        "text/yaml" => "yaml/yml",
        "text/x-toml" => "toml",
        "text/csv" => "csv",
        "text/plain" => "txt/text/conf/def/list/log/in",
        "audio/mpeg" => "mp3/mpga",
        "audio/wav" => "wav/wave",
        "audio/flac" => "flac",
        "audio/ogg" => "ogg/oga",
        "audio/midi" => "mid/midi",
        "audio/aac" => "aac",
        "audio/mp4" => "m4a",
        "video/mp4" => "mp4/m4v",
        "video/avi" => "avi",
        "video/x-matroska" => "mkv/mka",
        "video/webm" => "webm",
        "video/quicktime" => "mov/qt",
        "video/mpeg" => "mpeg/mpg/mpe",
        "video/x-flv" => "flv",
        "video/3gpp" => "3gp",
        "font/ttf" => "ttf/ttc",
        "font/otf" => "otf",
        "font/woff" => "woff",
        "font/woff2" => "woff2",
        "application/x-dosexec" => "exe/dll/sys/drv/scr",
        "application/x-elf" => "so/o/elf",
        "application/x-mach-binary" => "dylib",
        "application/epub+zip" => "epub",
        "application/rtf" => "rtf",
        "application/x-bittorrent" => "torrent",
        _ => return None,
    };
    Some(exts.to_string())
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
            charset: Some("binary".to_string()),
            extensions: None,
        };
    }

    if let Some(match_result) = magic::identify_by_magic(&buf) {
        return FileResult {
            path: "/dev/stdin".to_string(),
            description: match_result.description,
            mime_type: Some(match_result.mime_type),
            charset: Some("binary".to_string()),
            extensions: None,
        };
    }

    if text::is_text(&buf) {
        let info = text::analyze_text(&buf);
        let desc = text::format_text_description(&info);
        let mime = guess_mime_from_text(&info);
        let charset = detect_charset(&info);
        return FileResult {
            path: "/dev/stdin".to_string(),
            description: desc,
            mime_type: mime,
            charset: Some(charset),
            extensions: None,
        };
    }

    FileResult {
        path: "/dev/stdin".to_string(),
        description: "data".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
        charset: Some("binary".to_string()),
        extensions: None,
    }
}
