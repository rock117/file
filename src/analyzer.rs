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

impl FileResult {
    fn error(path: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            description: msg.into(),
            mime_type: None,
            charset: None,
            extensions: None,
        }
    }

    fn special(path: impl Into<String>, desc: impl Into<String>, mime: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            description: desc.into(),
            mime_type: Some(mime.into()),
            charset: None,
            extensions: None,
        }
    }

    fn unknown_data(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            description: "data".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            charset: Some("binary".to_string()),
            extensions: None,
        }
    }

    fn from_magic(path: impl Into<String>, desc: String, mime: String, is_text: bool) -> Self {
        Self {
            path: path.into(),
            description: desc,
            charset: Some(if is_text { "us-ascii".to_string() } else { "binary".to_string() }),
            extensions: get_extensions_for_mime(&mime),
            mime_type: Some(mime),
        }
    }
}

/// Analyze file with CLI options context
pub fn analyze_file_opts(path: &Path, args: &crate::Args) -> FileResult {
    let display_path = path.to_string_lossy().to_string();

    // Filesystem-level classification
    if let Some(result) = classify_by_filesystem(path, &display_path) {
        return result;
    }

    // Read file header
    let data = match read_file_header(path) {
        Some(d) => d,
        None => return FileResult::error(display_path, format!("cannot read: {}", path.display())),
    };

    let effective_data = get_effective_data(&data, args);
    analyze_content(path, &display_path, &*effective_data, args)
}

/// Filesystem-level checks: symlinks, special files, directories, empty files
fn classify_by_filesystem(path: &Path, display_path: &str) -> Option<FileResult> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return Some(FileResult::error(
                display_path,
                format!("cannot open: {} ({})", display_path, e),
            ));
        }
    };

    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        let target = fs::read_link(path)
            .map(|t| t.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let target_mime = fs::metadata(path).ok().and_then(|m| {
            if m.file_type().is_dir() {
                Some("inode/directory".to_string())
            } else {
                None
            }
        });
        return Some(FileResult {
            path: display_path.to_string(),
            description: format!("symbolic link to '{}'", target),
            mime_type: target_mime,
            charset: None,
            extensions: None,
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_block_device() {
            return Some(FileResult::special(display_path, "block special", "inode/blockdevice"));
        }
        if file_type.is_char_device() {
            return Some(FileResult::special(display_path, "character special", "inode/chardevice"));
        }
        if file_type.is_fifo() {
            return Some(FileResult::special(display_path, "fifo (named pipe)", "inode/fifo"));
        }
        if file_type.is_socket() {
            return Some(FileResult::special(display_path, "socket", "inode/socket"));
        }
    }

    if file_type.is_dir() {
        return Some(FileResult::special(display_path, "directory", "inode/directory"));
    }

    if metadata.len() == 0 {
        return Some(FileResult::special(display_path, "empty", "application/x-empty"));
    }

    None
}

/// Get effective data (possibly decompressed) based on CLI flags
fn get_effective_data<'a>(data: &'a [u8], args: &crate::Args) -> std::borrow::Cow<'a, [u8]> {
    if args.uncompress || args.uncompress_noreport {
        if let Some(decompressed) = try_decompress(data) {
            return std::borrow::Cow::Owned(decompressed);
        }
    }
    std::borrow::Cow::Borrowed(data)
}

/// Content-level analysis: magic detection, text analysis, extension fallback
fn analyze_content(path: &Path, display_path: &str, data: &[u8], args: &crate::Args) -> FileResult {
    // Magic number detection
    if let Some(match_result) = magic::identify_by_magic(data) {
        let desc = if args.uncompress && !args.uncompress_noreport {
            format!("{} (compressed)", match_result.description)
        } else {
            match_result.description
        };
        let is_text = match_result.mime_type.starts_with("text/");
        return FileResult::from_magic(display_path, desc, match_result.mime_type, is_text);
    }

    // Text analysis
    if text::is_text(data) {
        return analyze_text_content(path, display_path, data);
    }

    // Binary: try extension as fallback
    if let Some(match_result) = magic::guess_by_extension(path) {
        let mime = match_result.mime_type;
        return FileResult {
            path: display_path.to_string(),
            description: match_result.description,
            extensions: get_extensions_for_mime(&mime),
            mime_type: Some(mime),
            charset: Some("binary".to_string()),
        };
    }

    FileResult::unknown_data(display_path)
}

/// Analyze text file content
fn analyze_text_content(path: &Path, display_path: &str, data: &[u8]) -> FileResult {
    let info = text::analyze_text(data);
    let charset = detect_charset(&info);
    let enc_desc = text::format_encoding(&info.encoding, info.with_bom);

    // Try extension-based type identification
    if let Some(ext_match) = magic::guess_by_extension(path) {
        let mime = ext_match.mime_type;
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
                path: display_path.to_string(),
                description: parts.join(", "),
                extensions: get_extensions_for_mime(&mime),
                mime_type: Some(mime),
                charset: Some(charset),
            };
        }
        return FileResult {
            path: display_path.to_string(),
            description: ext_match.description,
            extensions: get_extensions_for_mime(&mime),
            mime_type: Some(mime),
            charset: Some(charset),
        };
    }

    // No known extension - use content heuristics
    let desc = text::format_text_description(&info);
    let mime = guess_mime_from_text(&info);
    FileResult {
        path: display_path.to_string(),
        description: desc,
        mime_type: mime,
        charset: Some(charset),
        extensions: None,
    }
}

fn detect_charset(info: &text::TextInfo) -> String {
    info.encoding.charset_name().to_string()
}

fn append_line_info(parts: &mut Vec<String>, info: &text::TextInfo) {
    if let Some(desc) = info.line_ending.description() {
        parts.push(desc.to_string());
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

/// Try to decompress gzip/zlib data
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
        return FileResult::from_magic(
            "/dev/stdin",
            match_result.description,
            match_result.mime_type,
            false,
        );
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

    FileResult::unknown_data("/dev/stdin")
}
