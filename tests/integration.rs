use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn file_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_file"))
}

fn run(args: &[&str]) -> (String, String, bool) {
    let output = Command::new(file_bin())
        .args(args)
        .output()
        .expect("failed to run file");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn create_temp_file(name: &str, content: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join("file_cmd_test");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn create_temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("file_cmd_test").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---- Normal output ----

#[test]
fn test_ascii_text_file() {
    let path = create_temp_file("ascii.txt", b"hello world\n");
    let (out, _, _) = run(&[path.to_str().unwrap()]);
    assert!(out.contains("ASCII text"));
}

#[test]
fn test_utf8_text_file() {
    let path = create_temp_file("utf8.txt", "你好世界\n".as_bytes());
    let (out, _, _) = run(&[path.to_str().unwrap()]);
    assert!(out.contains("UTF-8"));
}

#[test]
fn test_empty_file() {
    let path = create_temp_file("empty", b"");
    let (out, _, _) = run(&[path.to_str().unwrap()]);
    assert!(out.contains("empty"));
}

#[test]
fn test_directory() {
    let path = create_temp_dir("testdir");
    let (out, _, _) = run(&[path.to_str().unwrap()]);
    assert!(out.contains("directory"));
}

#[test]
fn test_crlf_text() {
    let path = create_temp_file("crlf.txt", b"line1\r\nline2\r\n");
    let (out, _, _) = run(&[path.to_str().unwrap()]);
    assert!(out.contains("CRLF"));
}

#[test]
fn test_nonexistent_file() {
    let (out, _, ok) = run(&["/no/such/file/ever"]);
    assert!(!ok);
    assert!(out.contains("cannot open"));
}

// ---- --mime-type ----

#[test]
fn test_mime_type_text() {
    let path = create_temp_file("ascii.txt", b"hello world\n");
    let (out, _, _) = run(&["--mime-type", path.to_str().unwrap()]);
    assert!(out.trim().contains("text/plain"));
}

#[test]
fn test_mime_type_directory() {
    let path = create_temp_dir("dir_mime");
    let (out, _, _) = run(&["--mime-type", path.to_str().unwrap()]);
    assert!(out.trim().contains("inode/directory"));
}

#[test]
fn test_mime_type_empty() {
    let path = create_temp_file("empty", b"");
    let (out, _, _) = run(&["--mime-type", path.to_str().unwrap()]);
    assert!(out.trim().contains("application/x-empty"));
}

// ---- -b --mime-type (brief, yazi uses this) ----

#[test]
fn test_brief_mime_type() {
    let path = create_temp_file("hello.py", b"print('hi')\n");
    let (out, _, _) = run(&["-bL", "--mime-type", "--", path.to_str().unwrap()]);
    assert_eq!(out.trim(), "text/x-python");
}

#[test]
fn test_brief_mime_type_rust() {
    let path = create_temp_file("main.rs", b"fn main() {}\n");
    let (out, _, _) = run(&["-bL", "--mime-type", "--", path.to_str().unwrap()]);
    assert_eq!(out.trim(), "text/rust");
}

#[test]
fn test_brief_mime_type_c() {
    let path = create_temp_file("test.c", b"#include <stdio.h>\nint main(){}\n");
    let (out, _, _) = run(&["-bL", "--mime-type", "--", path.to_str().unwrap()]);
    assert_eq!(out.trim(), "text/x-c");
}

// ---- --mime (full MIME with charset) ----

#[test]
fn test_mime_output() {
    let path = create_temp_file("ascii.txt", b"hello world\n");
    let (out, _, _) = run(&["--mime", path.to_str().unwrap()]);
    assert!(out.contains("text/plain; charset=us-ascii"));
}

#[test]
fn test_mime_binary() {
    // PNG magic bytes
    let path = create_temp_file("image.png", b"\x89PNG\r\n\x1a\nfake data here padding");
    let (out, _, _) = run(&["--mime", path.to_str().unwrap()]);
    assert!(out.contains("image/png"));
}

// ---- --mime-encoding ----

#[test]
fn test_mime_encoding_ascii() {
    let path = create_temp_file("ascii.txt", b"hello world\n");
    let (out, _, _) = run(&["--mime-encoding", path.to_str().unwrap()]);
    assert!(out.trim().contains("us-ascii"));
}

#[test]
fn test_mime_encoding_utf8() {
    let path = create_temp_file("utf8.txt", "你好\n".as_bytes());
    let (out, _, _) = run(&["--mime-encoding", path.to_str().unwrap()]);
    assert!(out.trim().contains("utf-8"));
}

#[test]
fn test_mime_encoding_binary() {
    let path = create_temp_file("image.png", b"\x89PNG\r\n\x1a\nfake data here padding");
    let (out, _, _) = run(&["--mime-encoding", path.to_str().unwrap()]);
    assert!(out.trim().contains("binary"));
}

// ---- --extension ----

#[test]
fn test_extension_flag() {
    let path = create_temp_file("image.png", b"\x89PNG\r\n\x1a\nfake data here padding");
    let (out, _, _) = run(&["--extension", path.to_str().unwrap()]);
    assert!(out.contains("png"));
}

// ---- -b (brief) ----

#[test]
fn test_brief_no_filename() {
    let path = create_temp_file("ascii.txt", b"hello world\n");
    let (out, _, _) = run(&["-b", path.to_str().unwrap()]);
    assert!(!out.contains("ascii.txt"));
    assert!(out.contains("ASCII text"));
}

// ---- Multiple files ----

#[test]
fn test_multiple_files() {
    let p1 = create_temp_file("a.txt", b"hello\n");
    let p2 = create_temp_file("b.txt", b"world\n");
    let (out, _, _) = run(&["-b", "--mime-type", p1.to_str().unwrap(), p2.to_str().unwrap()]);
    let lines: Vec<&str> = out.trim().lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("text/plain"));
    assert!(lines[1].contains("text/plain"));
}

// ---- -f - (stdin, yazi's Windows invocation) ----

#[test]
fn test_files_from_stdin() {
    let p1 = create_temp_file("s1.rs", b"fn main() {}\n");
    let p2 = create_temp_file("s2.py", b"print('hi')\n");
    let input = format!("{}\n{}\n", p1.display(), p2.display());
    let _output = Command::new(file_bin())
        .args(&["-bL", "--mime-type", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("failed to run file");
    use std::io::Write;
    let mut child = Command::new(file_bin())
        .args(&["-bL", "--mime-type", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn file");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(input.as_bytes()).unwrap();
    }
    let result = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&result.stdout).to_string();
    let lines: Vec<&str> = out.trim().lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "text/rust");
    assert_eq!(lines[1], "text/x-python");
}

// ---- Binary format detection ----

#[test]
fn test_zip_file() {
    let path = create_temp_file("test.zip", b"PK\x03\x04fake data here padding");
    let (out, _, _) = run(&["-b", "--mime-type", path.to_str().unwrap()]);
    assert_eq!(out.trim(), "application/zip");
}

#[test]
fn test_gzip_file() {
    let mut data = vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
    data.extend_from_slice(b"fake gzip payload here padding to make it longer");
    let path = create_temp_file("test.gz", &data);
    let (out, _, _) = run(&["-b", "--mime-type", path.to_str().unwrap()]);
    assert_eq!(out.trim(), "application/gzip");
}

#[test]
fn test_pdf_file() {
    let path = create_temp_file("doc.pdf", b"%PDF-1.4 fake content here padding");
    let (out, _, _) = run(&["-b", "--mime-type", path.to_str().unwrap()]);
    assert_eq!(out.trim(), "application/pdf");
}

#[test]
fn test_binary_data() {
    let path = create_temp_file("random.bin", &[0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0x00, 0x80]);
    let (out, _, _) = run(&["-b", "--mime-type", path.to_str().unwrap()]);
    assert_eq!(out.trim(), "application/octet-stream");
}

// ---- -F separator ----

#[test]
fn test_custom_separator() {
    let path = create_temp_file("ascii.txt", b"hello\n");
    let (out, _, _) = run(&["-F", "|", path.to_str().unwrap()]);
    assert!(out.contains("|"));
    assert!(!out.contains(": "));
}
