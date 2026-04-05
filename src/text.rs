/// Text file analysis: encoding detection, line ending detection, language heuristics.

/// Detected text encoding
#[derive(Debug, Clone, PartialEq)]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
    Other(String),
}

impl Encoding {
    /// Standard charset name for MIME output
    pub fn charset_name(&self) -> &str {
        match self {
            Self::Ascii => "us-ascii",
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            _ => "unknown-8bit",
        }
    }

    /// Human-readable encoding name for normal output
    pub fn display_name(&self, with_bom: bool) -> String {
        match self {
            Self::Ascii => "ASCII text".to_string(),
            Self::Utf8 if with_bom => "UTF-8 Unicode (with BOM) text".to_string(),
            Self::Utf8 => "UTF-8 Unicode text".to_string(),
            Self::Utf16Le => "Little-endian UTF-16 Unicode text".to_string(),
            Self::Utf16Be => "Big-endian UTF-16 Unicode text".to_string(),
            _ => "Non-ISO extended-ASCII text".to_string(),
        }
    }
}

/// Detected line ending style
#[derive(Debug, Clone, PartialEq)]
pub enum LineEnding {
    Lf,
    Crlf,
    Cr,
    Mixed,
    None,
}

impl LineEnding {
    pub fn description(&self) -> Option<&'static str> {
        match self {
            Self::Crlf => Some("with CRLF line terminators"),
            Self::Cr => Some("with CR line terminators"),
            Self::Mixed => Some("with mixed line terminators"),
            Self::None => Some("with no line terminators"),
            Self::Lf => None,
        }
    }
}

/// Result of text file analysis
#[derive(Debug)]
pub struct TextInfo {
    pub encoding: Encoding,
    pub line_ending: LineEnding,
    pub with_bom: bool,
    pub has_long_lines: bool,
    pub language_hint: Option<String>,
}

/// Detect text encoding and analyze text content
pub fn analyze_text(data: &[u8]) -> TextInfo {
    let (encoding, text, with_bom) = decode_text(data);
    let line_ending = detect_line_endings(&text);
    let has_long_lines = text.lines().any(|line| line.len() > 1000);
    let language_hint = detect_language(&text);

    TextInfo {
        encoding,
        line_ending,
        with_bom,
        has_long_lines,
        language_hint,
    }
}

/// Decode bytes to string, detecting encoding
fn decode_text(data: &[u8]) -> (Encoding, String, bool) {
    // Check for BOM first
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        let text = String::from_utf8_lossy(&data[3..]).to_string();
        return (Encoding::Utf8, text, true);
    }
    if data.starts_with(&[0xFF, 0xFE]) {
        let (cow, _, _) = encoding_rs::UTF_16LE.decode(&data[2..]);
        return (Encoding::Utf16Le, cow.to_string(), true);
    }
    if data.starts_with(&[0xFE, 0xFF]) {
        let (cow, _, _) = encoding_rs::UTF_16BE.decode(&data[2..]);
        return (Encoding::Utf16Be, cow.to_string(), true);
    }
    if data.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        let (cow, _, _) = encoding_rs::UTF_16LE.decode(&data[4..]);
        return (Encoding::Utf32Le, cow.to_string(), true);
    }
    if data.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        let (cow, _, _) = encoding_rs::UTF_16BE.decode(&data[4..]);
        return (Encoding::Utf32Be, cow.to_string(), true);
    }

    // Try UTF-8 first
    match String::from_utf8(data.to_vec()) {
        Ok(s) => {
            let is_ascii = data.iter().all(|&b| b <= 0x7F);
            let enc = if is_ascii { Encoding::Ascii } else { Encoding::Utf8 };
            return (enc, s, false);
        }
        Err(_) => {}
    }

    // Try other encodings
    let encodings = [
        encoding_rs::WINDOWS_1252,
        encoding_rs::GBK,
        encoding_rs::BIG5,
        encoding_rs::SHIFT_JIS,
        encoding_rs::EUC_JP,
        encoding_rs::EUC_KR,
        encoding_rs::KOI8_R,
        encoding_rs::ISO_8859_2,
        encoding_rs::ISO_8859_5,
        encoding_rs::ISO_8859_7,
        encoding_rs::ISO_8859_10,
        encoding_rs::WINDOWS_1251,
    ];

    for enc in encodings {
        let (cow, encoding_used, had_errors) = enc.decode(data);
        if !had_errors && is_plausible_text(&cow) {
            return (Encoding::Other(encoding_used.name().to_string()), cow.to_string(), false);
        }
    }

    // Fallback: lossy UTF-8
    let text = String::from_utf8_lossy(data).to_string();
    (Encoding::Other("unknown".to_string()), text, false)
}

/// Check if a string looks like plausible human-readable text
fn is_plausible_text(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let total = s.len();
    if total == 0 {
        return false;
    }
    let printable = s.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t').count();
    printable as f64 / total as f64 > 0.95
}

/// Detect line ending style
fn detect_line_endings(text: &str) -> LineEnding {
    let crlf = text.matches("\r\n").count();
    let lf = text.matches('\n').count() - crlf;
    let cr = text.matches('\r').count() - crlf;

    match (crlf, lf, cr) {
        (0, 0, 0) => LineEnding::None,
        (_, _, _) if crlf > lf && crlf > cr => LineEnding::Crlf,
        (_, _, _) if lf > crlf && lf > cr => LineEnding::Lf,
        (_, _, _) if cr > crlf && cr > lf => LineEnding::Cr,
        (0, _, _) if lf > 0 => LineEnding::Lf,
        (_, 0, _) if crlf > 0 => LineEnding::Crlf,
        _ => LineEnding::Mixed,
    }
}

/// Detect programming language or document type from content heuristics
fn detect_language(text: &str) -> Option<String> {
    let trimmed = text.trim_start();

    // Shell scripts
    if trimmed.starts_with("#!/bin/sh") || trimmed.starts_with("#!/bin/bash") {
        return Some("shell script".to_string());
    }
    if trimmed.starts_with("#!/usr/bin/env bash") || trimmed.starts_with("#!/usr/bin/env sh") {
        return Some("shell script".to_string());
    }

    // Python
    if trimmed.starts_with("#!/usr/bin/env python") || trimmed.starts_with("#!/usr/bin/python") {
        return Some("Python script".to_string());
    }
    if trimmed.contains("if __name__") && trimmed.contains("def ") {
        return Some("Python script".to_string());
    }
    if trimmed.contains("import ") && (trimmed.starts_with("import ") || trimmed.contains("\nimport "))
        && (trimmed.contains("def ") || trimmed.contains("class "))
        && !trimmed.contains("fn ") && !trimmed.contains("let ") && !trimmed.contains("pub ") {
        return Some("Python script".to_string());
    }

    // Perl
    if trimmed.starts_with("#!/usr/bin/perl") || trimmed.starts_with("#!/usr/bin/env perl") {
        return Some("Perl script".to_string());
    }

    // Ruby
    if trimmed.starts_with("#!/usr/bin/env ruby") || trimmed.starts_with("#!/usr/bin/ruby") {
        return Some("Ruby script".to_string());
    }

    // Node.js
    if trimmed.starts_with("#!/usr/bin/env node") {
        return Some("Node.js script".to_string());
    }

    // Rust - check before Python since Rust uses fn, let, pub, mod, crate, use
    if trimmed.contains("fn ") && (trimmed.contains("pub fn ") || trimmed.contains("fn "))
        && (trimmed.contains("let ") || trimmed.contains("::") || trimmed.contains("mod ") || trimmed.contains("pub "))
        && (trimmed.contains("use ") || trimmed.contains("impl ") || trimmed.contains("struct ") || trimmed.contains("enum ") || trimmed.contains("trait ")) {
        return Some("Rust source".to_string());
    }

    // C/C++
    if trimmed.contains("#include <") && (trimmed.contains("int main") || trimmed.contains("void main")) {
        if trimmed.contains("std::") || trimmed.contains("class ") || trimmed.contains("cout") {
            return Some("C++ source".to_string());
        }
        return Some("C source".to_string());
    }

    // Java
    if trimmed.contains("public class ") && trimmed.contains("import java.") {
        return Some("Java source".to_string());
    }

    // Go
    if trimmed.starts_with("package ") && trimmed.contains("import (") {
        return Some("Go source".to_string());
    }
    if trimmed.starts_with("package ") && trimmed.contains("func ") {
        return Some("Go source".to_string());
    }

    // PHP
    if trimmed.starts_with("<?php") {
        return Some("PHP script".to_string());
    }

    // HTML
    if trimmed.starts_with("<!DOCTYPE") || trimmed.starts_with("<!doctype") {
        return Some("HTML document".to_string());
    }
    if trimmed.starts_with("<html") || trimmed.starts_with("<HTML") {
        return Some("HTML document".to_string());
    }

    // XML
    if trimmed.starts_with("<?xml") {
        return Some("XML document".to_string());
    }

    // JSON
    if (trimmed.starts_with('{') || trimmed.starts_with('[')) && (trimmed.contains("\":") || trimmed.contains("\" :")) {
        return Some("JSON data".to_string());
    }

    // YAML
    if trimmed.contains("---\n") && (trimmed.contains(": ") || trimmed.contains("- ")) {
        return Some("YAML document".to_string());
    }

    // Makefile
    if trimmed.starts_with("all:") || trimmed.starts_with("clean:") || (trimmed.contains(":= ") && trimmed.contains("$(shell")) {
        return Some("Makefile".to_string());
    }

    // Dockerfile
    if trimmed.starts_with("FROM ") {
        return Some("Dockerfile".to_string());
    }

    // TOML
    if trimmed.starts_with('[') && trimmed.contains("= ") && !trimmed.contains("<?") {
        return Some("TOML document".to_string());
    }

    // INI
    if trimmed.starts_with('[') && trimmed.contains("= ") && trimmed.contains("\n[") {
        return Some("INI configuration".to_string());
    }

    // Markdown
    if (trimmed.starts_with("# ") || trimmed.contains("\n# ")) && (trimmed.contains("](") || trimmed.contains("**")) {
        return Some("Markdown document".to_string());
    }

    // SQL
    if (trimmed.starts_with("SELECT ") || trimmed.starts_with("select "))
        || (trimmed.contains("CREATE TABLE") && trimmed.contains("("))
        || trimmed.contains("INSERT INTO")
        || trimmed.contains("ALTER TABLE") {
        return Some("SQL".to_string());
    }

    // Diff/Patch
    if trimmed.starts_with("diff --git") || trimmed.starts_with("--- a/") {
        return Some("diff/patch".to_string());
    }

    // DOS batch
    if trimmed.starts_with("@echo off") || trimmed.starts_with("@ECHO OFF") {
        return Some("DOS batch".to_string());
    }

    // PowerShell
    if trimmed.starts_with("#Requires") || (trimmed.contains("$") && trimmed.contains("Write-Host")) {
        return Some("PowerShell script".to_string());
    }

    None
}

/// Check if data appears to be text (vs binary)
pub fn is_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }

    // Check for UTF BOM
    if data.starts_with(&[0xEF, 0xBB, 0xBF])
        || data.starts_with(&[0xFF, 0xFE])
        || data.starts_with(&[0xFE, 0xFF]) {
        return true;
    }

    // Check for null bytes (strong indicator of binary)
    let null_count = data.iter().take(8192).filter(|&&b| b == 0).count();
    if null_count > 0 {
        // Could be UTF-16/32 if nulls are in expected positions
        if null_count > data.len() / 4 {
            let is_utf16_le = data.len() > 4 && data[1] == 0 && data[3] == 0;
            let is_utf16_be = data.len() > 4 && data[0] == 0 && data[2] == 0;
            return is_utf16_le || is_utf16_be;
        }
        return false;
    }

    // Count control characters (excluding common whitespace)
    let sample_size = data.len().min(8192);
    let sample = &data[..sample_size];
    let control_count = sample.iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t' && b != 0x0C)
        .count();

    // Also check for high bytes (could be UTF-8 multibyte)
    let high_count = sample.iter().filter(|&&b| b >= 0x80).count();

    // If too many control characters, likely binary
    if control_count as f64 / sample_size as f64 > 0.1 {
        return false;
    }

    // If many high bytes with no valid UTF-8 sequences, likely binary
    if high_count as f64 / sample_size as f64 > 0.3 {
        match std::str::from_utf8(sample) {
            Ok(_) => return true,
            Err(_) => return false,
        }
    }

    // Check if valid UTF-8
    match std::str::from_utf8(sample) {
        Ok(_) => true,
        Err(_) => {
            let printable = sample.iter()
                .filter(|&&b| b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t')
                .count();
            printable as f64 / sample_size as f64 > 0.85
        }
    }
}

/// Format text info into a description string like the Linux `file` command
pub fn format_text_description(info: &TextInfo) -> String {
    let mut parts = Vec::new();

    let enc_desc = info.encoding.display_name(info.with_bom);

    // Language/type hint first, then encoding (matches Linux format)
    if let Some(ref lang) = info.language_hint {
        parts.push(lang.clone());
        parts.push(enc_desc);
    } else {
        parts.push(enc_desc);
    }

    // Line ending
    if let Some(desc) = info.line_ending.description() {
        parts.push(desc.to_string());
    }

    // Long lines indicator
    if info.has_long_lines {
        parts.push("with very long lines".to_string());
    }

    parts.join(", ")
}

/// Format encoding name to match Linux `file` output
pub fn format_encoding(encoding: &Encoding, with_bom: bool) -> String {
    encoding.display_name(with_bom)
}
