/// Magic number database for file type identification.
/// Covers the most common file formats found in real-world usage.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct MagicMatch {
    pub description: String,
    pub mime_type: String,
}

struct MagicRule {
    offset: usize,
    magic: &'static [u8],
    description: &'static str,
    mime_type: &'static str,
    /// Optional secondary check at another offset
    extra: Option<ExtraCheck>,
}

struct ExtraCheck {
    offset: usize,
    magic: &'static [u8],
}

// Helper macro to reduce boilerplate
macro_rules! magic {
    ($offset:expr, $magic:expr, $desc:expr, $mime:expr) => {
        MagicRule {
            offset: $offset,
            magic: $magic,
            description: $desc,
            mime_type: $mime,
            extra: None,
        }
    };
    ($offset:expr, $magic:expr, $desc:expr, $mime:expr, extra $eo:expr, $em:expr) => {
        MagicRule {
            offset: $offset,
            magic: $magic,
            description: $desc,
            mime_type: $mime,
            extra: Some(ExtraCheck { offset: $eo, magic: $em }),
        }
    };
}

static MAGIC_DB: &[MagicRule] = &[
    // === Images ===
    magic!(0, b"\x89PNG\r\n\x1a\n", "PNG image data", "image/png"),
    magic!(0, b"\xFF\xD8\xFF", "JPEG image data", "image/jpeg"),
    magic!(0, b"GIF87a", "GIF image data (version 87a)", "image/gif"),
    magic!(0, b"GIF89a", "GIF image data (version 89a)", "image/gif"),
    magic!(0, b"BM", "BMP image data", "image/bmp"),
    magic!(0, b"RIFF", "WebP image data", "image/webp", extra 8, b"WEBP"),
    magic!(0, b"II*\x00", "TIFF image data (little-endian)", "image/tiff"),
    magic!(0, b"MM\x00*", "TIFF image data (big-endian)", "image/tiff"),
    magic!(0, b"\x00\x00\x01\x00", "ICO image data", "image/x-icon"),
    magic!(0, b"\x00\x00\x02\x00", "CUR image data", "image/x-cursor"),
    magic!(8, b"\x49\x4E\x44\x48", "HDR image data (Radiance)", "image/vnd.radiance"),
    magic!(0, b"\x76\x2F\x31\x01", "XWD image data", "image/x-xwd"),
    magic!(0, b"P1", "Portable bitmap (PBM) text", "image/x-portable-bitmap"),
    magic!(0, b"P2", "Portable graymap (PGM) text", "image/x-portable-graymap"),
    magic!(0, b"P3", "Portable pixmap (PPM) text", "image/x-portable-pixmap"),
    magic!(0, b"P4", "Portable bitmap (PBM) binary", "image/x-portable-bitmap"),
    magic!(0, b"P5", "Portable graymap (PGM) binary", "image/x-portable-graymap"),
    magic!(0, b"P6", "Portable pixmap (PPM) binary", "image/x-portable-pixmap"),
    magic!(0, b"P7", "Portable arbitrary map (PAM)", "image/x-portable-arbitrarymap"),
    magic!(0, b"\x28\x00\x00\x00", "DIB image data (OS/2 or Windows BMP)", "image/bmp"),
    magic!(0, b"ftyp", "HEIF image data", "image/heif", extra 4, b"heic"),
    magic!(0, b"ftyp", "AVIF image data", "image/avif", extra 4, b"avif"),
    magic!(0, b"\x97MOTO", "MOTOTOOL image data", "application/octet-stream"),
    magic!(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Microsoft compound document (MSI/DOC/XLS/PPT)", "application/msword"),

    // === Archives ===
    magic!(0, b"PK\x03\x04", "Zip archive data", "application/zip"),
    magic!(0, b"PK\x05\x06", "Zip archive data (empty)", "application/zip"),
    magic!(0, b"\x1F\x8B", "gzip compressed data", "application/gzip"),
    magic!(0, b"BZh", "bzip2 compressed data", "application/x-bzip2"),
    magic!(0, b"\xFD7zXZ\x00", "XZ compressed data", "application/x-xz"),
    magic!(0, b"\x5D\x00\x00", "LZMA compressed data", "application/x-lzma"),
    magic!(0, b"Rar!\x1A\x07\x00", "RAR archive data (v4)", "application/x-rar"),
    magic!(0, b"Rar!\x1A\x07\x01\x00", "RAR archive data (v5)", "application/x-rar"),
    magic!(0, b"\x37\x7A\xBC\xAF\x27\x1C", "7-zip archive data", "application/x-7z-compressed"),
    magic!(0, b"\x60\xEA", "ARJ archive data", "application/x-arj"),
    magic!(0, b"!\x3C\x61\x72\x63\x68\x3E", "Debian binary package", "application/vnd.debian.binary-package"),
    magic!(0, b"070707", "cpio archive data", "application/x-cpio"),
    magic!(0, b"070701", "cpio newc archive data", "application/x-cpio"),
    magic!(0, b"070702", "cpio newc archive data (with CRC)", "application/x-cpio"),
    magic!(0, b"\x71\xC7", "Zoo archive data", "application/x-zoo"),
    magic!(0, b"MSDOS", "MS-DOS executable (COFF)", "application/x-msdos-program"),
    magic!(0, b"TAR", "tar archive (POSIX)", "application/x-tar", extra 257, b"ustar"),
    magic!(0, b"\x1A\x00", "MS-DOS executable (COM)", "application/x-msdos-program"),
    magic!(0, b"\xEB", "MS-DOS executable (boot sector)", "application/x-msdos-program"),
    magic!(0, b"\xFA\x33\xC0\x8E", "MS-DOS boot sector", "application/octet-stream"),

    // === Audio ===
    magic!(0, b"RIFF", "WAVE audio data", "audio/wav", extra 8, b"WAVE"),
    magic!(0, b"ID3", "MP3 audio data (ID3 tagged)", "audio/mpeg"),
    magic!(0, b"\xFF\xFB", "MP3 audio data", "audio/mpeg"),
    magic!(0, b"\xFF\xFA", "MP3 audio data", "audio/mpeg"),
    magic!(0, b"\xFF\xF3", "MP3 audio data", "audio/mpeg"),
    magic!(0, b"\xFF\xF2", "MP3 audio data", "audio/mpeg"),
    magic!(0, b"fLaC", "FLAC audio data", "audio/flac"),
    magic!(0, b"OggS", "Ogg data", "application/ogg"),
    magic!(0, b"MThd", "MIDI audio data", "audio/midi"),
    magic!(0, b"MAC ", "Monkey's Audio (APE)", "audio/x-ape"),
    magic!(0, b"wvpk", "WavPack audio data", "audio/x-wavpack"),
    magic!(0, b"FORM", "AIFF audio data", "audio/aiff", extra 8, b"AIFF"),
    magic!(0, b"FORM", "AIFF-C audio data", "audio/aiff", extra 8, b"AIFC"),
    magic!(0, b"#!AMR", "AMR audio data", "audio/amr"),
    magic!(0, b"\x7FELF", "ELF object file", "application/x-elf"),

    // === Video ===
    magic!(0, b"\x00\x00\x00\x1C\x66\x74\x79\x70", "MP4 video data", "video/mp4"),
    magic!(0, b"\x00\x00\x00\x20\x66\x74\x79\x70", "MP4 video data", "video/mp4"),
    magic!(0, b"\x00\x00\x00\x18\x66\x74\x79\x70", "MP4 video data", "video/mp4"),
    magic!(0, b"\x1A\x45\xDF\xA3", "Matroska/WebM video data", "video/x-matroska"),
    magic!(0, b"RIFF", "AVI video data", "video/avi", extra 8, b"AVI "),
    magic!(0, b"\x00\x00\x01\xBA", "MPEG video data (PS)", "video/mpeg"),
    magic!(0, b"\x00\x00\x01\xB3", "MPEG video data", "video/mpeg"),
    magic!(0, b"FLV\x01", "Flash video data", "video/x-flv"),

    // === Executables / Binary ===
    magic!(0, b"\x4D\x5A", "PE32 executable (Windows)", "application/x-dosexec"),
    magic!(0, b"\x7FELF\x01", "ELF 32-bit executable", "application/x-elf"),
    magic!(0, b"\x7FELF\x02", "ELF 64-bit executable", "application/x-elf"),
    magic!(0, b"\xCA\xFE\xBA\xBE", "Java class file / Mach-O universal binary", "application/java-vm"),
    magic!(0, b"\xFE\xED\xFA\xCE", "Mach-O 32-bit executable", "application/x-mach-binary"),
    magic!(0, b"\xFE\xED\xFA\xCF", "Mach-O 64-bit executable", "application/x-mach-binary"),
    magic!(0, b"\xCE\xFA\xED\xFE", "Mach-O 32-bit executable (LE)", "application/x-mach-binary"),
    magic!(0, b"\xCF\xFA\xED\xFE", "Mach-O 64-bit executable (LE)", "application/x-mach-binary"),
    magic!(0, b"\xDE\xC0\x17\x0B", "LLVM bitcode", "application/octet-stream"),
    magic!(0, b"BC\xC0\xDE", "LLVM bitcode (wrapped)", "application/octet-stream"),
    magic!(0, b"DEX\n", "Android DEX executable", "application/x-dex"),
    magic!(0, b"dyld_v1", "Darwin dyld cache", "application/octet-stream"),
    magic!(0, b"\x00\x61\x73\x6D", "WebAssembly binary module", "application/wasm"),

    // === Documents ===
    magic!(0, b"%PDF", "PDF document", "application/pdf"),
    magic!(0, b"%!PS", "PostScript document", "application/postscript"),
    magic!(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Microsoft compound document", "application/msword"),
    magic!(0, b"BEGIN:", "vCard/vCalendar data", "text/vcard"),
    magic!(0, b"\xEF\xBB\xBF<?xml", "XML document (UTF-8 BOM)", "text/xml"),
    magic!(0, b"<?xml", "XML document", "text/xml"),
    magic!(0, b"<svg", "SVG image data", "image/svg+xml"),
    magic!(0, b"<html", "HTML document", "text/html"),
    magic!(0, b"<!DOCTYPE html", "HTML document", "text/html"),
    magic!(0, b"<!doctype html", "HTML document", "text/html"),
    magic!(0, b"<HTML", "HTML document", "text/html"),

    // === Database ===
    magic!(0, b"SQLite format 3\x00", "SQLite 3.x database", "application/x-sqlite3"),
    magic!(0, b"\x00\x01\x00\x00", "Berkeley DB", "application/octet-stream"),
    magic!(0, b"\x00\x05\x31\x02", "LevelDB (LOG file)", "application/octet-stream"),
    magic!(0, b"GDBM", "GDBM database", "application/octet-stream"),

    // === Font files ===
    magic!(0, b"\x00\x01\x00\x00", "TrueType font data", "font/ttf"),
    magic!(0, b"OTTO", "OpenType font data", "font/otf"),
    magic!(0, b"ttcf", "TrueType Collection font", "font/collection"),
    magic!(0, b"wOFF", "WOFF font data", "font/woff"),
    magic!(0, b"wOF2", "WOFF2 font data", "font/woff2"),
    magic!(0, b"STARTFONT ", "BDF font data", "font/x-bdf"),
    magic!(0, b"\x14\x00\x00\x00", "PCF font data", "font/x-pcf"),
    magic!(0, b"%!PS-AdobeFont", "PostScript Type 1 font", "font/x-type1"),

    // === Cryptography / Security ===
    magic!(0, b"-----BEGIN PGP", "PGP data", "application/pgp"),
    magic!(0, b"-----BEGIN CERTIFICATE", "PEM certificate", "application/x-pem-file"),
    magic!(0, b"-----BEGIN RSA PRIVATE KEY", "PEM RSA private key", "application/x-pem-file"),
    magic!(0, b"-----BEGIN PRIVATE KEY", "PEM private key", "application/x-pem-file"),
    magic!(0, b"-----BEGIN PUBLIC KEY", "PEM public key", "application/x-pem-file"),
    magic!(0, b"ssh-rsa ", "SSH RSA public key", "application/x-ssh-key"),
    magic!(0, b"ssh-ed25519 ", "SSH ED25519 public key", "application/x-ssh-key"),
    magic!(0, b"ecdsa-sha2-", "SSH ECDSA public key", "application/x-ssh-key"),
    magic!(0, b"ssh-dss ", "SSH DSA public key", "application/x-ssh-key"),
    magic!(0, b"-----BEGIN OPENSSH PRIVATE KEY", "OpenSSH private key", "application/x-ssh-key"),

    // === Package managers ===
    magic!(0, b"\xED\xAB\xEE\xDB", "RPM package", "application/x-rpm"),
    magic!(0, b"#![allow(unused)]", "Rust source (uncommon)", "text/rust"),

    // === Disk / filesystem images ===
    magic!(0, b"VHD ", "VHD disk image", "application/x-vhd"),
    magic!(0, b"conectix", "VHD disk image (Connectix)", "application/x-vhd"),
    magic!(0, b"KDMV", "VMDK disk image", "application/x-vmdk"),
    magic!(0, b"VMDK", "VMDK disk image", "application/x-vmdk"),
    magic!(0, b"QFI\xfb", "QEMU qcow2 disk image", "application/x-qemu-disk"),
    magic!(0, b"EH\x00\x00", "QEMU qcow disk image", "application/x-qemu-disk"),
    magic!(0, b"BOCHS", "Bochs disk image", "application/octet-stream"),
    magic!(0, b"\xEB\x3C\x90", "FAT filesystem", "application/x-filesystem-image"),
    magic!(0, b"\xEB\x58\x90", "FAT filesystem", "application/x-filesystem-image"),
    magic!(0, b"NTFS    ", "NTFS filesystem", "application/x-filesystem-image"),
    magic!(0, b"EXTENDED", "Extended partition", "application/x-filesystem-image"),

    // === Other common formats ===
    magic!(0, b"SNAPY", "Snappy compressed data", "application/x-snappy-framed"),
    magic!(0, b"\x28\xB5\x2F\xFD", "Zstandard compressed data", "application/zstd"),
    magic!(0, b"\x04\x22\x4D\x18", "LZ4 compressed data (frame)", "application/x-lz4"),
    magic!(0, b"Cr24", "Chrome extension (CRX)", "application/x-chrome-extension"),
    magic!(0, b"MSCF\x00\x00\x00\x00", "Microsoft Cabinet archive", "application/vnd.ms-cab-compressed"),
    magic!(0, b"ITSF", "Microsoft HTML Help (CHM)", "application/x-chm"),
    magic!(0, b".registry", "Windows registry hive", "application/octet-stream"),
    magic!(0, b"regf", "Windows registry hive (REGF)", "application/octet-stream"),
    magic!(0, b"PMCC", "Windows prefetch file", "application/octet-stream"),
    magic!(0, b"SCCA", "Windows prefetch file (SCCA)", "application/octet-stream"),
    magic!(0, b"\x7F\x50\x52\x4F\x58", "PROX hash file", "application/octet-stream"),
    magic!(0, b"\x89\x50\x4E\x47", "PNG image (secondary check)", "image/png"),
];

/// Check a PE executable for more details (32/64-bit, GUI/Console, DLL)
fn analyze_pe(data: &[u8]) -> String {
    if data.len() < 64 {
        return "PE32 executable".to_string();
    }
    // PE header offset at 0x3C
    let pe_offset = match data.get(0x3C..0x40) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize,
        None => return "PE32 executable".to_string(),
    };
    if data.len() < pe_offset + 24 {
        return "PE32 executable".to_string();
    }
    // Check PE\0\0 signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return "PE32 executable".to_string();
    }

    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
    let characteristics = u16::from_le_bytes([data[pe_offset + 22], data[pe_offset + 23]]);

    let arch = match machine {
        0x014C => "x86",
        0x8664 => "x86-64",
        0xAA64 => "ARM64",
        0x01C0 => "ARM",
        0x01C4 => "ARM Thumb-2",
        _ => "unknown",
    };

    let is_dll = (characteristics & 0x2000) != 0;

    // Optional header starts at pe_offset + 24
    let opt_offset = pe_offset + 24;
    if data.len() < opt_offset + 2 {
        return format!("PE32 executable ({})", arch);
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let (pe_type, subsystem_offset) = match opt_magic {
        0x10B => ("32-bit", opt_offset + 68),
        0x20B => ("32-bit+ (PE32+)", opt_offset + 68),
        _ => return format!("PE32 executable ({})", arch),
    };

    let subsystem = if data.len() >= subsystem_offset + 2 {
        u16::from_le_bytes([data[subsystem_offset], data[subsystem_offset + 1]])
    } else {
        0
    };

    let sub_desc = match subsystem {
        1 => "native",
        2 => "console",
        3 => "Windows GUI",
        7 => "POSIX",
        9 => "Windows CE",
        10 => "EFI",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        _ => "unknown subsystem",
    };

    if is_dll {
        format!("PE32+ DLL ({}, {})", arch, pe_type)
    } else {
        format!("PE32+ executable ({}, {}, {})", arch, pe_type, sub_desc)
    }
}

/// Check ELF executable for more details
fn analyze_elf(data: &[u8]) -> String {
    if data.len() < 20 {
        return "ELF executable".to_string();
    }
    let class = match data[4] {
        1 => "32-bit",
        2 => "64-bit",
        _ => "unknown",
    };
    let endian = match data[5] {
        1 => "LSB",
        2 => "MSB",
        _ => "unknown",
    };
    let read_u16 = |off: usize| -> u16 {
        if off + 2 > data.len() {
            return 0;
        }
        if data[5] == 1 {
            u16::from_le_bytes([data[off], data[off + 1]])
        } else {
            u16::from_be_bytes([data[off], data[off + 1]])
        }
    };
    let etype = match read_u16(16) {
        0 => "none",
        1 => "relocatable",
        2 => "executable",
        3 => "shared object",
        4 => "core",
        _ => "unknown",
    };
    let machine = match read_u16(18) {
        0x03 => "Intel 80386",
        0x3E => "x86-64",
        0x28 => "ARM",
        0xB7 => "AArch64",
        0x08 => "MIPS",
        0xF3 => "RISC-V",
        0x15 => "PowerPC",
        0x16 => "PowerPC64",
        0x2A => "SPARC",
        0x32 => "IA-64",
        0xB6 => "ILP32 AArch64",
        _ => "unknown",
    };
    format!("ELF {} {} {}, {}", class, endian, etype, machine)
}

/// Analyze Ogg container for specific codec
fn analyze_ogg(data: &[u8]) -> String {
    if data.len() > 37 && &data[29..37] == b"\x01video" {
        return "Ogg video data (Theora)".to_string();
    }
    if data.len() > 37 && &data[29..36] == b"\x01audio" {
        return "Ogg audio data".to_string();
    }
    // Check for Vorbis
    if data.len() > 35 && &data[29..35] == b"vorbis" {
        return "Ogg Vorbis audio data".to_string();
    }
    // Check for Opus
    if data.len() > 40 && &data[29..33] == b"Opus" {
        return "Ogg Opus audio data".to_string();
    }
    // Check for FLAC in Ogg
    if data.len() > 37 && &data[29..33] == b"FLAC" {
        return "Ogg FLAC audio data".to_string();
    }
    "Ogg data".to_string()
}

/// Get additional info for gzip (check OS byte, etc.)
fn analyze_gzip(data: &[u8]) -> String {
    if data.len() < 10 {
        return "gzip compressed data".to_string();
    }
    let flags = data[3];
    let os = match data[9] {
        0 => "FAT filesystem",
        1 => "Amiga",
        2 => "VMS",
        3 => "Unix",
        5 => "Atari TOS",
        6 => "HPFS filesystem",
        7 => "Macintosh",
        10 => "TopS-20",
        11 => "NTFS filesystem",
        12 => "QDOS",
        13 => "Acorn RISCOS",
        255 => "unknown",
        _ => "unknown",
    };
    let method = match data[2] {
        8 => "deflate",
        _ => "unknown method",
    };
    let mut extra = String::new();
    if flags & 0x04 != 0 {
        extra.push_str(", has extra field");
    }
    if flags & 0x08 != 0 {
        extra.push_str(", has original filename");
    }
    if flags & 0x02 != 0 {
        extra.push_str(", has CRC16");
    }
    if flags & 0x10 != 0 {
        extra.push_str(", has comment");
    }
    format!("gzip compressed data, was \"{}\" ({}{})", os, method, extra)
}

/// Try to identify a file by its magic bytes
pub fn identify_by_magic(data: &[u8]) -> Option<MagicMatch> {
    if data.is_empty() {
        return None;
    }

    // Special handling for specific formats with deeper analysis
    // PE executable
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        let desc = analyze_pe(data);
        return Some(MagicMatch {
            description: desc,
            mime_type: "application/x-dosexec".to_string(),
        });
    }

    // ELF executable
    if data.len() >= 5 && data[0] == 0x7F && &data[1..4] == b"ELF" {
        let desc = analyze_elf(data);
        return Some(MagicMatch {
            description: desc,
            mime_type: "application/x-elf".to_string(),
        });
    }

    // Ogg container
    if data.len() >= 4 && &data[0..4] == b"OggS" {
        return Some(MagicMatch {
            description: analyze_ogg(data),
            mime_type: "application/ogg".to_string(),
        });
    }

    // Gzip
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return Some(MagicMatch {
            description: analyze_gzip(data),
            mime_type: "application/gzip".to_string(),
        });
    }

    // ftyp-based (MP4, HEIF, AVIF, 3GP, etc.)
    if data.len() >= 12 {
        // Check bytes 4-7 for "ftyp"
        if &data[4..8] == b"ftyp" {
            let brand = &data[8..12];
            let desc = match brand {
                b"qt  " => "QuickTime movie",
                b"isom" | b"iso2" | b"iso3" | b"iso4" | b"iso5" | b"iso6" | b"mp41" | b"mp42" => "MP4 video",
                b"avc1" => "MP4 video (AVC)",
                b"heic" | b"heix" => "HEIF image",
                b"hevc" => "HEIF image sequence (HEVC)",
                b"avif" => "AVIF image",
                b"avis" => "AVIF image sequence",
                b"msf1" => "MP4 video (MS)",
                b"mmp4" => "MP4 video (mobile)",
                b"3gp4" | b"3gp5" | b"3gp6" | b"3g2a" | b"3g2b" | b"3g2c" => "3GPP multimedia",
                b"M4V " | b"M4VH" | b"M4VP" => "M4V video (iTunes)",
                b"M4A " => "M4A audio (iTunes)",
                b"f4v " => "Flash video (F4V)",
                b"f4p " => "Flash video (F4P, protected)",
                b"f4a " => "Flash audio (F4A)",
                b"f4b " => "Flash audio (F4B, book)",
                b"dash" => "MPEG-DASH segment",
                b"crx " => "Chrome extension",
                _ => "ISO Base Media File (ftyp)",
            };
            let mime = if brand.starts_with(b"3g") {
                "video/3gpp"
            } else if brand.starts_with(b"heic") || brand.starts_with(b"heix") || brand.starts_with(b"hevc") {
                "image/heif"
            } else if brand.starts_with(b"avif") || brand.starts_with(b"avis") {
                "image/avif"
            } else if brand == b"M4A " {
                "audio/mp4"
            } else if brand == b"qt  " {
                "video/quicktime"
            } else {
                "video/mp4"
            };
            return Some(MagicMatch {
                description: format!("{} data", desc),
                mime_type: mime.to_string(),
            });
        }
    }

    // Check compound document for specific type
    if data.len() >= 8 && &data[0..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
        // Try to determine more specific type from content
        // These are OLE2 compound documents - could be DOC, XLS, PPT, MSI, MSG, etc.
        return Some(MagicMatch {
            description: "Microsoft compound document (OLE2)".to_string(),
            mime_type: "application/msword".to_string(),
        });
    }

    // XML detection (with or without BOM)
    if data.len() >= 5 {
        // UTF-8 BOM + XML
        if data.len() >= 8 && &data[0..3] == b"\xEF\xBB\xBF" && (&data[3..8] == b"<?xml" || &data[3..5] == b"<?") {
            return Some(MagicMatch {
                description: "XML 1.0 document text (UTF-8 BOM)".to_string(),
                mime_type: "text/xml".to_string(),
            });
        }
        // Direct XML
        if &data[0..5] == b"<?xml" {
            return Some(MagicMatch {
                description: "XML 1.0 document text".to_string(),
                mime_type: "text/xml".to_string(),
            });
        }
    }

    // Check standard magic rules
    for rule in MAGIC_DB {
        if rule.offset + rule.magic.len() > data.len() {
            continue;
        }
        if &data[rule.offset..rule.offset + rule.magic.len()] == rule.magic {
            if let Some(ref extra) = rule.extra {
                if extra.offset + extra.magic.len() > data.len() {
                    continue;
                }
                if &data[extra.offset..extra.offset + extra.magic.len()] != extra.magic {
                    continue;
                }
            }
            return Some(MagicMatch {
                description: rule.description.to_string(),
                mime_type: rule.mime_type.to_string(),
            });
        }
    }

    None
}

/// Try to guess file type from extension as fallback
pub fn guess_by_extension(path: &Path) -> Option<MagicMatch> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    let (desc, mime) = match ext.as_str() {
        // Programming languages
        "rs" => ("Rust source, UTF-8 Unicode text", "text/rust"),
        "c" => ("C source, ASCII text", "text/x-c"),
        "h" => ("C header, ASCII text", "text/x-c"),
        "cpp" | "cc" | "cxx" => ("C++ source, ASCII text", "text/x-c++"),
        "hpp" | "hh" | "hxx" => ("C++ header, ASCII text", "text/x-c++"),
        "java" => ("Java source, ASCII text", "text/x-java"),
        "py" => ("Python source, ASCII text", "text/x-python"),
        "js" => ("JavaScript source, ASCII text", "text/javascript"),
        "ts" => ("TypeScript source, ASCII text", "text/typescript"),
        "mts" | "cts" => ("TypeScript source, ASCII text", "text/typescript"),
        "jsx" => ("JSX source, ASCII text", "text/jsx"),
        "tsx" => ("TSX source, ASCII text", "text/tsx"),
        "go" => ("Go source, ASCII text", "text/x-go"),
        "rb" => ("Ruby source, ASCII text", "text/x-ruby"),
        "php" => ("PHP source, ASCII text", "text/x-php"),
        "cs" => ("C# source, ASCII text", "text/x-csharp"),
        "swift" => ("Swift source, ASCII text", "text/x-swift"),
        "kt" | "kts" => ("Kotlin source, ASCII text", "text/x-kotlin"),
        "scala" => ("Scala source, ASCII text", "text/x-scala"),
        "lua" => ("Lua source, ASCII text", "text/x-lua"),
        "pl" => ("Perl source, ASCII text", "text/x-perl"),
        "r" => ("R source, ASCII text", "text/x-r"),
        "sh" => ("Bourne-Again shell script, ASCII text executable", "text/x-shellscript"),
        "bash" => ("Bash script, ASCII text executable", "text/x-shellscript"),
        "zsh" => ("Zsh script, ASCII text executable", "text/x-shellscript"),
        "fish" => ("Fish shell script, ASCII text", "text/x-fish"),
        "ps1" | "psm1" => ("PowerShell script, ASCII text", "text/x-powershell"),
        "bat" | "cmd" => ("DOS batch file, ASCII text", "text/x-msdos-batch"),
        "vbs" => ("VBScript, ASCII text", "text/vbscript"),
        "sql" => ("SQL source, ASCII text", "text/x-sql"),
        "hs" => ("Haskell source, ASCII text", "text/x-haskell"),
        "ml" => ("OCaml source, ASCII text", "text/x-ocaml"),
        "erl" => ("Erlang source, ASCII text", "text/x-erlang"),
        "ex" | "exs" => ("Elixir source, ASCII text", "text/x-elixir"),
        "dart" => ("Dart source, ASCII text", "text/x-dart"),
        "zig" => ("Zig source, ASCII text", "text/x-zig"),
        "nim" => ("Nim source, ASCII text", "text/x-nim"),
        "v" => ("V source, ASCII text", "text/x-v"),
        "asm" | "s" => ("Assembler source, ASCII text", "text/x-asm"),
        "toml" => ("TOML document, ASCII text", "text/x-toml"),
        "yaml" | "yml" => ("YAML document, ASCII text", "text/yaml"),
        "json" => ("JSON data, ASCII text", "application/json"),
        "jsonl" => ("JSON Lines data, ASCII text", "application/jsonl"),
        "xml" => ("XML document, ASCII text", "text/xml"),
        "html" | "htm" => ("HTML document, ASCII text", "text/html"),
        "css" => ("CSS stylesheet, ASCII text", "text/css"),
        "scss" => ("SCSS stylesheet, ASCII text", "text/x-scss"),
        "less" => ("LESS stylesheet, ASCII text", "text/x-less"),
        "md" | "markdown" => ("Markdown document, UTF-8 Unicode text", "text/markdown"),
        "rst" => ("reStructuredText document, ASCII text", "text/x-rst"),
        "txt" => ("ASCII text", "text/plain"),
        "log" => ("ASCII text (log)", "text/plain"),
        "csv" => ("CSV text", "text/csv"),
        "tsv" => ("TSV text", "text/tab-separated-values"),
        "ini" | "cfg" | "conf" => ("INI configuration file, ASCII text", "text/plain"),
        "makefile" => ("makefile script, ASCII text", "text/x-makefile"),
        "dockerfile" => ("Dockerfile, ASCII text", "text/x-dockerfile"),
        "cmake" => ("CMake script, ASCII text", "text/x-cmake"),

        // Data formats
        "proto" => ("Protocol Buffer definition, ASCII text", "text/x-proto"),
        "graphql" | "gql" => ("GraphQL schema, ASCII text", "text/x-graphql"),
        "tf" => ("Terraform configuration, ASCII text", "text/x-terraform"),
        "dockerignore" | "gitignore" => ("ignore file, ASCII text", "text/plain"),
        "properties" => ("Java properties, ASCII text", "text/x-java-properties"),

        // Common binary formats by extension
        "exe" => ("PE32 executable (Windows)", "application/x-dosexec"),
        "dll" => ("PE32 DLL (Windows)", "application/x-dosexec"),
        "so" => ("ELF shared object", "application/x-elf"),
        "dylib" => ("Mach-O dynamic library", "application/x-mach-binary"),
        "a" => ("ar archive (static library)", "application/x-archive"),
        "o" => ("ELF relocatable object", "application/x-elf"),
        "lib" => ("COFF static library", "application/x-archive"),
        "obj" => ("COFF object file", "application/x-coff"),

        // Documents
        "docx" => ("Microsoft Word 2007+ document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xlsx" => ("Microsoft Excel 2007+ spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "pptx" => ("Microsoft PowerPoint 2007+ presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "doc" => ("Microsoft Word document", "application/msword"),
        "xls" => ("Microsoft Excel spreadsheet", "application/vnd.ms-excel"),
        "ppt" => ("Microsoft PowerPoint presentation", "application/vnd.ms-powerpoint"),
        "odt" => ("OpenDocument text", "application/vnd.oasis.opendocument.text"),
        "ods" => ("OpenDocument spreadsheet", "application/vnd.oasis.opendocument.spreadsheet"),
        "odp" => ("OpenDocument presentation", "application/vnd.oasis.opendocument.presentation"),
        "rtf" => ("Rich Text Format data", "application/rtf"),
        "epub" => ("EPUB document", "application/epub+zip"),
        "mobi" => ("Mobipocket eBook", "application/x-mobipocket-ebook"),

        // Images
        "png" => ("PNG image data", "image/png"),
        "jpg" | "jpeg" => ("JPEG image data", "image/jpeg"),
        "gif" => ("GIF image data", "image/gif"),
        "bmp" => ("BMP image data", "image/bmp"),
        "ico" => ("ICO image data", "image/x-icon"),
        "svg" => ("SVG image data", "image/svg+xml"),
        "webp" => ("WebP image data", "image/webp"),
        "tiff" | "tif" => ("TIFF image data", "image/tiff"),
        "psd" => ("Adobe Photoshop image", "image/vnd.adobe.photoshop"),
        "raw" | "cr2" | "nef" | "orf" | "arw" => ("RAW image data", "image/x-raw"),
        "heic" | "heif" => ("HEIF image data", "image/heif"),
        "avif" => ("AVIF image data", "image/avif"),

        // Audio
        "mp3" => ("MP3 audio data", "audio/mpeg"),
        "wav" => ("WAVE audio data", "audio/wav"),
        "flac" => ("FLAC audio data", "audio/flac"),
        "aac" => ("AAC audio data", "audio/aac"),
        "ogg" => ("Ogg audio data", "audio/ogg"),
        "wma" => ("Windows Media Audio", "audio/x-ms-wma"),
        "m4a" => ("M4A audio data", "audio/mp4"),
        "opus" => ("Opus audio data", "audio/opus"),
        "mid" | "midi" => ("MIDI audio data", "audio/midi"),
        "ape" => ("Monkey's Audio (APE)", "audio/x-ape"),

        // Video
        "mp4" => ("MP4 video data", "video/mp4"),
        "avi" => ("AVI video data", "video/avi"),
        "mkv" => ("Matroska video data", "video/x-matroska"),
        "webm" => ("WebM video data", "video/webm"),
        "mov" => ("QuickTime movie", "video/quicktime"),
        "wmv" => ("Windows Media Video", "video/x-ms-wmv"),
        "flv" => ("Flash video data", "video/x-flv"),
        "mpeg" | "mpg" => ("MPEG video data", "video/mpeg"),
        "3gp" => ("3GPP multimedia", "video/3gpp"),
        "m2ts" => ("MPEG transport stream", "video/mp2t"),

        // Archives
        "zip" => ("Zip archive data", "application/zip"),
        "gz" | "gzip" => ("gzip compressed data", "application/gzip"),
        "bz2" => ("bzip2 compressed data", "application/x-bzip2"),
        "xz" => ("XZ compressed data", "application/x-xz"),
        "lzma" => ("LZMA compressed data", "application/x-lzma"),
        "rar" => ("RAR archive data", "application/x-rar"),
        "7z" => ("7-zip archive data", "application/x-7z-compressed"),
        "tar" => ("tar archive", "application/x-tar"),
        "zst" => ("Zstandard compressed data", "application/zstd"),
        "lz4" => ("LZ4 compressed data", "application/x-lz4"),
        "cab" => ("Microsoft Cabinet archive", "application/vnd.ms-cab-compressed"),

        // Fonts
        "ttf" => ("TrueType font data", "font/ttf"),
        "otf" => ("OpenType font data", "font/otf"),
        "woff" => ("WOFF font data", "font/woff"),
        "woff2" => ("WOFF2 font data", "font/woff2"),
        "eot" => ("Embedded OpenType font", "application/vnd.ms-fontobject"),

        // Other
        "pdf" => ("PDF document", "application/pdf"),
        "ps" => ("PostScript document", "application/postscript"),
        "torrent" => ("BitTorrent torrent file", "application/x-bittorrent"),
        "iso" => ("ISO 9660 disk image", "application/x-iso9660-image"),
        "img" => ("disk image", "application/octet-stream"),
        "swap" => ("swap file", "application/octet-stream"),

        _ => return None,
    };
    Some(MagicMatch {
        description: desc.to_string(),
        mime_type: mime.to_string(),
    })
}
