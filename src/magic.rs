/// Magic number database for file type identification.
/// Covers the most common file formats found in real-world usage.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct MagicMatch {
    pub description: String,
    pub mime_type: String,
    /// If true, description is a type hint and should be combined with encoding info
    pub text_type: bool,
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
    let (_pe_type, subsystem_offset) = match opt_magic {
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
        3 => "GUI",
        7 => "POSIX",
        9 => "Windows CE",
        10 => "EFI",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        _ => "unknown",
    };

    if is_dll {
        format!("PE32+ dynamic link library (DLL) ({}) {}, for MS Windows", sub_desc, arch)
    } else {
        format!("PE32+ executable ({}) {}, for MS Windows", sub_desc, arch)
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
            text_type: false,
        });
    }

    // ELF executable
    if data.len() >= 5 && data[0] == 0x7F && &data[1..4] == b"ELF" {
        let desc = analyze_elf(data);
        return Some(MagicMatch {
            description: desc,
            mime_type: "application/x-elf".to_string(),
            text_type: false,
        });
    }

    // Ogg container
    if data.len() >= 4 && &data[0..4] == b"OggS" {
        return Some(MagicMatch {
            description: analyze_ogg(data),
            mime_type: "application/ogg".to_string(),
            text_type: false,
        });
    }

    // Gzip
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return Some(MagicMatch {
            description: analyze_gzip(data),
            mime_type: "application/gzip".to_string(),
            text_type: false,
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
                text_type: false,
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
            text_type: false,
        });
    }

    // XML detection (with or without BOM)
    if data.len() >= 5 {
        // UTF-8 BOM + XML
        if data.len() >= 8 && &data[0..3] == b"\xEF\xBB\xBF" && (&data[3..8] == b"<?xml" || &data[3..5] == b"<?") {
            return Some(MagicMatch {
                description: "XML 1.0 document text (UTF-8 BOM)".to_string(),
                mime_type: "text/xml".to_string(),
                text_type: false,
            });
        }
        // Direct XML
        if &data[0..5] == b"<?xml" {
            return Some(MagicMatch {
                description: "XML 1.0 document text".to_string(),
                mime_type: "text/xml".to_string(),
                text_type: false,
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
                text_type: false,
            });
        }
    }

    None
}

/// Try to guess file type from extension as fallback
pub fn guess_by_extension(path: &Path) -> Option<MagicMatch> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    // (description, mime, is_text_type)
    let (desc, mime, text_type) = match ext.as_str() {
        // Programming languages - type only, encoding added dynamically
        "rs" => ("Rust source", "text/rust", true),
        "c" => ("C source", "text/x-c", true),
        "h" => ("C header", "text/x-c", true),
        "cpp" | "cc" | "cxx" => ("C++ source", "text/x-c++", true),
        "hpp" | "hh" | "hxx" => ("C++ header", "text/x-c++", true),
        "java" => ("Java source", "text/x-java", true),
        "py" => ("Python script", "text/x-python", true),
        "js" => ("JavaScript source", "text/javascript", true),
        "ts" => ("TypeScript source", "text/typescript", true),
        "mts" | "cts" => ("TypeScript source", "text/typescript", true),
        "jsx" => ("JSX source", "text/jsx", true),
        "tsx" => ("TSX source", "text/tsx", true),
        "go" => ("Go source", "text/x-go", true),
        "rb" => ("Ruby source", "text/x-ruby", true),
        "php" => ("PHP script", "text/x-php", true),
        "cs" => ("C# source", "text/x-csharp", true),
        "swift" => ("Swift source", "text/x-swift", true),
        "kt" | "kts" => ("Kotlin source", "text/x-kotlin", true),
        "scala" => ("Scala source", "text/x-scala", true),
        "lua" => ("Lua source", "text/x-lua", true),
        "pl" => ("Perl script", "text/x-perl", true),
        "r" => ("R source", "text/x-r", true),
        "sh" => ("Bourne-Again shell script", "text/x-shellscript", true),
        "bash" => ("Bourne-Again shell script", "text/x-shellscript", true),
        "zsh" => ("Zsh script", "text/x-shellscript", true),
        "fish" => ("Fish shell script", "text/x-fish", true),
        "ps1" | "psm1" => ("PowerShell script", "text/x-powershell", true),
        "bat" | "cmd" => ("DOS batch file", "text/x-msdos-batch", true),
        "vbs" => ("VBScript", "text/vbscript", true),
        "sql" => ("SQL source", "text/x-sql", true),
        "hs" => ("Haskell source", "text/x-haskell", true),
        "erl" => ("Erlang source", "text/x-erlang", true),
        "ex" | "exs" => ("Elixir source", "text/x-elixir", true),
        "dart" => ("Dart source", "text/x-dart", true),
        "zig" => ("Zig source", "text/x-zig", true),
        "nim" => ("Nim source", "text/x-nim", true),
        "asm" | "s" => ("Assembler source", "text/x-asm", true),
        "toml" => ("TOML document", "text/x-toml", true),
        "yaml" | "yml" => ("YAML document", "text/yaml", true),
        "json" => ("JSON data", "application/json", true),
        "jsonl" => ("JSON Lines data", "application/jsonl", true),
        "xml" => ("XML document", "text/xml", true),
        "html" | "htm" => ("HTML document", "text/html", true),
        "css" => ("CSS stylesheet", "text/css", true),
        "scss" => ("SCSS stylesheet", "text/x-scss", true),
        "less" => ("LESS stylesheet", "text/x-less", true),
        "md" | "markdown" => ("Markdown document", "text/markdown", true),
        "rst" => ("reStructuredText document", "text/x-rst", true),
        "txt" => ("", "text/plain", true), // plain text, just show encoding
        "log" => ("", "text/plain", true),
        "csv" => ("CSV text", "text/csv", true),
        "tsv" => ("TSV text", "text/tab-separated-values", true),
        "ini" | "cfg" | "conf" => ("INI configuration file", "text/plain", true),
        "makefile" => ("makefile script", "text/x-makefile", true),
        "dockerfile" => ("Dockerfile", "text/x-dockerfile", true),
        "cmake" => ("CMake script", "text/x-cmake", true),
        "proto" => ("Protocol Buffer definition", "text/x-proto", true),
        "graphql" | "gql" => ("GraphQL schema", "text/x-graphql", true),
        "tf" => ("Terraform configuration", "text/x-terraform", true),
        "dockerignore" | "gitignore" => ("ignore file", "text/plain", true),
        "properties" => ("Java properties", "text/x-java-properties", true),

        // Common binary formats by extension
        "exe" => ("PE32 executable (Windows)", "application/x-dosexec", false),
        "dll" => ("PE32 DLL (Windows)", "application/x-dosexec", false),
        "so" => ("ELF shared object", "application/x-elf", false),
        "dylib" => ("Mach-O dynamic library", "application/x-mach-binary", false),
        "a" => ("ar archive (static library)", "application/x-archive", false),
        "o" => ("ELF relocatable object", "application/x-elf", false),
        "lib" => ("COFF static library", "application/x-archive", false),
        "obj" => ("COFF object file", "application/x-coff", false),

        // Documents (binary)
        "docx" => ("Microsoft Word 2007+ document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", false),
        "xlsx" => ("Microsoft Excel 2007+ spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", false),
        "pptx" => ("Microsoft PowerPoint 2007+ presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation", false),
        "doc" => ("Microsoft Word document", "application/msword", false),
        "xls" => ("Microsoft Excel spreadsheet", "application/vnd.ms-excel", false),
        "ppt" => ("Microsoft PowerPoint presentation", "application/vnd.ms-powerpoint", false),
        "odt" => ("OpenDocument text", "application/vnd.oasis.opendocument.text", false),
        "ods" => ("OpenDocument spreadsheet", "application/vnd.oasis.opendocument.spreadsheet", false),
        "odp" => ("OpenDocument presentation", "application/vnd.oasis.opendocument.presentation", false),
        "rtf" => ("Rich Text Format data", "application/rtf", false),
        "epub" => ("EPUB document", "application/epub+zip", false),
        "mobi" => ("Mobipocket eBook", "application/x-mobipocket-ebook", false),

        // Images
        "png" => ("PNG image data", "image/png", false),
        "jpg" | "jpeg" => ("JPEG image data", "image/jpeg", false),
        "gif" => ("GIF image data", "image/gif", false),
        "bmp" => ("BMP image data", "image/bmp", false),
        "ico" => ("ICO image data", "image/x-icon", false),
        "svg" => ("SVG image data", "image/svg+xml", true),
        "webp" => ("WebP image data", "image/webp", false),
        "tiff" | "tif" => ("TIFF image data", "image/tiff", false),
        "psd" => ("Adobe Photoshop image", "image/vnd.adobe.photoshop", false),
        "raw" | "cr2" | "nef" | "orf" | "arw" => ("RAW image data", "image/x-raw", false),
        "heic" | "heif" => ("HEIF image data", "image/heif", false),
        "avif" => ("AVIF image data", "image/avif", false),

        // Audio
        "mp3" => ("MP3 audio data", "audio/mpeg", false),
        "wav" => ("WAVE audio data", "audio/wav", false),
        "flac" => ("FLAC audio data", "audio/flac", false),
        "aac" => ("AAC audio data", "audio/aac", false),
        "ogg" => ("Ogg audio data", "audio/ogg", false),
        "wma" => ("Windows Media Audio", "audio/x-ms-wma", false),
        "m4a" => ("M4A audio data", "audio/mp4", false),
        "opus" => ("Opus audio data", "audio/opus", false),
        "mid" | "midi" => ("MIDI audio data", "audio/midi", false),
        "ape" => ("Monkey's Audio (APE)", "audio/x-ape", false),

        // Video
        "mp4" => ("MP4 video data", "video/mp4", false),
        "avi" => ("AVI video data", "video/avi", false),
        "mkv" => ("Matroska video data", "video/x-matroska", false),
        "webm" => ("WebM video data", "video/webm", false),
        "mov" => ("QuickTime movie", "video/quicktime", false),
        "wmv" => ("Windows Media Video", "video/x-ms-wmv", false),
        "flv" => ("Flash video data", "video/x-flv", false),
        "mpeg" | "mpg" => ("MPEG video data", "video/mpeg", false),
        "3gp" => ("3GPP multimedia", "video/3gpp", false),
        "m2ts" => ("MPEG transport stream", "video/mp2t", false),

        // Archives
        "zip" => ("Zip archive data", "application/zip", false),
        "gz" | "gzip" => ("gzip compressed data", "application/gzip", false),
        "bz2" => ("bzip2 compressed data", "application/x-bzip2", false),
        "xz" => ("XZ compressed data", "application/x-xz", false),
        "lzma" => ("LZMA compressed data", "application/x-lzma", false),
        "rar" => ("RAR archive data", "application/x-rar", false),
        "7z" => ("7-zip archive data", "application/x-7z-compressed", false),
        "tar" => ("tar archive", "application/x-tar", false),
        "zst" => ("Zstandard compressed data", "application/zstd", false),
        "lz4" => ("LZ4 compressed data", "application/x-lz4", false),
        "cab" => ("Microsoft Cabinet archive", "application/vnd.ms-cab-compressed", false),

        // Fonts
        "ttf" => ("TrueType font data", "font/ttf", false),
        "otf" => ("OpenType font data", "font/otf", false),
        "woff" => ("WOFF font data", "font/woff", false),
        "woff2" => ("WOFF2 font data", "font/woff2", false),
        "eot" => ("Embedded OpenType font", "application/vnd.ms-fontobject", false),

        // Other
        "pdf" => ("PDF document", "application/pdf", false),
        "ps" => ("PostScript document", "application/postscript", false),
        "torrent" => ("BitTorrent torrent file", "application/x-bittorrent", false),
        "iso" => ("ISO 9660 disk image", "application/x-iso9660-image", false),
        "img" => ("disk image", "application/octet-stream", false),
        "swap" => ("swap file", "application/octet-stream", false),

        _ => return None,
    };
    Some(MagicMatch {
        description: desc.to_string(),
        mime_type: mime.to_string(),
        text_type,
    })
}
