# file 命令实现原理

## 项目概述

本项目是一个用 Rust 实现的 Windows 版 Linux `file` 命令。主要目标是为 [yazi](https://github.com/sxyazi/yazi) 终端文件管理器提供 MIME 类型检测支持，使其能够正确显示文件信息和预览。

yazi 在 Windows 上通过以下方式调用：

```
file -bL --mime-type -f -
```

即从 stdin 逐行接收文件路径，为每个文件输出 MIME 类型。

## 整体架构

```
src/
├── main.rs      # CLI 入口，参数解析，输出格式化
├── magic.rs     # 魔数检测，扩展名匹配
├── text.rs      # 文本分析，编码检测，语言识别
└── analyzer.rs  # 分析协调器，串联所有检测步骤
```

### 模块职责

| 模块 | 职责 |
|------|------|
| `main.rs` | 使用 clap 解析命令行参数，遍历文件，格式化输出结果 |
| `magic.rs` | 通过文件头部字节签名（魔数）识别文件类型，以及通过扩展名回退识别 |
| `text.rs` | 判断文件是否为文本，检测编码，分析行尾格式，启发式识别编程语言 |
| `analyzer.rs` | 协调检测流程，按优先级依次调用 magic 和 text 模块，组装最终结果 |

## 检测流水线

对每个文件，按以下优先级依次检测，命中即返回：

```
1. 文件系统检查
   ├── 符号链接 → "symbolic link to '...'"
   ├── 块设备/字符设备/FIFO/Socket（仅 Unix）
   ├── 目录 → "directory"
   └── 空文件 → "empty"

2. 读取文件头部（前 64KB）

3. 解压缩（仅 -z/-Z 参数）
   └── 尝试 gzip/zlib 解压，对解压后内容继续检测

4. 魔数检测（最高优先级）
   ├── 特殊格式深度解析：PE → ELF → Ogg → gzip → ftyp（MP4/HEIF/AVIF）→ XML
   ├── 线性扫描 MAGIC_DB（~200 条规则）
   └── 命中返回 description + mime_type

5. 文本分析
   ├── is_text() 判断是否为文本
   ├── analyze_text() 检测编码 + 语言
   ├── 扩展名匹配（文本类扩展名）
   └── 返回 "ASCII text" / "UTF-8 Unicode text" / 语言 + 编码

6. 扩展名回退（二进制文件）
   └── 通过扩展名猜测类型（如 .exe → PE32）

7. 兜底
   └── "data" / "application/octet-stream"
```

## 魔数检测

### 原理

文件格式的头部通常包含固定的字节序列，称为"魔数"（Magic Number）。例如：

| 格式 | 偏移 | 魔数字节 | 说明 |
|------|------|----------|------|
| PNG | 0 | `89 50 4E 47 0D 0A 1A 0A` | `\x89PNG\r\n\x1a\n` |
| JPEG | 0 | `FF D8 FF` | |
| ZIP | 0 | `50 4B 03 04` | `PK\x03\x04` |
| PDF | 0 | `25 50 44 46` | `%PDF` |
| GZIP | 0 | `1F 8B` | |

### MAGIC_DB 规则表

所有规则以静态数组的形式编译进二进制：

```rust
struct MagicRule {
    offset: usize,        // 检测偏移量
    magic: &'static [u8], // 期望的字节序列
    description: &'static str,
    mime_type: &'static str,
    extra: Option<ExtraCheck>,  // 可选的第二偏移校验
}
```

`extra` 字段用于需要双重校验的格式。例如 WebP 需要偏移 0 处是 `RIFF`，偏移 8 处是 `WEBP`：

```rust
magic!(0, b"RIFF", "WebP image data", "image/webp", extra 8, b"WEBP")
```

规则按类别组织：图片、压缩包、音频、视频、可执行文件、文档、数据库、字体、加密/安全、磁盘镜像等，共约 200 条。

### 特殊格式深度解析

某些格式需要比简单字节匹配更复杂的分析：

**PE 可执行文件**（`analyze_pe`）：读取 PE 头部偏移 → 解析机器架构（x86/x86-64/ARM64）→ 判断 DLL/EXE → 读取子系统类型（console/GUI/native/EFI 等），输出如 `PE32+ executable (GUI) x86-64, for MS Windows`。

**ELF 可执行文件**（`analyze_elf`）：解析 32/64 位 → 字节序（LSB/MSB）→ 类型（executable/shared object/core）→ 机器类型（x86-64/AArch64/RISC-V 等），输出如 `ELF 64-bit LSB executable, x86-64`。

**Gzip**（`analyze_gzip`）：解析压缩方法、标志位（是否有原始文件名、注释等）、OS 字节，输出如 `gzip compressed data, was "Unix" (deflate, has original filename)`。

**Ogg 容器**（`analyze_ogg`）：检查容器内的编解码器标识，区分 Vorbis/Opus/FLAC/Theora。

**ftyp 容器**（MP4/HEIF/AVIF/QuickTime 等）：读取 brand 字段区分具体格式和 MIME 类型。

### 扩展名匹配

当魔数检测未命中时，通过文件扩展名回退识别。扩展名匹配表在 `guess_by_extension()` 中定义，覆盖 100+ 种扩展名。

扩展名分为两类：
- **text_type = true**：文本类文件（如 `.rs`、`.py`、`.json`），检测结果会附带编码信息
- **text_type = false**：二进制文件（如 `.exe`、`.zip`、`.png`），直接返回类型描述

## 文本分析

### 文本 vs 二进制判断（`is_text`）

按以下步骤判断文件是否为文本：

1. **BOM 检查**：UTF-8/UTF-16 BOM → 文本
2. **空字节检查**：存在空字节 → 可能是 UTF-16（每隔一字节为 0），否则 → 二进制
3. **控制字符统计**：控制字符占比 > 10% → 二进制
4. **高字节检查**：高字节数 > 30% → 验证 UTF-8 有效性
5. **UTF-8 验证**：有效 UTF-8 → 文本，否则 → 检查可打印字符比例 > 85% → 文本

### 编码检测（`decode_text`）

按优先级依次尝试：

```
BOM 检测
├── EF BB BF     → UTF-8 (with BOM)
├── FF FE         → UTF-16 LE
├── FE FF         → UTF-16 BE
├── FF FE 00 00   → UTF-32 LE
└── 00 00 FE FF   → UTF-32 BE

UTF-8 验证
├── 纯 ASCII（所有字节 ≤ 0x7F）→ "ascii"
└── 有效 UTF-8              → "utf-8"

多编码尝试（使用 encoding_rs）
├── Windows-1252
├── GBK
├── Big5
├── Shift_JIS
├── EUC-JP
├── EUC-KR
├── KOI8-R
├── ISO-8859-2/5/7/10
└── Windows-1251

兜底 → lossy UTF-8, "unknown"
```

对每种编码，用 `is_plausible_text()` 验证：可打印字符比例 > 95% 才认为匹配成功。

### 行尾检测

统计 CRLF、LF、CR 的出现次数，判断主要行尾格式：`LF`（Unix）、`CRLF`（Windows）、`CR`（旧 Mac）、`mixed`（混合）、`no line terminators`（无换行）。

### 语言启发式检测（`detect_language`）

通过内容模式匹配识别编程语言和文档类型：

- **Shebang**：`#!/bin/sh` → shell, `#!/usr/bin/env python` → Python
- **关键字组合**：`fn ` + `use ` + `impl ` → Rust, `#include <` + `int main` → C
- **标记语言**：`<!DOCTYPE html` → HTML, `<?xml` → XML, `---\n` + `: ` → YAML
- **数据格式**：`{` + `":` → JSON, `[` + `: ` + `= ` → TOML
- **特殊文件**：`FROM ` → Dockerfile, `all:` / `clean:` → Makefile, `diff --git` → diff/patch

## CLI 选项

### 常用选项

| 选项 | 说明 |
|------|------|
| `-b` / `--brief` | 不输出文件名，只输出描述 |
| `-L` / `--dereference` | 跟随符号链接 |
| `-h` / `--no-dereference` | 不跟随符号链接 |
| `-i` / `--mime` | 输出 MIME 类型 + 字符集 |
| `--mime-type` | 只输出 MIME 类型 |
| `--mime-encoding` | 只输出字符编码 |
| `--extension` | 输出有效扩展名列表 |
| `-f` / `--files-from` | 从文件或 stdin（`-f -`）读取文件列表 |
| `-z` / `--uncompress` | 查看压缩文件内部内容 |
| `-F` / `--separator` | 自定义文件名与描述的分隔符 |

### 输出模式示例

```
# 普通模式
$ file src/main.rs
src/main.rs: Rust source, UTF-8 Unicode text

# --mime-type（yazi 使用）
$ file -bL --mime-type -- src/main.rs
text/rust

# --mime
$ file --mime src/main.rs
src/main.rs: text/rust; charset=utf-8

# -f -（yazi Windows 模式，从 stdin 读路径）
$ echo "src/main.rs" | file -bL --mime-type -f -
text/rust
```

## 与 Linux file 的关键差异

| 方面 | Linux `file` | 本实现 |
|------|-------------|--------|
| Magic 数据库 | 外部文件 `magic.mgc`（2000+ 条规则），运行时加载 | 硬编码静态数组（~200 条），编译进二进制 |
| 规则表达力 | DSL 支持间接偏移、正则、递归调用、强度排序 | 固定偏移 + 字节序列精确匹配 + 第二偏移校验 |
| 部署方式 | 需附带 magic.mgc | 单文件，无外部依赖 |
| 格式覆盖 | 包含大量冷门格式（Amiga、Atari、VMS 等） | 覆盖常见格式（95% 实际使用场景） |
| 可扩展性 | 用户可添加自定义 magic 文件 | 需修改源码重编译 |
| 文本编码 | `text_chars[256]` 查表 + EBCDIC/UTF-7 支持 | `encoding_rs` 库 + 统计判断，覆盖 CJK 编码 |
| 安全性 | libmagic 有 CVE 历史（C 语言） | Rust 内存安全保证 |
| 启动开销 | 需加载并解析数据库文件 | 零开销 |
