# file

Windows 版 Linux `file` 命令，使用 Rust 实现。

## 功能

- **魔数检测**：100+ 文件格式签名识别（图片、音频、视频、压缩包、可执行文件、文档等）
- **PE32/PE32+ 详细分析**：架构（x86/x64/ARM）、子系统（Console/GUI/Native）、DLL 识别
- **ELF 32/64 位详细分析**
- **文本编码检测**：UTF-8/16/32 BOM、GBK、Big5、Shift_JIS、EUC-JP/KR、KOI8-R 等
- **行尾符检测**：CRLF / LF / CR / mixed
- **源代码识别**：基于扩展名识别 30+ 编程语言
- **内容语言检测**：通过内容启发式识别 Shell、Python、Rust、C/C++、Java 等
- **MIME 类型输出**（`-i`）
- **递归目录扫描**（`-r`）
- **从文件读取列表**（`-f`）
- **自定义分隔符**（`-F`）
- **简洁模式**（`-b`）
- **符号链接处理**（`-h` / `-L`）
- **标准输入支持**

## 构建

```bash
cargo build --release
```

输出文件：`target/release/file.exe`

## 使用

```bash
# 识别文件类型
file *.exe *.png *.txt

# 输出 MIME 类型
file --mime-type document.pdf

# 简洁模式（不显示文件名）
file --brief *.rs

# 递归扫描目录
file --recursive src/

# 自定义分隔符
file -F " -> " file.txt

# 从文件列表读取
file -f filelist.txt

# 读取标准输入
echo "hello" | file -
```

## 示例输出

```
C:\Windows\notepad.exe: PE32+ executable (x86-64, 32-bit+ (PE32+), console)
C:\Windows\System32\kernel32.dll: PE32+ DLL (x86-64, 32-bit+ (PE32+))
image.png: PNG image data (1.2 MiB)
data.gz: gzip compressed data, was "Unix" (deflate)
src/main.rs: Rust source, UTF-8 Unicode text (5.0 KiB)
config.json: JSON data, UTF-8 Unicode text (128 bytes)
```

## 命令行选项

```
Usage: file [OPTIONS] [FILES]...

Arguments:
  [FILES]...  Files to examine

Options:
  -i, --mime-type                Show MIME type
  -I, --mime-encoding            Output MIME encoding
  -h, --no-dereference           Don't follow symbolic links
  -L, --dereference              Follow symbolic links
  -f, --files-from <FILES_FROM>  Read file names from FILE (one per line)
  -s, --special-files            Read from stdin
  -r, --recursive                Recursive directory traversal
  -F, --separator <SEPARATOR>    Separator [default: ": "]
  -b, --brief                    Do not prepend filenames
  -v, --verbose                  Verbose mode
  -V, --version                  Print version
```

## License

MIT
