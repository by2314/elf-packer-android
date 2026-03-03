# 加固大师 (ELF + APK Protection Suite for Android)

> Android 一体化保护工具，支持对 ELF 可执行文件加壳和对 Android APK 多维度加固混淆。

![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B-brightgreen)
![Language](https://img.shields.io/badge/Language-Java-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## 📖 项目简介

本工具是一款运行在 Android 设备上的一体化安全保护工具，提供两大功能模块：

### ⚙️ ELF 文件加壳

| 保护方式 | 英文名 | 原理简介 |
|---------|--------|---------|
| 🔒 UPX 压缩加壳 | UPX Packing | DEFLATE 压缩 + UPX 魔数头，减小体积并防止静态分析 |
| 📦 GZIP 加密压缩 | GZIP Encryption | AES-256-CBC 加密 + GZIP 压缩双重保护，密钥由文件 SHA-256 哈希派生 |
| 🛡️ VMP 虚拟机保护 | Virtual Machine Protection | 解析 ELF PT_LOAD 段、XOR 加密代码段 + 注入 64 字节 VM 解释器头 |
| 🔀 OLLVM 混淆 | OLLVM Obfuscation | 控制流平坦化 + 指令替换 + 虚假控制流三重混淆 |

### 📦 APK 加固保护

| 保护方式 | 英文名 | 原理简介 |
|---------|--------|---------|
| 🔤 字符串混淆 | String Obfuscation | XOR 加密 DEX 字符串常量池，密钥存入 `META-INF/str_keys.bin` |
| 📁 资源文件混淆 | Asset Obfuscation | 随机重命名 `assets/` 目录文件 + XOR 加密内容，映射存入 `META-INF/asset_map.bin` |
| 🏷️ 类名方法名混淆 | Class/Method Obfuscation | DEX 字符串池内替换类描述符和方法名为随机字母串 |
| ⚡ DEX2C 本地化 | DEX2C Protection | 解析 DEX 方法表 + 注入 ARM64 native stub ELF + 生成 `META-INF/dex2c_manifest.bin` |

多种 APK 保护方式可以**叠加组合**，以流水线方式依次执行。

---

## 🚀 使用方法

### ELF 文件加壳
1. 打开应用，点击「ELF 文件加壳」卡片
2. 选择加壳方式（UPX / GZIP+AES / VMP / OLLVM）
3. 点击「选择 ELF 文件并加壳」，从文件管理器选取目标文件
4. 等待处理完成，查看结果并导出/分享

### APK 加固保护
1. 点击「APK 加固保护」卡片
2. 点击「选择 APK 文件并加固」，选取目标 APK
3. 勾选所需保护技术（可多选）
4. 点击「开始加固」，等待处理完成后查看结果

输出文件保存在：`/sdcard/Android/data/com.elfpacker.app/files/packed/`

---

## 🔧 技术原理

### ELF 加壳

#### UPX 压缩加壳
写入 13 字节 UPX 魔数头（`!UPX` + 版本/方法标志），用 DEFLATE 算法压缩原始 ELF 数据，
写入原始长度（4 字节 LE），便于解压存根分配缓冲区。

#### GZIP 加密压缩
1. 计算原始文件 SHA-256 哈希值
2. 生成随机 16 字节 IV，用 PBKDF2WithHmacSHA256（10000 次迭代）派生 AES-256 密钥
3. AES-256-CBC 加密原始数据
4. GZIP 压缩密文
5. 写入 8 字节 Magic + 16 字节 IV + 4 字节原始长度 + GZIP 数据

#### VMP 虚拟机保护
1. 解析 ELF 头（EI_CLASS、e_machine、e_entry、程序头表）
2. 定位覆盖入口点的 PT_LOAD 段（即 .text 所在段）
3. 生成 32 字节随机 XOR 密钥，对代码段逐字节加密
4. 在文件起始处注入 64 字节 VM 头（含密钥和加密区间信息）

#### OLLVM 混淆
1. **指令替换**：以 4 字节为单位对约 33% 的字执行等价变换 `w → ~w ^ 0xA5A5A5A5`
2. **控制流平坦化**：将代码分成 64 字节块并随机打乱存储顺序，写入块索引表
3. **虚假控制流**：追加约 10% 大小的随机"死代码"字节块

### APK 加固

#### 字符串混淆
遍历 APK（ZIP）内所有 `.dex` 文件，解析 DEX 字符串池（`string_ids` 表），
对每个字符串数据字节执行 XOR 加密（per-DEX 独立 32 字节随机密钥）。
密钥映射写入 `META-INF/str_keys.bin`。

#### 资源文件混淆
将 `assets/` 目录下所有文件重命名为随机 8 字符十六进制名称（保留扩展名），
并对文件内容进行 XOR 加密（16 字节随机密钥）。
原始路径与混淆路径的映射及密钥写入 `META-INF/asset_map.bin`。

#### 类名方法名混淆
直接操作 DEX 字符串池字节，将类型描述符（`Lpackage/ClassName;`）中的简单类名
和方法名替换为随机 4-6 字符字母串（保留 `<init>`、`onCreate` 等框架保留名）。
重命名映射写入 `META-INF/class_map.bin`。

#### DEX2C 本地化
1. 解析 DEX `method_id` 表，提取前 50 个方法的类名和方法名
2. 生成合法 ARM64 ELF64 共享库骨架（`lib/arm64-v8a/libdex2c_stub.so`），
   导出 JNI 桥接符号 `Java_com_elfpacker_dex2c_NativeBridge_invoke`
3. 将方法列表写入 `META-INF/dex2c_manifest.bin` 供运行时 stub 使用

---

## 🏗️ 构建方法

```bash
# 克隆项目
git clone https://github.com/by2314/elf-packer-android.git
cd elf-packer-android

# 使用 Android Studio 打开或命令行构建
./gradlew assembleDebug

# 输出 APK 位于
# app/build/outputs/apk/debug/app-debug.apk
```

**环境要求：**
- Android Studio Hedgehog 或更高版本
- JDK 17+
- Android SDK API 34

---

## 📁 项目结构

```
app/src/main/java/com/elfpacker/app/
├── MainActivity.java                 # 主入口，ELF/APK 两大功能入口
├── packer/
│   ├── ElfPacker.java                # ELF 加壳接口
│   ├── UpxPacker.java                # UPX 压缩加壳
│   ├── GzipPacker.java               # AES-256-CBC + GZIP 加密
│   ├── VmpPacker.java                # VMP 虚拟机保护
│   └── OllvmPacker.java              # OLLVM 三重混淆
├── protector/
│   ├── ApkProtector.java             # APK 保护接口
│   ├── StringObfuscator.java         # DEX 字符串池 XOR 加密
│   ├── AssetObfuscator.java          # assets 重命名 + XOR 加密
│   ├── ClassNameObfuscator.java      # 类名/方法名随机化
│   └── Dex2CProtector.java           # native stub 注入
├── ui/
│   ├── ElfPackerActivity.java        # ELF 加壳界面
│   ├── ApkProtectorActivity.java     # APK 加固界面
│   └── PackerResultActivity.java     # 结果展示界面
└── utils/
    └── FileUtils.java                # 文件 I/O 工具
```

---

## ⚠️ 免责声明

**本工具仅供合法用途：**
- ✅ 保护开发者自有的合法软件
- ✅ 安全研究与学习
- ✅ CTF 竞赛练习
- ❌ 禁止用于保护恶意软件、病毒或任何违法程序
- ❌ 禁止用于侵犯他人知识产权

使用本工具即代表您同意仅将其用于合法目的。作者不对任何滥用行为承担责任。

---

## 📄 License

MIT License © 2026 by2314
