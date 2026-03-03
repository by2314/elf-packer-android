# ELF 加壳工具 (ELF Packer for Android)

> Android APK 工具，对 ELF 可执行二进制文件进行加密加壳保护。

![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B-brightgreen)
![Language](https://img.shields.io/badge/Language-Java-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## 📖 项目简介

本工具是一款运行在 Android 设备上的 ELF 二进制文件加壳/加密工具，支持以下四种保护方式：

| 保护方式 | 英文名 | 原理简介 |
|---------|--------|---------|
| 🔒 UPX 压缩加壳 | UPX Packing | 压缩 ELF 文件，减小体积，加入自定义解压存根 |
| 📦 GZIP 加密压缩 | GZIP Encryption | AES-256-CBC 加密 + GZIP 压缩，双重保护 |
| 🛡️ VMP 虚拟机保护 | Virtual Machine Protection | 将代码段虚拟化，XOR 混淆 + VM 头注入 |
| 🔀 OLLVM 混淆 | OLLVM Obfuscation | 控制流平坦化 + 指令替换 + 虚假控制流三重混淆 |

---

## 🚀 使用方法

1. 安装 APK 到 Android 设备（Android 8.0+）
2. 打开应用，主界面显示 4 种加壳选项
3. 点击底部"选择 ELF 文件并加壳"按钮
4. 从文件管理器选取目标 ELF 文件
5. 在弹出对话框中选择加壳方式
6. 等待处理完成，查看结果并导出

---

## 🔧 技术原理

### UPX 压缩加壳
模拟 UPX 头部格式，将原始 ELF 数据用 DEFLATE 算法压缩，写入 UPX 魔数头（`!UPX`），生成带解压存根标记的输出文件。

### GZIP 加密压缩
1. 读取 ELF 文件内容
2. 使用 PBKDF2 从文件 SHA-256 哈希派生 AES-256 密钥
3. AES-256-CBC 加密原始数据
4. GZIP 压缩加密后的数据
5. 写入自定义文件头：Magic（8字节）+ IV（16字节）+ 长度（4字节）+ 数据

### VMP 虚拟机保护
1. 解析 ELF 头（Magic、架构、入口点）
2. 定位 `.text` 代码段
3. 对代码段进行逐字节 XOR 混淆（随机密钥）
4. 在文件起始处注入 VM 解释器标记头
5. 运行时由 VM 解释器解密并执行

### OLLVM 混淆
模拟 OLLVM 编译器的三种混淆 pass：
- **控制流平坦化**：将代码块打散重排，通过调度器控制执行流
- **指令替换**：将简单运算替换为等价但更复杂的操作序列
- **虚假控制流**：插入永远不会执行的虚假代码路径

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
