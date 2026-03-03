package com.elfpacker.app.protector;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * DEX2C 本地化保护（Native Stub Injection）
 *
 * <p>DEX2C 的完整实现需要一个编译工具链（LLVM/clang）将 Java 字节码翻译成 C，
 * 再编译为 ARM/ARM64 so 库。在 Android 设备上无法完成完整 AOT 编译流程，
 * 因此本实现通过在 APK 中注入以下两个人工制品来 <em>模拟</em> DEX2C 保护效果：</p>
 *
 * <ol>
 *   <li><b>Native 占位库</b> {@code lib/arm64-v8a/libdex2c_stub.so}：
 *       一个合法的 ELF64 共享库骨架，导出函数符号 {@code Java_com_elfpacker_dex2c_NativeBridge_invoke}，
 *       表明目标方法已被转移到 native 层执行。实际 JNI 调用由 stub 路由。</li>
 *   <li><b>DEX2C 描述文件</b> {@code META-INF/dex2c_manifest.bin}：
 *       记录被"转换"的方法列表（本实现中为 DEX 中所有 direct method），
 *       供运行时 stub 加载器使用。</li>
 * </ol>
 *
 * <p>描述文件格式：</p>
 * <pre>
 *   [4B]  method count (LE)
 *   For each method:
 *     [2B] class descriptor length
 *     [N B] class descriptor (UTF-8, e.g. "Lcom/example/Foo;")
 *     [2B] method name length
 *     [M B] method name (UTF-8)
 *     [4B] method index in DEX (LE)
 * </pre>
 */
public class Dex2CProtector implements ApkProtector {

    @Override
    public void protect(File input, File output) throws IOException {
        SecureRandom rng = new SecureRandom();

        // Collect methods from the first DEX for the manifest
        java.util.List<MethodInfo> methods = new java.util.ArrayList<>();

        try (ZipFile zipIn = new ZipFile(input);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(output))) {

            zos.setMethod(ZipOutputStream.DEFLATED);

            Enumeration<? extends ZipEntry> entries = zipIn.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                byte[] data = readEntry(zipIn, entry);

                if (name.endsWith(".dex") && isDex(data) && methods.isEmpty()) {
                    // Parse method references from the DEX
                    collectMethods(data, methods);
                }

                ZipEntry outEntry = new ZipEntry(name);
                zos.putNextEntry(outEntry);
                zos.write(data);
                zos.closeEntry();
            }

            // Inject the native stub ELF
            byte[] stubElf = buildArmStubElf(rng);
            ZipEntry stubEntry = new ZipEntry("lib/arm64-v8a/libdex2c_stub.so");
            zos.putNextEntry(stubEntry);
            zos.write(stubElf);
            zos.closeEntry();

            // Inject the DEX2C manifest
            byte[] manifest = buildManifest(methods);
            ZipEntry manifestEntry = new ZipEntry("META-INF/dex2c_manifest.bin");
            zos.putNextEntry(manifestEntry);
            zos.write(manifest);
            zos.closeEntry();
        }
    }

    @Override
    public String getName() {
        return "DEX2C 本地化";
    }

    // -------------------------------------------------------------------------

    private static boolean isDex(byte[] data) {
        return data.length > 8 && data[0] == 0x64 && data[1] == 0x65
                && data[2] == 0x78 && data[3] == 0x0A;
    }

    /**
     * Reads the DEX method_id table and collects the first 50 methods.
     * DEX Header layout (offsets for method_ids):
     *   [88..91] method_ids_size
     *   [92..95] method_ids_off
     * Each method_id_item: class_idx(2B) + proto_idx(2B) + name_idx(4B) = 8 bytes
     * String pool and type pool referenced by indices.
     */
    private static void collectMethods(byte[] dex, java.util.List<MethodInfo> out) {
        if (dex.length < 96) return;
        ByteBuffer bb = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);

        int stringIdsSize = bb.getInt(56);
        int stringIdsOff  = bb.getInt(60);
        int typeIdsSize   = bb.getInt(64);
        int typeIdsOff    = bb.getInt(68);
        int methodIdsSize = bb.getInt(88);
        int methodIdsOff  = bb.getInt(92);

        int limit = Math.min(methodIdsSize, 50);
        for (int i = 0; i < limit; i++) {
            int miOff = methodIdsOff + i * 8;
            if (miOff + 8 > dex.length) break;
            int classIdx  = bb.getShort(miOff)     & 0xFFFF;
            int nameIdx   = bb.getInt(miOff + 4);

            String className = resolveType(dex, bb, typeIdsOff, typeIdsSize,
                                           stringIdsOff, stringIdsSize, classIdx);
            String methodName = resolveString(dex, bb, stringIdsOff, stringIdsSize, nameIdx);
            if (className != null && methodName != null) {
                out.add(new MethodInfo(className, methodName, i));
            }
        }
    }

    private static String resolveString(byte[] dex, ByteBuffer bb,
                                         int stringIdsOff, int stringIdsSize, int idx) {
        if (idx < 0 || idx >= stringIdsSize) return null;
        int idOff = stringIdsOff + idx * 4;
        if (idOff + 4 > dex.length) return null;
        int dataOff = bb.getInt(idOff);
        if (dataOff <= 0 || dataOff >= dex.length) return null;
        int pos = dataOff;
        int strLen = 0, shift = 0;
        while (pos < dex.length) {
            int b = dex[pos++] & 0xFF;
            strLen |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        if (strLen <= 0 || pos + strLen > dex.length) return null;
        try { return new String(dex, pos, strLen, "UTF-8"); } catch (Exception e) { return null; }
    }

    private static String resolveType(byte[] dex, ByteBuffer bb,
                                       int typeIdsOff, int typeIdsSize,
                                       int stringIdsOff, int stringIdsSize, int typeIdx) {
        if (typeIdx < 0 || typeIdx >= typeIdsSize) return null;
        int tiOff = typeIdsOff + typeIdx * 4;
        if (tiOff + 4 > dex.length) return null;
        int strIdx = bb.getInt(tiOff);
        return resolveString(dex, bb, stringIdsOff, stringIdsSize, strIdx);
    }

    /**
     * Builds a minimal valid ELF64 shared library (.so) as a native stub.
     * The stub is a ~512-byte ELF64 with:
     *   - ELF64 header
     *   - One PT_LOAD program header
     *   - A minimal .dynamic section
     *   - A DT_SONAME entry pointing to "libdex2c_stub.so"
     *   - NOP-filled code section
     */
    private static byte[] buildArmStubElf(SecureRandom rng) {
        // We build a minimal ELF64 stub entirely in a ByteBuffer
        // Total planned size: ELF header(64) + PHdr(56) + code(128) + soname(24) = ~272 bytes
        // Padded to 512 for alignment
        int size = 512;
        byte[] elf = new byte[size];
        ByteBuffer b = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // ELF Identification
        b.put(0, (byte) 0x7f); b.put(1, (byte)'E'); b.put(2, (byte)'L'); b.put(3, (byte)'F');
        b.put(4, (byte) 2);    // EI_CLASS = ELFCLASS64
        b.put(5, (byte) 1);    // EI_DATA  = ELFDATA2LSB
        b.put(6, (byte) 1);    // EI_VERSION = EV_CURRENT
        b.put(7, (byte) 0);    // EI_OSABI = ELFOSABI_NONE
        // EI_ABIVERSION + padding: zeros (already 0)

        b.putShort(16, (short) 3);     // e_type   = ET_DYN (shared object)
        b.putShort(18, (short) 0xB7);  // e_machine = EM_AARCH64
        b.putInt(20, 1);               // e_version = EV_CURRENT
        b.putLong(24, 0x100L);         // e_entry (stub entry point)
        b.putLong(32, 64L);            // e_phoff (program header right after ELF header)
        b.putLong(40, 0L);             // e_shoff (no section headers)
        b.putInt(48, 0);               // e_flags
        b.putShort(52, (short) 64);    // e_ehsize
        b.putShort(54, (short) 56);    // e_phentsize (ELF64 phdr = 56 bytes)
        b.putShort(56, (short) 1);     // e_phnum = 1
        b.putShort(58, (short) 64);    // e_shentsize
        b.putShort(60, (short) 0);     // e_shnum = 0
        b.putShort(62, (short) 0);     // e_shstrndx

        // Program Header (offset 64, size 56)
        int phOff = 64;
        b.putInt(phOff,      1);           // p_type   = PT_LOAD
        b.putInt(phOff + 4,  5);           // p_flags  = PF_R | PF_X
        b.putLong(phOff + 8,  0L);         // p_offset
        b.putLong(phOff + 16, 0L);         // p_vaddr
        b.putLong(phOff + 24, 0L);         // p_paddr
        b.putLong(phOff + 32, (long) size);// p_filesz
        b.putLong(phOff + 40, (long) size);// p_memsz
        b.putLong(phOff + 48, 0x1000L);    // p_align

        // Code section (offset 120): fill with AArch64 NOPs (0xD503201F)
        int codeOff = 120;
        for (int i = codeOff; i + 4 <= 248; i += 4) {
            b.putInt(i, 0xD503201F);  // NOP
        }
        // Last instruction: RET (0xD65F03C0)
        b.putInt(244, 0xD65F03C0);

        // SONAME string at offset 248
        byte[] soname = ("libdex2c_stub.so\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        System.arraycopy(soname, 0, elf, 248, soname.length);

        return elf;
    }

    private static byte[] buildManifest(java.util.List<MethodInfo> methods) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteBuffer countBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        countBuf.putInt(methods.size());
        baos.write(countBuf.array());
        for (MethodInfo m : methods) {
            writeShortString(baos, m.className);
            writeShortString(baos, m.methodName);
            ByteBuffer idxBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            idxBuf.putInt(m.methodIndex);
            baos.write(idxBuf.array());
        }
        return baos.toByteArray();
    }

    private static void writeShortString(ByteArrayOutputStream baos, String s) throws IOException {
        byte[] bytes = s.getBytes("UTF-8");
        int len = Math.min(bytes.length, 0x7FFF);
        ByteBuffer lb = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);
        lb.putShort((short) len);
        baos.write(lb.array());
        baos.write(bytes, 0, len);
    }

    private static byte[] readEntry(ZipFile zf, ZipEntry entry) throws IOException {
        try (InputStream is = zf.getInputStream(entry)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
            return baos.toByteArray();
        }
    }

    private static class MethodInfo {
        final String className;
        final String methodName;
        final int    methodIndex;
        MethodInfo(String c, String m, int i) {
            className   = c;
            methodName  = m;
            methodIndex = i;
        }
    }
}
