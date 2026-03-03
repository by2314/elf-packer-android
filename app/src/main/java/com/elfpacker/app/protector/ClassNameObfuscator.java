package com.elfpacker.app.protector;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * 类名与方法名混淆保护（Class/Method Name Obfuscation）
 *
 * <p>通过修改 DEX 文件的字符串常量池，将类名（type descriptors）和方法名替换为
 * 短随机标识符，使反编译后的代码难以理解。</p>
 *
 * <h3>策略</h3>
 * <ul>
 *   <li>类型描述符（string pool 中形如 {@code Lcom/example/MyClass;} 的条目）
 *       —— 保留包路径、仅替换最后一个组件（简单类名）为随机 4 字符字母串</li>
 *   <li>方法名（string pool 中纯字母数字串，且非 Android/Java 保留名）
 *       —— 替换为随机 4 字符字母串</li>
 *   <li>保留 {@code <init>}、{@code <clinit>}、{@code toString}、{@code equals}、
 *       {@code hashCode}、{@code onCreate}、{@code onResume} 等框架方法名</li>
 * </ul>
 *
 * <p>重命名映射写入 {@code META-INF/class_map.bin}，格式：</p>
 * <pre>
 *   [4B] count (LE)
 *   For each entry:
 *     [2B] original name length
 *     [N B] original name (UTF-8)
 *     [2B] mapped name length
 *     [M B] mapped name (UTF-8)
 * </pre>
 *
 * <p><b>注意：</b>此实现直接操作 DEX 字节，仅替换等长或更短的字符串
 * （用零字节填充剩余空间）以避免破坏 DEX 文件内的偏移量。
 * 若需更换为更长的名称，需要完整重写 DEX，超出此示例范围。</p>
 */
public class ClassNameObfuscator implements ApkProtector {

    /** Framework & lifecycle method names that must not be renamed. */
    private static final java.util.Set<String> RESERVED = new java.util.HashSet<>(java.util.Arrays.asList(
            "<init>", "<clinit>", "toString", "equals", "hashCode",
            "onCreate", "onStart", "onResume", "onPause", "onStop",
            "onDestroy", "onCreateView", "onViewCreated", "onAttach",
            "run", "main", "compareTo", "clone", "finalize",
            "getClass", "notify", "notifyAll", "wait"
    ));

    @Override
    public void protect(File input, File output) throws IOException {
        SecureRandom rng = new SecureRandom();

        try (ZipFile zipIn = new ZipFile(input);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(output))) {

            zos.setMethod(ZipOutputStream.DEFLATED);

            // Shared rename map across all DEX files for consistency
            Map<String, String> renameMap = new HashMap<>();

            Enumeration<? extends ZipEntry> entries = zipIn.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                byte[] data = readEntry(zipIn, entry);

                if (name.endsWith(".dex") && isDex(data)) {
                    data = obfuscateDex(data, rng, renameMap);
                }

                ZipEntry outEntry = new ZipEntry(name);
                zos.putNextEntry(outEntry);
                zos.write(data);
                zos.closeEntry();
            }

            // Write mapping file
            byte[] mapBytes = buildMapFile(renameMap);
            ZipEntry mapEntry = new ZipEntry("META-INF/class_map.bin");
            zos.putNextEntry(mapEntry);
            zos.write(mapBytes);
            zos.closeEntry();
        }
    }

    @Override
    public String getName() {
        return "类名方法名混淆";
    }

    // -------------------------------------------------------------------------

    private static boolean isDex(byte[] data) {
        return data.length > 8 && data[0] == 0x64 && data[1] == 0x65
                && data[2] == 0x78 && data[3] == 0x0A;
    }

    /**
     * Iterates the DEX string pool and renames candidate strings in-place
     * (only strings whose replacement is ≤ original length).
     */
    private static byte[] obfuscateDex(byte[] dex, SecureRandom rng,
                                        Map<String, String> renameMap) {
        ByteBuffer bb = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsSize = bb.getInt(56);
        int stringIdsOff  = bb.getInt(60);

        byte[] out = java.util.Arrays.copyOf(dex, dex.length);

        for (int i = 0; i < stringIdsSize; i++) {
            int idOff = stringIdsOff + i * 4;
            if (idOff + 4 > dex.length) break;
            int dataOff = ByteBuffer.wrap(dex, idOff, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if (dataOff <= 0 || dataOff >= dex.length) continue;

            // Decode ULEB128 length
            int pos = dataOff;
            int strLen = 0;
            int shift = 0;
            int ulebBytes = 0;
            while (pos < dex.length) {
                int b = dex[pos++] & 0xFF;
                strLen |= (b & 0x7F) << shift;
                ulebBytes++;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            if (strLen <= 0 || pos + strLen > dex.length) continue;

            String orig;
            try {
                orig = new String(dex, pos, strLen, "MUTF-8");
            } catch (Exception e) {
                continue;
            }

            if (!isRenameable(orig)) continue;

            // Look up or generate new name (must fit in same byte count)
            String renamed = renameMap.get(orig);
            if (renamed == null) {
                renamed = generateName(rng, strLen);
                if (renamed == null) continue;  // can't fit
                renameMap.put(orig, renamed);
            }

            byte[] renamedBytes;
            try {
                renamedBytes = renamed.getBytes("UTF-8");
            } catch (Exception e) {
                continue;
            }
            if (renamedBytes.length > strLen) continue;

            // Patch: write new ULEB128 length + new string + zero-pad
            int newLen = renamedBytes.length;
            // Re-encode ULEB128 for newLen (must fit in same ulebBytes)
            byte[] newUleb = encodeLeb128(newLen);
            if (newUleb.length > ulebBytes) continue;  // can't fit ULEB in same space

            int patchPos = dataOff;
            // Write ULEB128, zero-padding to ulebBytes
            for (int u = 0; u < ulebBytes; u++) {
                out[patchPos++] = u < newUleb.length ? newUleb[u] : 0x00;
            }
            // Write new string bytes
            System.arraycopy(renamedBytes, 0, out, patchPos, renamedBytes.length);
            patchPos += renamedBytes.length;
            // Zero-pad remaining space + null terminator
            for (int u = renamedBytes.length; u <= strLen; u++) {
                out[patchPos++] = 0x00;
            }
        }
        return out;
    }

    /**
     * Returns true if the string looks like a renameable class simple-name or method name.
     * We rename:
     *  - Type descriptors ending with ";": last component after '/' before ';'
     *  - Pure identifier strings that are not reserved
     */
    private static boolean isRenameable(String s) {
        if (s == null || s.isEmpty()) return false;
        if (RESERVED.contains(s)) return false;
        // Type descriptor: Lpackage/path/ClassName;
        if (s.startsWith("L") && s.endsWith(";") && s.contains("/")) return true;
        // Plain identifier (method/field name): letters, digits, $, _
        if (s.matches("[a-zA-Z][a-zA-Z0-9_$]{2,}") && !RESERVED.contains(s)) return true;
        return false;
    }

    /**
     * Generates a random alphabetic name of at most {@code maxLen} UTF-8 bytes.
     * Returns null if maxLen < 4.
     */
    private static String generateName(SecureRandom rng, int maxLen) {
        if (maxLen < 4) return null;
        int len = Math.min(maxLen, 6);
        char[] chars = new char[len];
        for (int i = 0; i < len; i++) {
            chars[i] = (char) ('a' + rng.nextInt(26));
        }
        return new String(chars);
    }

    private static byte[] encodeLeb128(int value) {
        List<Byte> bytes = new ArrayList<>();
        do {
            byte b = (byte) (value & 0x7F);
            value >>>= 7;
            if (value != 0) b |= 0x80;
            bytes.add(b);
        } while (value != 0);
        byte[] result = new byte[bytes.size()];
        for (int i = 0; i < result.length; i++) result[i] = bytes.get(i);
        return result;
    }

    private static byte[] buildMapFile(Map<String, String> map) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteBuffer countBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        countBuf.putInt(map.size());
        baos.write(countBuf.array());
        for (Map.Entry<String, String> e : map.entrySet()) {
            writeShortString(baos, e.getKey());
            writeShortString(baos, e.getValue());
        }
        return baos.toByteArray();
    }

    private static void writeShortString(ByteArrayOutputStream baos, String s) throws IOException {
        byte[] bytes = s.getBytes("UTF-8");
        ByteBuffer lb = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);
        lb.putShort((short) Math.min(bytes.length, 0x7FFF));
        baos.write(lb.array());
        baos.write(bytes, 0, Math.min(bytes.length, 0x7FFF));
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
}
