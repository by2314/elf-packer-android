package com.elfpacker.app.protector;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * 字符串混淆保护
 *
 * <p>在 APK（ZIP 格式）中定位所有 {@code .dex} 文件，对每个 DEX 文件的字符串常量池
 * 执行逐字节 XOR 加密，并在 APK 根目录写入密钥映射文件 {@code META-INF/str_keys.bin}。</p>
 *
 * <h3>DEX 字符串池格式（简要）</h3>
 * <pre>
 *   DEX Header[0..7]   = magic "dex\n035\0" or "dex\n036\0" or "dex\n039\0"
 *   [56..59] string_ids_size  (LE uint32)
 *   [60..63] string_ids_off   (LE uint32)
 *   Each string_id_item[off] = { data_off: uint32 }
 *   Each string_data_item    = { uleb128 size } + { MUTF-8 chars } + { 0x00 }
 * </pre>
 *
 * <p>加密：对每个字符串数据字节 {@code b[i]} 应用 {@code b[i] ^= key[i % key.length]}，
 * 其中 key 是 32 字节随机密钥，per-DEX 独立生成。</p>
 *
 * <p>密钥文件格式（{@code str_keys.bin}）：</p>
 * <pre>
 *   [4B] entry count (LE)
 *   For each entry:
 *     [2B] dex filename length (LE)
 *     [N B] dex filename (UTF-8)
 *     [32B] XOR key
 * </pre>
 */
public class StringObfuscator implements ApkProtector {

    private static final int KEY_LEN = 32;

    @Override
    public void protect(File input, File output) throws IOException {
        SecureRandom rng = new SecureRandom();

        // Collect dex names and keys before we write the output
        java.util.List<String> dexNames = new java.util.ArrayList<>();
        java.util.List<byte[]> dexKeys  = new java.util.ArrayList<>();

        try (ZipFile zipIn = new ZipFile(input);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(output))) {

            zos.setMethod(ZipOutputStream.DEFLATED);

            Enumeration<? extends ZipEntry> entries = zipIn.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                byte[] data = readEntry(zipIn, entry);

                if (name.endsWith(".dex") && isDex(data)) {
                    byte[] key = new byte[KEY_LEN];
                    rng.nextBytes(key);
                    data = xorDexStrings(data, key);
                    dexNames.add(name);
                    dexKeys.add(key);
                }

                ZipEntry outEntry = new ZipEntry(name);
                zos.putNextEntry(outEntry);
                zos.write(data);
                zos.closeEntry();
            }

            // Write key mapping file
            byte[] keyFile = buildKeyFile(dexNames, dexKeys);
            ZipEntry keyEntry = new ZipEntry("META-INF/str_keys.bin");
            zos.putNextEntry(keyEntry);
            zos.write(keyFile);
            zos.closeEntry();
        }
    }

    @Override
    public String getName() {
        return "字符串混淆";
    }

    // -------------------------------------------------------------------------

    private static boolean isDex(byte[] data) {
        return data.length > 8
                && data[0] == 0x64 && data[1] == 0x65 && data[2] == 0x78   // "dex"
                && data[3] == 0x0A;                                          // '\n'
    }

    /**
     * XOR-encrypts all string data bytes in the DEX string pool.
     * The DEX header is NOT modified (magic, checksum, SHA-1 fields are left intact
     * so the file is still recognisable as DEX; a runtime stub would re-patch them).
     */
    private static byte[] xorDexStrings(byte[] dex, byte[] key) {
        ByteBuffer bb = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsSize = bb.getInt(56);
        int stringIdsOff  = bb.getInt(60);

        byte[] out = java.util.Arrays.copyOf(dex, dex.length);
        for (int i = 0; i < stringIdsSize; i++) {
            int idOff = stringIdsOff + i * 4;
            if (idOff + 4 > dex.length) break;
            int dataOff = ByteBuffer.wrap(dex, idOff, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if (dataOff <= 0 || dataOff >= dex.length) continue;

            // Read ULEB128 string length (skip it, don't encrypt)
            int pos = dataOff;
            int strLen = 0;
            int shift = 0;
            while (pos < dex.length) {
                int b = dex[pos++] & 0xFF;
                strLen |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            // XOR the UTF-8 string bytes (strLen bytes + null terminator)
            for (int j = 0; j < strLen && pos + j < out.length; j++) {
                out[pos + j] ^= key[(pos + j) % key.length];
            }
        }
        return out;
    }

    private static byte[] buildKeyFile(java.util.List<String> names, java.util.List<byte[]> keys) throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        ByteBuffer countBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        countBuf.putInt(names.size());
        baos.write(countBuf.array());
        for (int i = 0; i < names.size(); i++) {
            byte[] nameBytes = names.get(i).getBytes("UTF-8");
            ByteBuffer lenBuf = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);
            lenBuf.putShort((short) nameBytes.length);
            baos.write(lenBuf.array());
            baos.write(nameBytes);
            baos.write(keys.get(i));
        }
        return baos.toByteArray();
    }

    private static byte[] readEntry(ZipFile zf, ZipEntry entry) throws IOException {
        try (InputStream is = zf.getInputStream(entry)) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
            return baos.toByteArray();
        }
    }
}
