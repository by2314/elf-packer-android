package com.elfpacker.app.packer;

import com.elfpacker.app.utils.FileUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * GZIP 加密压缩加壳
 *
 * <p>双重保护流程：</p>
 * <ol>
 *   <li>计算原始 ELF 文件的 SHA-256 哈希值作为 PBKDF2 密码</li>
 *   <li>生成随机 16 字节 IV，用 PBKDF2WithHmacSHA256 派生 32 字节 AES-256 密钥</li>
 *   <li>AES-256-CBC 加密原始数据</li>
 *   <li>GZIP 压缩加密后的密文</li>
 *   <li>写入自定义文件头：Magic(8B) + IV(16B) + 原始长度(4B LE) + GZIP 数据</li>
 * </ol>
 */
public class GzipPacker implements ElfPacker {

    private static final byte[] MAGIC = {
            0x47, 0x5A, 0x45, 0x4C, 0x46, 0x50, 0x4B, 0x01  // GZELFPKx01
    };
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int KEY_LEN_BITS = 256;

    @Override
    public void pack(File input, File output) throws IOException {
        byte[] original = java.nio.file.Files.readAllBytes(input.toPath());

        try {
            // Derive key from SHA-256 of file content
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(original);
            char[] password = bytesToHex(hash).toCharArray();

            // Random IV
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            // PBKDF2 key derivation
            PBEKeySpec spec = new PBEKeySpec(password, iv, PBKDF2_ITERATIONS, KEY_LEN_BITS);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            // AES-256-CBC encrypt
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(original);

            // GZIP compress the ciphertext
            ByteArrayOutputStream gzipBuf = new ByteArrayOutputStream();
            try (GZIPOutputStream gz = new GZIPOutputStream(gzipBuf)) {
                gz.write(encrypted);
            }
            byte[] gzipped = gzipBuf.toByteArray();

            // Build output: MAGIC | IV | original_len (LE 4B) | gzipped
            ByteBuffer bb = ByteBuffer.allocate(MAGIC.length + 16 + 4 + gzipped.length);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.put(MAGIC);
            bb.put(iv);
            bb.putInt(original.length);
            bb.put(gzipped);

            FileUtils.writeFile(output, bb.array());

        } catch (Exception e) {
            throw new IOException("GZIP 加密压缩失败: " + e.getMessage(), e);
        }
    }

    @Override
    public String getName() {
        return "GZIP 加密压缩";
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
