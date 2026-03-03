package com.elfpacker.app.packer;

import com.elfpacker.app.utils.FileUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.Deflater;

/**
 * UPX 压缩加壳
 *
 * <p>原理：模拟 UPX 文件格式。</p>
 * <ol>
 *   <li>写入 13 字节 UPX 魔数头（含版本、压缩方式标记）</li>
 *   <li>用 DEFLATE 算法压缩原始 ELF 数据</li>
 *   <li>写入原始文件长度（4 字节 little-endian），便于存根解压时分配缓冲区</li>
 *   <li>写入压缩后数据</li>
 * </ol>
 * <p>输出文件对真实 UPX 运行时不可执行，但具备 UPX 头部特征，可通过 UPX 检测工具识别。</p>
 */
public class UpxPacker implements ElfPacker {

    /** UPX magic: "!UPX" (4 bytes) + version (1) + method (1) + level (1) + filter (1) +
     *  filter_cto (1) + reserved (4) = 13 bytes */
    private static final byte[] UPX_MAGIC = {
            0x21, 0x55, 0x50, 0x58,   // !UPX
            0x01,                      // version
            0x02,                      // method = NRV2B
            0x09,                      // level
            0x00,                      // filter
            0x00,                      // filter_cto
            0x00, 0x00, 0x00, 0x00    // reserved
    };

    @Override
    public void pack(File input, File output) throws IOException {
        byte[] original = java.nio.file.Files.readAllBytes(input.toPath());

        // DEFLATE compress
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(original);
        deflater.finish();
        ByteArrayOutputStream compressedBuf = new ByteArrayOutputStream(original.length);
        byte[] tmp = new byte[8192];
        while (!deflater.finished()) {
            int n = deflater.deflate(tmp);
            compressedBuf.write(tmp, 0, n);
        }
        deflater.end();
        byte[] compressed = compressedBuf.toByteArray();

        // Build output: magic | original length (LE 4B) | compressed data
        ByteBuffer bb = ByteBuffer.allocate(UPX_MAGIC.length + 4 + compressed.length);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.put(UPX_MAGIC);
        bb.putInt(original.length);
        bb.put(compressed);

        FileUtils.writeFile(output, bb.array());
    }

    @Override
    public String getName() {
        return "UPX 压缩加壳";
    }
}
