package com.elfpacker.app.packer;

import com.elfpacker.app.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * OLLVM 混淆加壳
 *
 * <p>模拟 OLLVM 编译器插件的三个混淆 pass，在字节码层面施加以下变换：</p>
 *
 * <h3>1. 控制流平坦化（Control Flow Flattening）</h3>
 * <p>将代码段切分为等长块，随机打乱块的存储顺序，并在文件头写入块索引表。
 * 运行时由 VM 调度器按索引表顺序重建原始执行流。</p>
 *
 * <h3>2. 指令替换（Instruction Substitution）</h3>
 * <p>以每 4 字节为单位，对部分字（按概率 ~33%）做等价变换：
 * {@code w → ~w ^ 0xA5A5A5A5}，模拟将简单运算替换为更复杂的等价序列。</p>
 *
 * <h3>3. 虚假控制流（Bogus Control Flow）</h3>
 * <p>在代码段末尾追加随机"死代码"字节块（大小为代码段的 10%），
 * 模拟插入永远不执行的虚假路径。</p>
 *
 * <p>输出文件头结构（32 字节 OLLVM 头 + 原始文件体）：</p>
 * <pre>
 *   Offset  Size  描述
 *    0       8    Magic: "OLLVMPKR"
 *    8       4    版本标志
 *   12       4    块大小（bytes/block）
 *   16       4    块数量
 *   20       4    死代码大小
 *   24       4    替换字数
 *   28       4    保留
 * </pre>
 */
public class OllvmPacker implements ElfPacker {

    private static final byte[] OLLVM_MAGIC = {
            0x4F, 0x4C, 0x4C, 0x56, 0x4D, 0x50, 0x4B, 0x52  // OLLVMPKR
    };
    private static final int HEADER_SIZE = 32;
    private static final int BLOCK_SIZE  = 64;   // bytes per CFF block

    @Override
    public void pack(File input, File output) throws IOException {
        byte[] elf = java.nio.file.Files.readAllBytes(input.toPath());
        SecureRandom rng = new SecureRandom();

        // --- Pass 1: Instruction Substitution ---
        // Operate on a copy to avoid aliasing
        byte[] body = java.util.Arrays.copyOf(elf, elf.length);
        int substitutionCount = 0;
        for (int i = 0; i + 4 <= body.length; i += 4) {
            if (rng.nextInt(3) == 0) {  // ~33% probability
                int word = ByteBuffer.wrap(body, i, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                int substituted = (~word) ^ 0xA5A5A5A5;
                ByteBuffer.wrap(body, i, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(substituted);
                substitutionCount++;
            }
        }

        // --- Pass 2: Control Flow Flattening ---
        // Split body into BLOCK_SIZE chunks and shuffle their order
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 0; i < body.length; i += BLOCK_SIZE) {
            int end = Math.min(i + BLOCK_SIZE, body.length);
            byte[] block = new byte[end - i];
            System.arraycopy(body, i, block, 0, block.length);
            blocks.add(block);
        }
        // Shuffle block list (simulates CFF: blocks stored out of order, index table added)
        List<Integer> indexTable = new ArrayList<>();
        for (int i = 0; i < blocks.size(); i++) indexTable.add(i);
        Collections.shuffle(indexTable, rng);

        // Re-assemble blocks in shuffled order (a real CFF would keep original semantics
        // via a dispatch switch; here we store in shuffled order to obscure static analysis)
        byte[] shuffled = new byte[body.length];
        int pos = 0;
        for (int idx : indexTable) {
            byte[] blk = blocks.get(idx);
            System.arraycopy(blk, 0, shuffled, pos, blk.length);
            pos += blk.length;
        }

        // --- Pass 3: Bogus Control Flow ---
        // Append dead-code bytes (~10% of body size, random content)
        int bogusSize = Math.max(16, body.length / 10);
        byte[] bogus = new byte[bogusSize];
        rng.nextBytes(bogus);

        // --- Build index table header (block count entries, each 4 bytes, little-endian) ---
        // Index table tells the runtime the original block order
        // We embed it right after the OLLVM header, before the shuffled code body
        int blockCount = blocks.size();
        byte[] indexTableBytes = new byte[blockCount * 4];
        ByteBuffer ibuf = ByteBuffer.wrap(indexTableBytes).order(ByteOrder.LITTLE_ENDIAN);
        for (int idx : indexTable) ibuf.putInt(idx);

        // --- Assemble OLLVM header (HEADER_SIZE bytes) ---
        ByteBuffer hdr = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        hdr.put(OLLVM_MAGIC);
        hdr.putInt(0x00010003);          // version flags: CFF | IS | BCF
        hdr.putInt(BLOCK_SIZE);
        hdr.putInt(blockCount);
        hdr.putInt(bogusSize);
        hdr.putInt(substitutionCount);
        hdr.putInt(0);                   // reserved

        // Final output: header | index table | shuffled body | bogus dead code
        int totalSize = HEADER_SIZE + indexTableBytes.length + shuffled.length + bogus.length;
        byte[] result = new byte[totalSize];
        int off = 0;
        System.arraycopy(hdr.array(),       0, result, off, HEADER_SIZE);            off += HEADER_SIZE;
        System.arraycopy(indexTableBytes,   0, result, off, indexTableBytes.length); off += indexTableBytes.length;
        System.arraycopy(shuffled,          0, result, off, shuffled.length);        off += shuffled.length;
        System.arraycopy(bogus,             0, result, off, bogus.length);

        FileUtils.writeFile(output, result);
    }

    @Override
    public String getName() {
        return "OLLVM 混淆";
    }
}
