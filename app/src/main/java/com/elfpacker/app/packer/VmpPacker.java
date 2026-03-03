package com.elfpacker.app.packer;

import com.elfpacker.app.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * VMP 虚拟机保护（Virtual Machine Protection）
 *
 * <p>保护流程：</p>
 * <ol>
 *   <li>解析 ELF 文件头（EI_CLASS、e_machine、e_entry、e_phoff、e_shoff）</li>
 *   <li>定位 .text 代码段偏移量与大小（通过解析 ELF Program Headers）</li>
 *   <li>生成随机 32 字节 XOR 密钥，对代码段字节逐字节 XOR 加密</li>
 *   <li>在文件起始处注入 64 字节 VM 解释器头，包含魔数、密钥、加密区间信息</li>
 * </ol>
 * <p>VM 头结构（64 字节）：</p>
 * <pre>
 *   Offset  Size  描述
 *    0       8    Magic: "VMPELFHD"
 *    8       1    ELF Class (1=32bit, 2=64bit)
 *    9       2    e_machine
 *   11       4    e_entry (LE)
 *   15       4    code_section_offset (LE)
 *   19       4    code_section_size (LE)
 *   23       1    xor_key_len (=32)
 *   24      32    xor_key bytes
 *   56       8    reserved / padding
 * </pre>
 */
public class VmpPacker implements ElfPacker {

    private static final byte[] VM_MAGIC = {
            0x56, 0x4D, 0x50, 0x45, 0x4C, 0x46, 0x48, 0x44  // VMPELFHD
    };
    private static final int VM_HEADER_SIZE = 64;

    @Override
    public void pack(File input, File output) throws IOException {
        byte[] elf = java.nio.file.Files.readAllBytes(input.toPath());

        if (elf.length < 64) throw new IOException("文件太短，不是有效的 ELF 文件");
        if (elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F') {
            throw new IOException("不是有效的 ELF 文件（魔数不匹配）");
        }

        byte elfClass = elf[4];  // 1=ELF32, 2=ELF64
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // Parse ELF header fields
        int eMachine  = bb.getShort(18) & 0xFFFF;
        long eEntry;
        long ePhoff;
        int  ePhentsize;
        int  ePhnum;

        if (elfClass == 1) {
            // ELF32
            eEntry     = bb.getInt(24) & 0xFFFFFFFFL;
            ePhoff     = bb.getInt(28) & 0xFFFFFFFFL;
            ePhentsize = bb.getShort(42) & 0xFFFF;
            ePhnum     = bb.getShort(44) & 0xFFFF;
        } else {
            // ELF64
            eEntry     = bb.getLong(24);
            ePhoff     = bb.getLong(32);
            ePhentsize = bb.getShort(54) & 0xFFFF;
            ePhnum     = bb.getShort(56) & 0xFFFF;
        }

        // Find the LOAD segment containing the entry point (best approximation for .text)
        long codeOffset = 0;
        long codeSize = 0;
        for (int i = 0; i < ePhnum; i++) {
            long phBase = ePhoff + (long) i * ePhentsize;
            if (phBase + ePhentsize > elf.length) break;
            int pType;
            long pOffset, pFilesz, pVaddr;
            if (elfClass == 1) {
                pType   = bb.getInt((int) phBase);
                pOffset = bb.getInt((int) phBase + 4) & 0xFFFFFFFFL;
                pVaddr  = bb.getInt((int) phBase + 8) & 0xFFFFFFFFL;
                pFilesz = bb.getInt((int) phBase + 16) & 0xFFFFFFFFL;
            } else {
                pType   = bb.getInt((int) phBase);
                pOffset = bb.getLong((int) phBase + 8);
                pVaddr  = bb.getLong((int) phBase + 16);
                pFilesz = bb.getLong((int) phBase + 32);
            }
            // PT_LOAD = 1; pick segment covering entry point
            if (pType == 1 && eEntry >= pVaddr && eEntry < pVaddr + pFilesz) {
                codeOffset = pOffset;
                codeSize   = pFilesz;
                break;
            }
        }
        // Fallback: protect from ELF header end to EOF
        if (codeSize == 0) {
            codeOffset = elfClass == 1 ? 52 : 64;
            codeSize   = elf.length - codeOffset;
        }

        // Generate random XOR key (32 bytes)
        byte[] xorKey = new byte[32];
        new SecureRandom().nextBytes(xorKey);

        // XOR-encrypt the code section in-place on a copy
        byte[] protected_ = Arrays.copyOf(elf, elf.length);
        for (long j = codeOffset; j < codeOffset + codeSize && j < protected_.length; j++) {
            protected_[(int) j] ^= xorKey[(int) (j % xorKey.length)];
        }

        // Build VM header (64 bytes)
        ByteBuffer vmHeader = ByteBuffer.allocate(VM_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        vmHeader.put(VM_MAGIC);                   // 0-7   magic
        vmHeader.put(elfClass);                   // 8     ELF class
        vmHeader.putShort((short) eMachine);      // 9-10  e_machine
        vmHeader.putInt((int) eEntry);            // 11-14 e_entry
        vmHeader.putInt((int) codeOffset);        // 15-18 code offset
        vmHeader.putInt((int) codeSize);          // 19-22 code size
        vmHeader.put((byte) 32);                  // 23    key length
        vmHeader.put(xorKey);                     // 24-55 XOR key
        // 56-63: padding (zeroes from allocate)

        // Output: VM header || protected ELF body
        byte[] result = new byte[VM_HEADER_SIZE + protected_.length];
        System.arraycopy(vmHeader.array(), 0, result, 0, VM_HEADER_SIZE);
        System.arraycopy(protected_, 0, result, VM_HEADER_SIZE, protected_.length);

        FileUtils.writeFile(output, result);
    }

    @Override
    public String getName() {
        return "VMP 虚拟机保护";
    }
}
