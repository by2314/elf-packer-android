package com.elfpacker.app.packer;

import java.io.File;
import java.io.IOException;

/**
 * ELF 文件加壳通用接口
 * 所有加壳实现均实现此接口，统一输入/输出契约。
 */
public interface ElfPacker {

    /**
     * 对 {@code input} 文件执行加壳操作，将结果写入 {@code output}。
     *
     * @param input  原始 ELF 文件
     * @param output 加壳后输出文件
     * @throws IOException 处理失败时抛出
     */
    void pack(File input, File output) throws IOException;

    /**
     * 返回对用户展示的加壳方式名称（中文）。
     */
    String getName();
}
