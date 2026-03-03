package com.elfpacker.app.protector;

import java.io.File;
import java.io.IOException;

/**
 * APK 加固保护通用接口
 * 每种保护技术实现此接口，接收原始 APK 文件，输出处理后的 APK 文件。
 */
public interface ApkProtector {

    /**
     * 对 {@code input} APK 执行一道保护处理，将结果写入 {@code output}。
     *
     * @param input  原始（或已被前一道保护处理过的）APK 文件
     * @param output 本道保护后的输出 APK 文件
     * @throws IOException 处理失败时抛出
     */
    void protect(File input, File output) throws IOException;

    /**
     * 返回此保护技术的用户可见名称（中文）。
     */
    String getName();
}
