package com.elfpacker.app.ui;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;

import com.elfpacker.app.R;
import com.elfpacker.app.utils.FileUtils;
import com.google.android.material.button.MaterialButton;

import java.io.File;

/**
 * 加壳结果展示界面
 * 显示：原始文件名、加壳方式、原始大小、加壳后大小、压缩率、输出路径
 * 提供：分享文件、返回主页 两个操作
 */
public class PackerResultActivity extends AppCompatActivity {

    public static final String EXTRA_PACKER_NAME   = "packer_name";
    public static final String EXTRA_INPUT_NAME    = "input_name";
    public static final String EXTRA_OUTPUT_PATH   = "output_path";
    public static final String EXTRA_ORIGINAL_SIZE = "original_size";
    public static final String EXTRA_PACKED_SIZE   = "packed_size";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);

        // 获取传入数据
        String packerName   = getIntent().getStringExtra(EXTRA_PACKER_NAME);
        String inputName    = getIntent().getStringExtra(EXTRA_INPUT_NAME);
        String outputPath   = getIntent().getStringExtra(EXTRA_OUTPUT_PATH);
        long   originalSize = getIntent().getLongExtra(EXTRA_ORIGINAL_SIZE, 0L);
        long   packedSize   = getIntent().getLongExtra(EXTRA_PACKED_SIZE, 0L);

        // 计算压缩率
        String ratio;
        if (originalSize > 0) {
            double r = (1.0 - (double) packedSize / originalSize) * 100.0;
            if (r >= 0) ratio = String.format("减小 %.1f%%", r);
            else        ratio = String.format("增大 %.1f%%", -r);
        } else {
            ratio = "N/A";
        }

        // 填充 UI
        ((TextView) findViewById(R.id.tv_input_name)).setText(inputName);
        ((TextView) findViewById(R.id.tv_packer_type)).setText(packerName);
        ((TextView) findViewById(R.id.tv_original_size)).setText(FileUtils.formatSize(originalSize));
        ((TextView) findViewById(R.id.tv_packed_size)).setText(FileUtils.formatSize(packedSize));
        ((TextView) findViewById(R.id.tv_ratio)).setText(ratio);
        ((TextView) findViewById(R.id.tv_output_path)).setText(outputPath);

        // 分享文件
        MaterialButton btnShare = findViewById(R.id.btn_share);
        btnShare.setOnClickListener(v -> shareFile(outputPath));

        // 返回主页
        MaterialButton btnHome = findViewById(R.id.btn_home);
        btnHome.setOnClickListener(v -> finish());
    }

    /** 通过 FileProvider 分享输出文件 */
    private void shareFile(String filePath) {
        if (filePath == null) {
            Toast.makeText(this, "文件路径无效", Toast.LENGTH_SHORT).show();
            return;
        }
        File file = new File(filePath);
        if (!file.exists()) {
            Toast.makeText(this, "文件不存在：" + filePath, Toast.LENGTH_LONG).show();
            return;
        }
        try {
            Uri uri = FileProvider.getUriForFile(
                    this,
                    getPackageName() + ".fileprovider",
                    file);
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("application/octet-stream");
            shareIntent.putExtra(Intent.EXTRA_STREAM, uri);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(shareIntent, "分享加壳文件"));
        } catch (Exception e) {
            Toast.makeText(this, "分享失败：" + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
}