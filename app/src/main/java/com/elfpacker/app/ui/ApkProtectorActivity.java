package com.elfpacker.app.ui;

import android.app.ProgressDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.CheckBox;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.elfpacker.app.R;
import com.elfpacker.app.protector.ApkProtector;
import com.elfpacker.app.protector.AssetObfuscator;
import com.elfpacker.app.protector.ClassNameObfuscator;
import com.elfpacker.app.protector.Dex2CProtector;
import com.elfpacker.app.protector.StringObfuscator;
import com.elfpacker.app.utils.FileUtils;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * APK 加固保护界面
 * 用户选择 APK 文件，勾选若干保护技术，点击"开始加固"后在后台线程
 * 依次执行每道保护（pipeline），最终输出加固后的 APK 并跳转结果页。
 */
public class ApkProtectorActivity extends AppCompatActivity {

    private Uri selectedUri;
    private TextView tvSelectedApk;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final ActivityResultLauncher<String[]> filePickerLauncher =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
                if (uri != null) {
                    selectedUri = uri;
                    String name = FileUtils.getFileName(this, uri);
                    tvSelectedApk.setText(name != null ? name : uri.toString());
                }
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_apk_protector);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        tvSelectedApk = findViewById(R.id.tv_selected_apk);

        MaterialButton btnSelectApk = findViewById(R.id.btn_select_apk);
        btnSelectApk.setOnClickListener(v ->
                filePickerLauncher.launch(new String[]{"application/vnd.android.package-archive", "*/*"}));

        MaterialButton btnProtect = findViewById(R.id.btn_protect);
        btnProtect.setOnClickListener(v -> startProtection());
    }

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    private void startProtection() {
        if (selectedUri == null) {
            Toast.makeText(this, "请先选择 APK 文件", Toast.LENGTH_SHORT).show();
            return;
        }

        // Build protection pipeline from checked options
        List<ApkProtector> pipeline = new ArrayList<>();
        if (((CheckBox) findViewById(R.id.cb_string_obf)).isChecked())
            pipeline.add(new StringObfuscator());
        if (((CheckBox) findViewById(R.id.cb_asset_obf)).isChecked())
            pipeline.add(new AssetObfuscator());
        if (((CheckBox) findViewById(R.id.cb_class_obf)).isChecked())
            pipeline.add(new ClassNameObfuscator());
        if (((CheckBox) findViewById(R.id.cb_dex2c)).isChecked())
            pipeline.add(new Dex2CProtector());

        if (pipeline.isEmpty()) {
            Toast.makeText(this, "请至少选择一种加固方式", Toast.LENGTH_SHORT).show();
            return;
        }

        ProgressDialog progress = new ProgressDialog(this);
        progress.setMessage(getString(R.string.processing));
        progress.setCancelable(false);
        progress.show();

        executor.execute(() -> {
            try {
                File inputFile = FileUtils.copyUriToCache(this, selectedUri);
                long originalSize = inputFile.length();

                // Build display name from selected protectors
                StringBuilder nameBuilder = new StringBuilder();
                for (ApkProtector p : pipeline) {
                    if (nameBuilder.length() > 0) nameBuilder.append(" + ");
                    nameBuilder.append(p.getName());
                }
                String protectionName = nameBuilder.toString();

                // Execute the pipeline: each pass reads its input and writes to a temp file
                File outputDir = FileUtils.getOutputDir(this);
                File currentInput = inputFile;

                for (int i = 0; i < pipeline.size(); i++) {
                    ApkProtector protector = pipeline.get(i);
                    String tmpName = inputFile.getName() + "_pass" + i + ".apk";
                    File tmpOutput = new File(outputDir, tmpName);
                    protector.protect(currentInput, tmpOutput);

                    // Clean up previous temp file (not the original input)
                    if (currentInput != inputFile) currentInput.delete();
                    currentInput = tmpOutput;
                }

                // Rename last output to final name
                String finalName = inputFile.getName().replaceAll("\\.apk$", "")
                        + "_protected.apk";
                File finalOutput = new File(outputDir, finalName);
                if (!currentInput.renameTo(finalOutput)) {
                    // If rename fails (cross-device), copy using InputStream
                    try (java.io.InputStream in = new java.io.FileInputStream(currentInput);
                         java.io.OutputStream out2 = new java.io.FileOutputStream(finalOutput)) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) != -1) out2.write(buf, 0, n);
                    }
                    currentInput.delete();
                }

                long packedSize = finalOutput.length();

                runOnUiThread(() -> {
                    progress.dismiss();
                    Intent intent = new Intent(this, PackerResultActivity.class);
                    intent.putExtra(PackerResultActivity.EXTRA_PACKER_NAME,   protectionName);
                    intent.putExtra(PackerResultActivity.EXTRA_INPUT_NAME,    inputFile.getName());
                    intent.putExtra(PackerResultActivity.EXTRA_OUTPUT_PATH,   finalOutput.getAbsolutePath());
                    intent.putExtra(PackerResultActivity.EXTRA_ORIGINAL_SIZE, originalSize);
                    intent.putExtra(PackerResultActivity.EXTRA_PACKED_SIZE,   packedSize);
                    startActivity(intent);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    progress.dismiss();
                    Toast.makeText(this, "加固失败：" + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }
}
