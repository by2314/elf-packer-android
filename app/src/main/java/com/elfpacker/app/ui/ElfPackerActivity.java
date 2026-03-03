package com.elfpacker.app.ui;

import android.app.ProgressDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.elfpacker.app.R;
import com.elfpacker.app.packer.ElfPacker;
import com.elfpacker.app.packer.GzipPacker;
import com.elfpacker.app.packer.OllvmPacker;
import com.elfpacker.app.packer.UpxPacker;
import com.elfpacker.app.packer.VmpPacker;
import com.elfpacker.app.utils.FileUtils;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * ELF 文件加壳界面
 * 用户选择 ELF 文件和加壳方式后，在后台线程执行加壳并跳转结果页。
 */
public class ElfPackerActivity extends AppCompatActivity {

    private Uri selectedUri;
    private TextView tvSelectedFile;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final ActivityResultLauncher<String[]> filePickerLauncher =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
                if (uri != null) {
                    selectedUri = uri;
                    String name = FileUtils.getFileName(this, uri);
                    tvSelectedFile.setText(name != null ? name : uri.toString());
                }
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_elf_packer);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        tvSelectedFile = findViewById(R.id.tv_selected_file);

        MaterialButton btnSelect = findViewById(R.id.btn_select_elf);
        btnSelect.setOnClickListener(v -> {
            ElfPacker packer = getSelectedPacker();
            if (selectedUri == null) {
                filePickerLauncher.launch(new String[]{"*/*"});
            } else {
                startPacking(packer);
            }
        });

        // Make option cards also select the radio button on tap
        setupCardClick(R.id.card_upx, R.id.rb_upx);
        setupCardClick(R.id.card_gzip, R.id.rb_gzip);
        setupCardClick(R.id.card_vmp, R.id.rb_vmp);
        setupCardClick(R.id.card_ollvm, R.id.rb_ollvm);

        // Update button label after file is selected
        tvSelectedFile.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) {}
            @Override public void afterTextChanged(android.text.Editable s) {
                if (selectedUri != null) btnSelect.setText("开始加壳");
            }
        });
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

    private void setupCardClick(int cardId, int radioId) {
        RadioButton rb = findViewById(radioId);
        findViewById(cardId).setOnClickListener(v -> {
            clearRadios();
            rb.setChecked(true);
        });
    }

    private void clearRadios() {
        ((RadioButton) findViewById(R.id.rb_upx)).setChecked(false);
        ((RadioButton) findViewById(R.id.rb_gzip)).setChecked(false);
        ((RadioButton) findViewById(R.id.rb_vmp)).setChecked(false);
        ((RadioButton) findViewById(R.id.rb_ollvm)).setChecked(false);
    }

    private ElfPacker getSelectedPacker() {
        if (((RadioButton) findViewById(R.id.rb_gzip)).isChecked())  return new GzipPacker();
        if (((RadioButton) findViewById(R.id.rb_vmp)).isChecked())   return new VmpPacker();
        if (((RadioButton) findViewById(R.id.rb_ollvm)).isChecked()) return new OllvmPacker();
        return new UpxPacker();
    }

    private void startPacking(ElfPacker packer) {
        if (selectedUri == null) {
            Toast.makeText(this, "请先选择 ELF 文件", Toast.LENGTH_SHORT).show();
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

                String outName = inputFile.getName() + "_" + packer.getName().replaceAll(" ", "_") + ".packed";
                File outputDir  = FileUtils.getOutputDir(this);
                File outputFile = new File(outputDir, outName);

                packer.pack(inputFile, outputFile);
                long packedSize = outputFile.length();

                runOnUiThread(() -> {
                    progress.dismiss();
                    Intent intent = new Intent(this, PackerResultActivity.class);
                    intent.putExtra(PackerResultActivity.EXTRA_PACKER_NAME,   packer.getName());
                    intent.putExtra(PackerResultActivity.EXTRA_INPUT_NAME,    inputFile.getName());
                    intent.putExtra(PackerResultActivity.EXTRA_OUTPUT_PATH,   outputFile.getAbsolutePath());
                    intent.putExtra(PackerResultActivity.EXTRA_ORIGINAL_SIZE, originalSize);
                    intent.putExtra(PackerResultActivity.EXTRA_PACKED_SIZE,   packedSize);
                    startActivity(intent);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    progress.dismiss();
                    Toast.makeText(this, "加壳失败：" + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }
}
