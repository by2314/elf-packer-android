package com.elfpacker.app;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;

import com.elfpacker.app.ui.ApkProtectorActivity;
import com.elfpacker.app.ui.ElfPackerActivity;

/**
 * 主界面
 * 提供两个入口：ELF 文件加壳 和 APK 加固保护
 */
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        CardView cardElf = findViewById(R.id.card_elf_packer);
        cardElf.setOnClickListener(v ->
                startActivity(new Intent(this, ElfPackerActivity.class)));

        CardView cardApk = findViewById(R.id.card_apk_protector);
        cardApk.setOnClickListener(v ->
                startActivity(new Intent(this, ApkProtectorActivity.class)));
    }
}
