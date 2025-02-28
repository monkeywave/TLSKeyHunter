package com.example.rustls_android;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

import android.view.View;
import android.widget.Button;
import android.widget.Switch;
import android.widget.Toast;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;


public class MainActivity extends AppCompatActivity {
    // Load the Rust shared library.
    static {
        System.loadLibrary("rustls_android_12");
        System.loadLibrary("rustls_android_12_ex");
        System.loadLibrary("rustls_android_13");
        System.loadLibrary("rustls_android_13_ex");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        AtomicInteger version_num = new AtomicInteger(12);
        Switch version = findViewById(R.id.versionSwitch);
        version.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                version_num.set(13);
            } else {
                version_num.set(12);
            }
        });

        AtomicBoolean keyLogsEnabled = new AtomicBoolean(false);
        Switch keyLogsSwitch = findViewById(R.id.exportSwitch);
        keyLogsSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                keyLogsEnabled.set(true);
            } else {
                keyLogsEnabled.set(false);
            }
        });


        Button startButton = findViewById(R.id.start_button);
        startButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                RustTls rustTls = new RustTls();
                String result = rustTls.runRustls(version_num.get(), keyLogsEnabled.get());

                // Check the result and act accordingly.
                Toast.makeText(MainActivity.this,  result, Toast.LENGTH_LONG).show();
                /*
                String keyLogs = rustTls.getKeyLogs();
                TextView keyLogsView = findViewById(R.id.sample_text);
                keyLogsView.setText(keyLogs);
                */
            }
        });



    }
}