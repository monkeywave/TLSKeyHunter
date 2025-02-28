package com.example.tls_library_ground_truth;

import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import androidx.appcompat.app.AppCompatActivity;
import com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastle;
import com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastleKeyExport;
import com.example.tls_library_ground_truth.BouncyCastle.TestClient13BouncyCastle;
import com.example.tls_library_ground_truth.BouncyCastle.TestClient13BouncyCastleKeyExport;
import com.example.tls_library_ground_truth.databinding.ActivityMainBinding;
import java.util.HashMap;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    String[] libraryMapping;
    String flavor = "bouncycastle";
    boolean java_mode = false;
    boolean bouncy = false;
    int version_java_close = -1;
    String[] versionMapping = {"TLS 1.2", "TLS 1.3", "TLS 1.2 with key export", "TLS 1.3 with key export"};
    String[] supportedLibraries = {"BotanSSL", "OpenSSL", "LibreSSL", "S2nTLS", "WolfSSL", "MbedTLS", "bouncycastle", "BoringSSL"};
    String HOST = "10.0.2.2";
    int PORT = 4433;
    HashMap<String, Integer> libraryMappping_Hash = new HashMap<>();
    HashMap<String, Integer> versionMappping_Hash = new HashMap<String, Integer>() { // from class: com.example.tls_library_ground_truth.MainActivity.1
        {
            put("TLS 1.2", 0);
            put("TLS 1.3", 1);
            put("TLS 1.2 with key export", 2);
            put("TLS 1.3 with key export", 3);
        }
    };

    public native String closeClient();

    public native String runClient(int i, int i2, String str, String str2, int i3);

    static {
        System.loadLibrary("tls_library_ground_truth");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        ((EditText) findViewById(C0596R.C0599id.ip_field)).addTextChangedListener(new TextWatcher() { // from class: com.example.tls_library_ground_truth.MainActivity.2
            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
            }

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
                MainActivity.this.HOST = charSequence.toString();
            }
        });
        ((EditText) findViewById(C0596R.C0599id.port_field)).addTextChangedListener(new TextWatcher() { // from class: com.example.tls_library_ground_truth.MainActivity.3
            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
            }

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
                MainActivity.this.PORT = Integer.parseInt(charSequence.toString());
            }
        });
        if (this.flavor.equals("BotanSSL")) {
            this.libraryMapping = new String[]{"BotanSSL"};
            this.libraryMappping_Hash.put("BotanSSL", 0);
        } else if (this.flavor.equals("OpenSSL")) {
            this.libraryMapping = new String[]{"OpenSSL"};
            this.libraryMappping_Hash.put("OpenSSL", 1);
        } else if (this.flavor.equals("LibreSSL")) {
            this.libraryMapping = new String[]{"LibreSSL"};
            this.libraryMappping_Hash.put("LibreSSL", 2);
        } else if (this.flavor.equals("S2nTLS")) {
            this.libraryMapping = new String[]{"S2nTLS"};
            this.libraryMappping_Hash.put("S2nTLS", 3);
        } else if (this.flavor.equals("WolfSSL")) {
            this.libraryMapping = new String[]{"WolfSSL"};
            this.libraryMappping_Hash.put("WolfSSL", 4);
        } else if (this.flavor.equals("MbedTLS")) {
            this.libraryMapping = new String[]{"MbedTLS"};
            this.libraryMappping_Hash.put("MbedTLS", 5);
        } else if (this.flavor.equals("bouncycastle")) {
            this.java_mode = true;
            this.bouncy = true;
            this.libraryMapping = new String[]{"bouncycastle"};
            this.libraryMappping_Hash.put("bouncycastle", 6);
        } else if (!this.flavor.equals("BoringSSL")) {
            this.libraryMapping = new String[]{"BotanSSL", "OpenSSL", "LibreSSL", "S2nTLS", "WolfSSL", "MbedTLS", "bouncycastle", "BoringSSL"};
            this.libraryMappping_Hash.put("BotanSSL", 0);
            this.libraryMappping_Hash.put("OpenSSL", 1);
            this.libraryMappping_Hash.put("LibreSSL", 2);
            this.libraryMappping_Hash.put("S2nTLS", 3);
            this.libraryMappping_Hash.put("WolfSSL", 4);
            this.libraryMappping_Hash.put("MbedTLS", 5);
            this.libraryMappping_Hash.put("bouncycastle", 6);
            this.libraryMappping_Hash.put("BoringSSL", 7);
        } else {
            this.libraryMapping = new String[]{"BoringSSL"};
            this.libraryMappping_Hash.put("BoringSSL", 7);
        }
        final Spinner spinner = (Spinner) findViewById(C0596R.C0599id.library_spinner);
        ArrayAdapter arrayAdapter = new ArrayAdapter(this, 17367048, this.libraryMapping);
        arrayAdapter.setDropDownViewResource(17367049);
        spinner.setAdapter((SpinnerAdapter) arrayAdapter);
        final Spinner spinner2 = (Spinner) findViewById(C0596R.C0599id.version_spinner);
        ArrayAdapter arrayAdapter2 = new ArrayAdapter(this, 17367048, this.versionMapping);
        arrayAdapter2.setDropDownViewResource(17367049);
        spinner2.setAdapter((SpinnerAdapter) arrayAdapter2);
        spinner2.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() { // from class: com.example.tls_library_ground_truth.MainActivity.4
            @Override // android.widget.AdapterView.OnItemSelectedListener
            public void onNothingSelected(AdapterView<?> adapterView) {
            }

            @Override // android.widget.AdapterView.OnItemSelectedListener
            public void onItemSelected(AdapterView<?> adapterView, View view, int i, long j) {
                MainActivity.this.binding.textView.setText("");
                MainActivity.this.binding.keyView.setText("");
            }
        });
        this.binding.startButton.setOnClickListener(new View.OnClickListener() { // from class: com.example.tls_library_ground_truth.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.this.m251x802ec18b(spinner, spinner2, view);
            }
        });
        this.binding.stopButton.setOnClickListener(new View.OnClickListener() { // from class: com.example.tls_library_ground_truth.MainActivity$$ExternalSyntheticLambda1
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.this.m250xc3b9df4c(view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$onCreate$0$com-example-tls_library_ground_truth-MainActivity */
    public /* synthetic */ void m251x802ec18b(Spinner spinner, Spinner spinner2, View view) {
        String str;
        int intValue = this.libraryMappping_Hash.get(spinner.getSelectedItem().toString()).intValue();
        int intValue2 = this.versionMappping_Hash.get(spinner2.getSelectedItem().toString()).intValue();
        if (!this.java_mode) {
            str = runClient(intValue, intValue2, getApplicationContext().getFilesDir().getAbsolutePath() + "/sslkeylog.log", this.HOST, this.PORT);
            while (str == null) {
                try {
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        } else {
            this.version_java_close = intValue2;
            if (this.bouncy) {
                BouncyNetworkTask bouncyNetworkTask = new BouncyNetworkTask();
                bouncyNetworkTask.execute(Integer.valueOf(intValue2), 0, this.HOST, Integer.valueOf(this.PORT));
                try {
                    str = bouncyNetworkTask.get();
                } catch (Exception e2) {
                    e2.printStackTrace();
                    str = null;
                }
                while (str == null) {
                    try {
                        Thread.sleep(1L);
                    } catch (InterruptedException e3) {
                        e3.printStackTrace();
                    }
                }
            } else {
                str = null;
            }
        }
        if (!str.contains("KEYLOG")) {
            this.binding.textView.setText(str);
        } else if (intValue2 == 2 || intValue2 == 3) {
            String substring = str.substring(str.indexOf("KEYLOG:"));
            this.binding.textView.setText("\n" + this.supportedLibraries[intValue] + " " + this.versionMapping[intValue2] + " client: " + str.substring(0, str.indexOf("KEYLOG:")));
            this.binding.keyView.setText(substring);
        } else {
            this.binding.textView.setText("\n" + this.supportedLibraries[intValue] + " " + this.versionMapping[intValue2] + " client: " + str.substring(0, str.indexOf("KEYLOG:")));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$onCreate$1$com-example-tls_library_ground_truth-MainActivity */
    public /* synthetic */ void m250xc3b9df4c(View view) {
        if (!this.java_mode) {
            String closeClient = closeClient();
            while (closeClient == null) {
                try {
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            this.binding.textView.append("\n" + closeClient);
        } else if (this.bouncy) {
            BouncyNetworkTask bouncyNetworkTask = new BouncyNetworkTask();
            bouncyNetworkTask.execute(Integer.valueOf(this.version_java_close), 1, this.HOST, Integer.valueOf(this.PORT));
            try {
                this.binding.textView.append("\n" + bouncyNetworkTask.get());
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class BouncyNetworkTask extends AsyncTask<Object, Void, String> {
        private String HOST;
        private int PORT;
        private int mode;
        private int version;

        private BouncyNetworkTask() {
            this.version = -1;
            this.mode = -1;
            this.HOST = "10.0.2.2";
            this.PORT = 4433;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public String doInBackground(Object... objArr) {
            this.version = ((Integer) objArr[0]).intValue();
            this.mode = ((Integer) objArr[1]).intValue();
            this.HOST = (String) objArr[2];
            this.PORT = ((Integer) objArr[3]).intValue();
            int i = this.mode;
            if (i == 0) {
                return run_Bouncy();
            }
            if (i == 1) {
                return close_Bouncy();
            }
            return "Unsupported mode";
        }

        private String run_Bouncy() {
            int i = this.version;
            if (i != 0) {
                if (i != 1) {
                    if (i != 2) {
                        if (i == 3) {
                            return TestClient13BouncyCastleKeyExport.run_bouncy_13_ex(this.HOST, this.PORT);
                        }
                        return "Version not supported";
                    }
                    return TestClient12BouncyCastleKeyExport.run_bouncy_12_ex(this.HOST, this.PORT);
                }
                return TestClient13BouncyCastle.run_bouncy_13(this.HOST, this.PORT);
            }
            return TestClient12BouncyCastle.run_bouncy_12(this.HOST, this.PORT);
        }

        protected String close_Bouncy() {
            int i = this.version;
            if (i != 0) {
                if (i != 1) {
                    if (i != 2) {
                        if (i == 3) {
                            return TestClient13BouncyCastleKeyExport.close_bouncy_13_ex();
                        }
                        return "Version not supported";
                    }
                    return TestClient12BouncyCastleKeyExport.close_bouncy_12_ex();
                }
                return TestClient13BouncyCastle.close_bouncy_13();
            }
            return TestClient12BouncyCastle.close_bouncy_12();
        }
    }
}