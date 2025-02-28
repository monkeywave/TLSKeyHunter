package com.example.rustls_android;

public class RustTls {

    public String runRustls(int version, boolean keyLogsEnabled) {
        switch (version) {
            case 12:
                if (!keyLogsEnabled) {
                    System.out.println("Running Rustls 1.2");
                    return runTlsClient12();
                } else {
                    System.out.println("Running Rustls 1.2 with key logs");
                    return runTlsClient12Ex();
                }
            case 13:
                if (!keyLogsEnabled) {
                    System.out.println("Running Rustls 1.3");
                    return runTlsClient13();
                } else {
                    System.out.println("Running Rustls 1.3 with key logs");
                    return runTlsClient13Ex();
                }
            default:
                return "Invalid version";
        }
    }
    private native String runTlsClient12();
    private native  String runTlsClient12Ex();
    private native String runTlsClient13();
    private native  String runTlsClient13Ex();
    //public native String getKeyLogs();
}
