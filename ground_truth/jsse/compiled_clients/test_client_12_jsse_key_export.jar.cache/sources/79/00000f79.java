package org.openjsse.javax.net.ssl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/javax/net/ssl/SSLEngine.class */
public abstract class SSLEngine extends javax.net.ssl.SSLEngine {
    public abstract boolean needUnwrapAgain();

    protected SSLEngine() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public SSLEngine(String peerHost, int peerPort) {
        super(peerHost, peerPort);
    }
}