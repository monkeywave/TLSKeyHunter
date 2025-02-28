package org.openjsse.javax.net.ssl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/javax/net/ssl/SSLParameters.class */
public class SSLParameters extends javax.net.ssl.SSLParameters {
    private boolean enableRetransmissions;
    private int maximumPacketSize;
    private String[] applicationProtocols;

    public SSLParameters() {
        this.enableRetransmissions = true;
        this.maximumPacketSize = 0;
        this.applicationProtocols = new String[0];
    }

    public SSLParameters(String[] cipherSuites) {
        super(cipherSuites);
        this.enableRetransmissions = true;
        this.maximumPacketSize = 0;
        this.applicationProtocols = new String[0];
    }

    public SSLParameters(String[] cipherSuites, String[] protocols) {
        super(cipherSuites, protocols);
        this.enableRetransmissions = true;
        this.maximumPacketSize = 0;
        this.applicationProtocols = new String[0];
    }

    public void setEnableRetransmissions(boolean enableRetransmissions) {
        this.enableRetransmissions = enableRetransmissions;
    }

    public boolean getEnableRetransmissions() {
        return this.enableRetransmissions;
    }

    public void setMaximumPacketSize(int maximumPacketSize) {
        if (maximumPacketSize < 0) {
            throw new IllegalArgumentException("The maximum packet size cannot be negative");
        }
        this.maximumPacketSize = maximumPacketSize;
    }

    public int getMaximumPacketSize() {
        return this.maximumPacketSize;
    }
}