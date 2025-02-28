package org.bouncycastle.tls.crypto;

/* loaded from: classes2.dex */
public class TlsKemConfig {
    protected final boolean isServer;
    protected final int namedGroup;

    public TlsKemConfig(int i, boolean z) {
        this.namedGroup = i;
        this.isServer = z;
    }

    public int getNamedGroup() {
        return this.namedGroup;
    }

    public boolean isServer() {
        return this.isServer;
    }
}