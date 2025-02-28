package org.bouncycastle.tls.crypto;

/* loaded from: classes2.dex */
public class TlsECConfig {
    protected final int namedGroup;

    public TlsECConfig(int i) {
        this.namedGroup = i;
    }

    public int getNamedGroup() {
        return this.namedGroup;
    }
}