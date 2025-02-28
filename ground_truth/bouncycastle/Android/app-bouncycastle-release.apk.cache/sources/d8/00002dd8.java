package org.bouncycastle.tls.crypto;

/* loaded from: classes2.dex */
public class TlsDHConfig {
    protected final DHGroup explicitGroup;
    protected final int namedGroup;
    protected final boolean padded;

    public TlsDHConfig(int i, boolean z) {
        this.explicitGroup = null;
        this.namedGroup = i;
        this.padded = z;
    }

    public TlsDHConfig(DHGroup dHGroup) {
        this.explicitGroup = dHGroup;
        this.namedGroup = -1;
        this.padded = false;
    }

    public DHGroup getExplicitGroup() {
        return this.explicitGroup;
    }

    public int getNamedGroup() {
        return this.namedGroup;
    }

    public boolean isPadded() {
        return this.padded;
    }
}