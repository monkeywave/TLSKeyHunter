package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.pqc.crypto.KEMParameters;
import org.bouncycastle.tls.CipherSuite;

/* loaded from: classes2.dex */
public class BIKEParameters implements KEMParameters {
    public static final BIKEParameters bike128 = new BIKEParameters("bike128", 12323, CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA, CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA, 256, 5, 3, 128);
    public static final BIKEParameters bike192 = new BIKEParameters("bike192", 24659, 206, CipherSuite.TLS_SM4_CCM_SM3, 256, 5, 3, 192);
    public static final BIKEParameters bike256 = new BIKEParameters("bike256", 40973, 274, 264, 256, 5, 3, 256);
    private BIKEEngine bikeEngine;
    private final int defaultKeySize;

    /* renamed from: l */
    private int f1211l;
    private String name;
    private int nbIter;

    /* renamed from: r */
    private int f1212r;

    /* renamed from: t */
    private int f1213t;
    private int tau;

    /* renamed from: w */
    private int f1214w;

    private BIKEParameters(String str, int i, int i2, int i3, int i4, int i5, int i6, int i7) {
        this.name = str;
        this.f1212r = i;
        this.f1214w = i2;
        this.f1213t = i3;
        this.f1211l = i4;
        this.nbIter = i5;
        this.tau = i6;
        this.defaultKeySize = i7;
        this.bikeEngine = new BIKEEngine(i, i2, i3, i4, i5, i6);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BIKEEngine getEngine() {
        return this.bikeEngine;
    }

    public int getL() {
        return this.f1211l;
    }

    public int getLByte() {
        return this.f1211l / 8;
    }

    public String getName() {
        return this.name;
    }

    public int getNbIter() {
        return this.nbIter;
    }

    public int getR() {
        return this.f1212r;
    }

    public int getRByte() {
        return (this.f1212r + 7) / 8;
    }

    public int getSessionKeySize() {
        return this.defaultKeySize;
    }

    public int getT() {
        return this.f1213t;
    }

    public int getTau() {
        return this.tau;
    }

    public int getW() {
        return this.f1214w;
    }
}