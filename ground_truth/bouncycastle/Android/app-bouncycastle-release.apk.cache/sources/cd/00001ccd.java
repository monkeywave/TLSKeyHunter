package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SHA512Digest extends LongDigest {
    private static final int DIGEST_LENGTH = 64;

    public SHA512Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public SHA512Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        reset();
    }

    public SHA512Digest(SHA512Digest sHA512Digest) {
        super(sHA512Digest);
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    public SHA512Digest(byte[] bArr) {
        super(CryptoServicePurpose.values()[bArr[bArr.length - 1]]);
        restoreState(bArr);
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SHA512Digest(this);
    }

    @Override // org.bouncycastle.crypto.digests.LongDigest
    protected CryptoServiceProperties cryptoServiceProperties() {
        return Utils.getDefaultProperties(this, 256, this.purpose);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        finish();
        Pack.longToBigEndian(this.f437H1, bArr, i);
        Pack.longToBigEndian(this.f438H2, bArr, i + 8);
        Pack.longToBigEndian(this.f439H3, bArr, i + 16);
        Pack.longToBigEndian(this.f440H4, bArr, i + 24);
        Pack.longToBigEndian(this.f441H5, bArr, i + 32);
        Pack.longToBigEndian(this.f442H6, bArr, i + 40);
        Pack.longToBigEndian(this.f443H7, bArr, i + 48);
        Pack.longToBigEndian(this.f444H8, bArr, i + 56);
        reset();
        return 64;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "SHA-512";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 64;
    }

    @Override // org.bouncycastle.crypto.digests.EncodableDigest
    public byte[] getEncodedState() {
        int encodedStateSize = getEncodedStateSize();
        byte[] bArr = new byte[encodedStateSize + 1];
        super.populateState(bArr);
        bArr[encodedStateSize] = (byte) this.purpose.ordinal();
        return bArr;
    }

    @Override // org.bouncycastle.crypto.digests.LongDigest, org.bouncycastle.crypto.Digest
    public void reset() {
        super.reset();
        this.f437H1 = 7640891576956012808L;
        this.f438H2 = -4942790177534073029L;
        this.f439H3 = 4354685564936845355L;
        this.f440H4 = -6534734903238641935L;
        this.f441H5 = 5840696475078001361L;
        this.f442H6 = -7276294671716946913L;
        this.f443H7 = 2270897969802886507L;
        this.f444H8 = 6620516959819538809L;
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        copyIn((SHA512Digest) memoable);
    }
}