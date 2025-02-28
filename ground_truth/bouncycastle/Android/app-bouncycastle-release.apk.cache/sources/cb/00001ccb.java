package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SHA384Digest extends LongDigest {
    private static final int DIGEST_LENGTH = 48;

    public SHA384Digest() {
        this(CryptoServicePurpose.ANY);
    }

    public SHA384Digest(CryptoServicePurpose cryptoServicePurpose) {
        super(cryptoServicePurpose);
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
        reset();
    }

    public SHA384Digest(SHA384Digest sHA384Digest) {
        super(sHA384Digest);
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    public SHA384Digest(byte[] bArr) {
        super(CryptoServicePurpose.values()[bArr[bArr.length - 1]]);
        restoreState(bArr);
        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    @Override // org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new SHA384Digest(this);
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
        reset();
        return 48;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return McElieceCCA2KeyGenParameterSpec.SHA384;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 48;
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
        this.f437H1 = -3766243637369397544L;
        this.f438H2 = 7105036623409894663L;
        this.f439H3 = -7973340178411365097L;
        this.f440H4 = 1526699215303891257L;
        this.f441H5 = 7436329637833083697L;
        this.f442H6 = -8163818279084223215L;
        this.f443H7 = -2662702644619276377L;
        this.f444H8 = 5167115440072839076L;
    }

    @Override // org.bouncycastle.util.Memoable
    public void reset(Memoable memoable) {
        super.copyIn((SHA384Digest) memoable);
    }
}