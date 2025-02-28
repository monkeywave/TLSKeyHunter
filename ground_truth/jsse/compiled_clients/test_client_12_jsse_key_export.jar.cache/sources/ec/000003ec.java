package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/GOST3411_2012_256Digest.class */
public final class GOST3411_2012_256Digest extends GOST3411_2012Digest {

    /* renamed from: IV */
    private static final byte[] f162IV = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    public GOST3411_2012_256Digest() {
        super(f162IV);
    }

    public GOST3411_2012_256Digest(GOST3411_2012_256Digest gOST3411_2012_256Digest) {
        super(f162IV);
        reset(gOST3411_2012_256Digest);
    }

    @Override // org.bouncycastle.crypto.digests.GOST3411_2012Digest, org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "GOST3411-2012-256";
    }

    @Override // org.bouncycastle.crypto.digests.GOST3411_2012Digest, org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.digests.GOST3411_2012Digest, org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        byte[] bArr2 = new byte[64];
        super.doFinal(bArr2, 0);
        System.arraycopy(bArr2, 32, bArr, i, 32);
        return 32;
    }

    @Override // org.bouncycastle.crypto.digests.GOST3411_2012Digest, org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new GOST3411_2012_256Digest(this);
    }
}