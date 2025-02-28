package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/GOST3411_2012_512Digest.class */
public class GOST3411_2012_512Digest extends GOST3411_2012Digest {

    /* renamed from: IV */
    private static final byte[] f163IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    public GOST3411_2012_512Digest() {
        super(f163IV);
    }

    public GOST3411_2012_512Digest(GOST3411_2012_512Digest gOST3411_2012_512Digest) {
        super(f163IV);
        reset(gOST3411_2012_512Digest);
    }

    @Override // org.bouncycastle.crypto.digests.GOST3411_2012Digest, org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "GOST3411-2012-512";
    }

    @Override // org.bouncycastle.crypto.digests.GOST3411_2012Digest, org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 64;
    }

    @Override // org.bouncycastle.crypto.digests.GOST3411_2012Digest, org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new GOST3411_2012_512Digest(this);
    }
}