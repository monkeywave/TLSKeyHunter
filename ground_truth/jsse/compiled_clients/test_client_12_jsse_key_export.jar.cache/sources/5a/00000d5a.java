package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMOtsPrivateKey.class */
class LMOtsPrivateKey {
    private final LMOtsParameters parameter;

    /* renamed from: I */
    private final byte[] f832I;

    /* renamed from: q */
    private final int f833q;
    private final byte[] masterSecret;

    public LMOtsPrivateKey(LMOtsParameters lMOtsParameters, byte[] bArr, int i, byte[] bArr2) {
        this.parameter = lMOtsParameters;
        this.f832I = bArr;
        this.f833q = i;
        this.masterSecret = bArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext getSignatureContext(LMSigParameters lMSigParameters, byte[][] bArr) {
        byte[] bArr2 = new byte[32];
        SeedDerive derivationFunction = getDerivationFunction();
        derivationFunction.setJ(-3);
        derivationFunction.deriveSeed(bArr2, false);
        Digest digest = DigestUtil.getDigest(this.parameter.getDigestOID());
        LmsUtils.byteArray(getI(), digest);
        LmsUtils.u32str(getQ(), digest);
        LmsUtils.u16str((short) -32383, digest);
        LmsUtils.byteArray(bArr2, digest);
        return new LMSContext(this, lMSigParameters, digest, bArr2, bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SeedDerive getDerivationFunction() {
        SeedDerive seedDerive = new SeedDerive(this.f832I, this.masterSecret, DigestUtil.getDigest(this.parameter.getDigestOID()));
        seedDerive.setQ(this.f833q);
        return seedDerive;
    }

    public LMOtsParameters getParameter() {
        return this.parameter;
    }

    public byte[] getI() {
        return this.f832I;
    }

    public int getQ() {
        return this.f833q;
    }

    public byte[] getMasterSecret() {
        return this.masterSecret;
    }
}