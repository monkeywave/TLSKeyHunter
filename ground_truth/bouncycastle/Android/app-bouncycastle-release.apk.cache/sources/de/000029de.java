package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

/* loaded from: classes2.dex */
class LMOtsPrivateKey {

    /* renamed from: I */
    private final byte[] f1321I;
    private final byte[] masterSecret;
    private final LMOtsParameters parameter;

    /* renamed from: q */
    private final int f1322q;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMOtsPrivateKey(LMOtsParameters lMOtsParameters, byte[] bArr, int i, byte[] bArr2) {
        this.parameter = lMOtsParameters;
        this.f1321I = bArr;
        this.f1322q = i;
        this.masterSecret = bArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SeedDerive getDerivationFunction() {
        SeedDerive seedDerive = new SeedDerive(this.f1321I, this.masterSecret, DigestUtil.getDigest(this.parameter));
        seedDerive.setQ(this.f1322q);
        return seedDerive;
    }

    public byte[] getI() {
        return this.f1321I;
    }

    public byte[] getMasterSecret() {
        return this.masterSecret;
    }

    public LMOtsParameters getParameter() {
        return this.parameter;
    }

    public int getQ() {
        return this.f1322q;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext getSignatureContext(LMSigParameters lMSigParameters, byte[][] bArr) {
        byte[] bArr2 = new byte[this.parameter.getN()];
        SeedDerive derivationFunction = getDerivationFunction();
        derivationFunction.setJ(-3);
        derivationFunction.deriveSeed(bArr2, false);
        Digest digest = DigestUtil.getDigest(this.parameter);
        LmsUtils.byteArray(getI(), digest);
        LmsUtils.u32str(getQ(), digest);
        LmsUtils.u16str((short) -32383, digest);
        LmsUtils.byteArray(bArr2, digest);
        return new LMSContext(this, lMSigParameters, digest, bArr2, bArr);
    }
}