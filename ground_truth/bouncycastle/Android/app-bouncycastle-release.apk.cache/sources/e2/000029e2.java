package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

/* loaded from: classes2.dex */
public class LMSContext implements Digest {

    /* renamed from: C */
    private final byte[] f1328C;
    private volatile Digest digest;
    private final LMOtsPrivateKey key;
    private final byte[][] path;
    private final LMOtsPublicKey publicKey;
    private final LMSigParameters sigParams;
    private final Object signature;
    private LMSSignedPubKey[] signedPubKeys;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext(LMOtsPrivateKey lMOtsPrivateKey, LMSigParameters lMSigParameters, Digest digest, byte[] bArr, byte[][] bArr2) {
        this.key = lMOtsPrivateKey;
        this.sigParams = lMSigParameters;
        this.digest = digest;
        this.f1328C = bArr;
        this.path = bArr2;
        this.publicKey = null;
        this.signature = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext(LMOtsPublicKey lMOtsPublicKey, Object obj, Digest digest) {
        this.publicKey = lMOtsPublicKey;
        this.signature = obj;
        this.digest = digest;
        this.f1328C = null;
        this.key = null;
        this.sigParams = null;
        this.path = null;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        return this.digest.doFinal(bArr, i);
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return this.digest.getAlgorithmName();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getC() {
        return this.f1328C;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.digest.getDigestSize();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[][] getPath() {
        return this.path;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMOtsPrivateKey getPrivateKey() {
        return this.key;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMOtsPublicKey getPublicKey() {
        return this.publicKey;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getQ() {
        byte[] bArr = new byte[34];
        this.digest.doFinal(bArr, 0);
        this.digest = null;
        return bArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSigParameters getSigParams() {
        return this.sigParams;
    }

    public Object getSignature() {
        return this.signature;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSSignedPubKey[] getSignedPubKeys() {
        return this.signedPubKeys;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.digest.reset();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        this.digest.update(b);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        this.digest.update(bArr, i, i2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext withSignedPublicKeys(LMSSignedPubKey[] lMSSignedPubKeyArr) {
        this.signedPubKeys = lMSSignedPubKeyArr;
        return this;
    }
}