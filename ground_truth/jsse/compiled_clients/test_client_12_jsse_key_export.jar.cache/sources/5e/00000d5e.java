package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/LMSContext.class */
public class LMSContext implements Digest {

    /* renamed from: C */
    private final byte[] f839C;
    private final LMOtsPrivateKey key;
    private final LMSigParameters sigParams;
    private final byte[][] path;
    private final LMOtsPublicKey publicKey;
    private final Object signature;
    private LMSSignedPubKey[] signedPubKeys;
    private volatile Digest digest;

    public LMSContext(LMOtsPrivateKey lMOtsPrivateKey, LMSigParameters lMSigParameters, Digest digest, byte[] bArr, byte[][] bArr2) {
        this.key = lMOtsPrivateKey;
        this.sigParams = lMSigParameters;
        this.digest = digest;
        this.f839C = bArr;
        this.path = bArr2;
        this.publicKey = null;
        this.signature = null;
    }

    public LMSContext(LMOtsPublicKey lMOtsPublicKey, Object obj, Digest digest) {
        this.publicKey = lMOtsPublicKey;
        this.signature = obj;
        this.digest = digest;
        this.f839C = null;
        this.key = null;
        this.sigParams = null;
        this.path = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getC() {
        return this.f839C;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getQ() {
        byte[] bArr = new byte[34];
        this.digest.doFinal(bArr, 0);
        this.digest = null;
        return bArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[][] getPath() {
        return this.path;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMOtsPrivateKey getPrivateKey() {
        return this.key;
    }

    public LMOtsPublicKey getPublicKey() {
        return this.publicKey;
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

    /* JADX INFO: Access modifiers changed from: package-private */
    public LMSContext withSignedPublicKeys(LMSSignedPubKey[] lMSSignedPubKeyArr) {
        this.signedPubKeys = lMSSignedPubKeyArr;
        return this;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return this.digest.getAlgorithmName();
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.digest.getDigestSize();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        this.digest.update(b);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        this.digest.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        return this.digest.doFinal(bArr, i);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.digest.reset();
    }
}