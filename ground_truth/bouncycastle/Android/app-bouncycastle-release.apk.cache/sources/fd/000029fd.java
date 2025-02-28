package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/* loaded from: classes2.dex */
public class MLDSASigner implements Signer {
    private static final byte[] EMPTY_CONTEXT = new byte[0];
    private MLDSAEngine engine;
    private SHAKEDigest msgDigest;
    private MLDSAPrivateKeyParameters privKey;
    private MLDSAPublicKeyParameters pubKey;
    private SecureRandom random;

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() throws CryptoException, DataLengthException {
        byte[] bArr = new byte[32];
        SecureRandom secureRandom = this.random;
        if (secureRandom != null) {
            secureRandom.nextBytes(bArr);
        }
        byte[] generateSignature = this.engine.generateSignature(this.msgDigest, this.privKey.rho, this.privKey.f1342k, this.privKey.f1345t0, this.privKey.f1343s1, this.privKey.f1344s2, bArr);
        reset();
        return generateSignature;
    }

    @Override // org.bouncycastle.crypto.Signer
    public void init(boolean z, CipherParameters cipherParameters) {
        MLDSAParameters parameters;
        byte[] bArr = EMPTY_CONTEXT;
        if (cipherParameters instanceof ParametersWithContext) {
            ParametersWithContext parametersWithContext = (ParametersWithContext) cipherParameters;
            bArr = parametersWithContext.getContext();
            cipherParameters = parametersWithContext.getParameters();
            if (bArr.length > 255) {
                throw new IllegalArgumentException("context too long");
            }
        }
        if (z) {
            this.pubKey = null;
            if (cipherParameters instanceof ParametersWithRandom) {
                ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
                this.privKey = (MLDSAPrivateKeyParameters) parametersWithRandom.getParameters();
                this.random = parametersWithRandom.getRandom();
            } else {
                this.privKey = (MLDSAPrivateKeyParameters) cipherParameters;
                this.random = null;
            }
            parameters = this.privKey.getParameters();
            MLDSAEngine engine = parameters.getEngine(this.random);
            this.engine = engine;
            engine.initSign(this.privKey.f1347tr, false, bArr);
        } else {
            MLDSAPublicKeyParameters mLDSAPublicKeyParameters = (MLDSAPublicKeyParameters) cipherParameters;
            this.pubKey = mLDSAPublicKeyParameters;
            this.privKey = null;
            this.random = null;
            parameters = mLDSAPublicKeyParameters.getParameters();
            MLDSAEngine engine2 = parameters.getEngine(null);
            this.engine = engine2;
            engine2.initVerify(this.pubKey.rho, this.pubKey.f1348t1, false, bArr);
        }
        if (parameters.isPreHash()) {
            throw new IllegalArgumentException("\"pure\" ml-dsa must use non pre-hash parameters");
        }
        reset();
    }

    protected byte[] internalGenerateSignature(byte[] bArr, byte[] bArr2) {
        MLDSAEngine engine = this.privKey.getParameters().getEngine(this.random);
        engine.initSign(this.privKey.f1347tr, false, null);
        return engine.signInternal(bArr, bArr.length, this.privKey.rho, this.privKey.f1342k, this.privKey.f1345t0, this.privKey.f1343s1, this.privKey.f1344s2, bArr2);
    }

    protected boolean internalVerifySignature(byte[] bArr, byte[] bArr2) {
        MLDSAEngine engine = this.pubKey.getParameters().getEngine(this.random);
        engine.initVerify(this.pubKey.rho, this.pubKey.f1348t1, false, null);
        SHAKEDigest shake256Digest = engine.getShake256Digest();
        shake256Digest.update(bArr, 0, bArr.length);
        return engine.verifyInternal(bArr2, bArr2.length, shake256Digest, this.pubKey.rho, this.pubKey.f1348t1);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.msgDigest = this.engine.getShake256Digest();
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte b) {
        this.msgDigest.update(b);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte[] bArr, int i, int i2) {
        this.msgDigest.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public boolean verifySignature(byte[] bArr) {
        boolean verifyInternal = this.engine.verifyInternal(bArr, bArr.length, this.msgDigest, this.pubKey.rho, this.pubKey.f1348t1);
        reset();
        return verifyInternal;
    }
}