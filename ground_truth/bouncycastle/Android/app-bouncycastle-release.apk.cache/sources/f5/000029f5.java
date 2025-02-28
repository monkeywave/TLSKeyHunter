package org.bouncycastle.pqc.crypto.mldsa;

import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.DigestUtils;

/* loaded from: classes2.dex */
public class HashMLDSASigner implements Signer {
    private static final byte[] EMPTY_CONTEXT = new byte[0];
    private Digest digest;
    private byte[] digestOIDEncoding;
    private MLDSAEngine engine;
    private MLDSAPrivateKeyParameters privKey;
    private MLDSAPublicKeyParameters pubKey;
    private SecureRandom random;

    private static Digest createDigest(MLDSAParameters mLDSAParameters) {
        int type = mLDSAParameters.getType();
        if (type == 0 || type == 1) {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("unknown parameters type");
    }

    private SHAKEDigest finishPreHash() {
        int digestSize = this.digest.getDigestSize();
        byte[] bArr = new byte[digestSize];
        this.digest.doFinal(bArr, 0);
        SHAKEDigest shake256Digest = this.engine.getShake256Digest();
        byte[] bArr2 = this.digestOIDEncoding;
        shake256Digest.update(bArr2, 0, bArr2.length);
        shake256Digest.update(bArr, 0, digestSize);
        return shake256Digest;
    }

    private void initDigest(MLDSAParameters mLDSAParameters) {
        Digest createDigest = createDigest(mLDSAParameters);
        this.digest = createDigest;
        try {
            this.digestOIDEncoding = DigestUtils.getDigestOid(createDigest.getAlgorithmName()).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new IllegalStateException("oid encoding failed: " + e.getMessage());
        }
    }

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() throws CryptoException, DataLengthException {
        SHAKEDigest finishPreHash = finishPreHash();
        byte[] bArr = new byte[32];
        SecureRandom secureRandom = this.random;
        if (secureRandom != null) {
            secureRandom.nextBytes(bArr);
        }
        return this.engine.generateSignature(finishPreHash, this.privKey.rho, this.privKey.f1342k, this.privKey.f1345t0, this.privKey.f1343s1, this.privKey.f1344s2, bArr);
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
            engine.initSign(this.privKey.f1347tr, true, bArr);
        } else {
            MLDSAPublicKeyParameters mLDSAPublicKeyParameters = (MLDSAPublicKeyParameters) cipherParameters;
            this.pubKey = mLDSAPublicKeyParameters;
            this.privKey = null;
            this.random = null;
            parameters = mLDSAPublicKeyParameters.getParameters();
            MLDSAEngine engine2 = parameters.getEngine(null);
            this.engine = engine2;
            engine2.initVerify(this.pubKey.rho, this.pubKey.f1348t1, true, bArr);
        }
        initDigest(parameters);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.digest.reset();
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte b) {
        this.digest.update(b);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte[] bArr, int i, int i2) {
        this.digest.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public boolean verifySignature(byte[] bArr) {
        return this.engine.verifyInternal(bArr, bArr.length, finishPreHash(), this.pubKey.rho, this.pubKey.f1348t1);
    }
}