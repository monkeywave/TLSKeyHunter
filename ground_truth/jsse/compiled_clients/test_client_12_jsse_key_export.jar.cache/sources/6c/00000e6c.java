package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/provider/qtesla/SignatureSpi.class */
public class SignatureSpi extends Signature {
    private Digest digest;
    private QTESLASigner signer;
    private SecureRandom random;

    /* renamed from: org.bouncycastle.pqc.jcajce.provider.qtesla.SignatureSpi$PI */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/provider/qtesla/SignatureSpi$PI.class */
    public static class C0345PI extends SignatureSpi {
        public C0345PI() {
            super(QTESLASecurityCategory.getName(5), new NullDigest(), new QTESLASigner());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/provider/qtesla/SignatureSpi$PIII.class */
    public static class PIII extends SignatureSpi {
        public PIII() {
            super(QTESLASecurityCategory.getName(6), new NullDigest(), new QTESLASigner());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/provider/qtesla/SignatureSpi$qTESLA.class */
    public static class qTESLA extends SignatureSpi {
        public qTESLA() {
            super("qTESLA", new NullDigest(), new QTESLASigner());
        }
    }

    protected SignatureSpi(String str) {
        super(str);
    }

    protected SignatureSpi(String str, Digest digest, QTESLASigner qTESLASigner) {
        super(str);
        this.digest = digest;
        this.signer = qTESLASigner;
    }

    @Override // java.security.SignatureSpi
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof BCqTESLAPublicKey)) {
            throw new InvalidKeyException("unknown public key passed to qTESLA");
        }
        CipherParameters keyParams = ((BCqTESLAPublicKey) publicKey).getKeyParams();
        this.digest.reset();
        this.signer.init(false, keyParams);
    }

    @Override // java.security.SignatureSpi
    protected void engineInitSign(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException {
        this.random = secureRandom;
        engineInitSign(privateKey);
    }

    @Override // java.security.SignatureSpi
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof BCqTESLAPrivateKey)) {
            throw new InvalidKeyException("unknown private key passed to qTESLA");
        }
        ParametersWithRandom keyParams = ((BCqTESLAPrivateKey) privateKey).getKeyParams();
        if (this.random != null) {
            keyParams = new ParametersWithRandom(keyParams, this.random);
        }
        this.signer.init(true, keyParams);
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte b) throws SignatureException {
        this.digest.update(b);
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte[] bArr, int i, int i2) throws SignatureException {
        this.digest.update(bArr, i, i2);
    }

    @Override // java.security.SignatureSpi
    protected byte[] engineSign() throws SignatureException {
        try {
            return this.signer.generateSignature(DigestUtil.getDigestResult(this.digest));
        } catch (Exception e) {
            if (e instanceof IllegalStateException) {
                throw new SignatureException(e.getMessage());
            }
            throw new SignatureException(e.toString());
        }
    }

    @Override // java.security.SignatureSpi
    protected boolean engineVerify(byte[] bArr) throws SignatureException {
        return this.signer.verifySignature(DigestUtil.getDigestResult(this.digest), bArr);
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(String str, Object obj) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    @Override // java.security.SignatureSpi
    protected Object engineGetParameter(String str) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
}