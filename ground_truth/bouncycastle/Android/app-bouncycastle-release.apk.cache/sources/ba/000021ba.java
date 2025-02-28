package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.pqc.crypto.slhdsa.HashSLHDSASigner;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;

/* loaded from: classes2.dex */
public class HashSignatureSpi extends BaseDeterministicOrRandomSignature {
    private final HashSLHDSASigner signer;

    /* loaded from: classes2.dex */
    public static class Direct extends HashSignatureSpi {
        public Direct() {
            super(new HashSLHDSASigner());
        }
    }

    protected HashSignatureSpi(HashSLHDSASigner hashSLHDSASigner) {
        super("HASH-SLH-DSA");
        this.signer = hashSLHDSASigner;
    }

    @Override // java.security.SignatureSpi
    protected byte[] engineSign() throws SignatureException {
        if (this.keyParams instanceof SLHDSAPrivateKeyParameters) {
            try {
                try {
                    return this.signer.generateSignature();
                } catch (Exception e) {
                    throw new SignatureException(e.toString());
                }
            } finally {
                this.isInitState = true;
            }
        }
        throw new SignatureException("engine initialized for verification");
    }

    @Override // java.security.SignatureSpi
    protected boolean engineVerify(byte[] bArr) throws SignatureException {
        if (this.keyParams instanceof SLHDSAPublicKeyParameters) {
            try {
                return this.signer.verifySignature(bArr);
            } finally {
                this.isInitState = true;
            }
        }
        throw new SignatureException("engine initialized for signing");
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature
    protected void reInitialize(boolean z, CipherParameters cipherParameters) {
        this.signer.init(z, cipherParameters);
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature
    protected void signInit(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException {
        this.appRandom = secureRandom;
        if (!(privateKey instanceof BCSLHDSAPrivateKey)) {
            throw new InvalidKeyException("unknown private key passed to SLH-DSA");
        }
        this.keyParams = ((BCSLHDSAPrivateKey) privateKey).getKeyParams();
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature
    protected void updateEngine(byte b) throws SignatureException {
        this.signer.update(b);
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature
    protected void updateEngine(byte[] bArr, int i, int i2) throws SignatureException {
        this.signer.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature
    protected void verifyInit(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof BCSLHDSAPublicKey)) {
            throw new InvalidKeyException("unknown public key passed to SLH-DSA");
        }
        this.keyParams = ((BCSLHDSAPublicKey) publicKey).getKeyParams();
    }
}