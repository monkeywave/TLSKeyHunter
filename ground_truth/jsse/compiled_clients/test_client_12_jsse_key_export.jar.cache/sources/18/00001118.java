package org.openjsse.sun.security.ssl;

import java.security.AlgorithmParameters;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSASignature.class */
public final class RSASignature extends SignatureSpi {
    private final Signature rawRsa = JsseJce.getSignature("NONEwithRSA");
    private final MessageDigest mdMD5 = JsseJce.getMessageDigest("MD5");
    private final MessageDigest mdSHA = JsseJce.getMessageDigest("SHA");

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Signature getInstance() throws NoSuchAlgorithmException {
        return JsseJce.getSignature("MD5andSHA1withRSA");
    }

    @Override // java.security.SignatureSpi
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey == null) {
            throw new InvalidKeyException("Public key must not be null");
        }
        this.mdMD5.reset();
        this.mdSHA.reset();
        this.rawRsa.initVerify(publicKey);
    }

    @Override // java.security.SignatureSpi
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override // java.security.SignatureSpi
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("Private key must not be null");
        }
        this.mdMD5.reset();
        this.mdSHA.reset();
        this.rawRsa.initSign(privateKey, random);
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte b) {
        this.mdMD5.update(b);
        this.mdSHA.update(b);
    }

    @Override // java.security.SignatureSpi
    protected void engineUpdate(byte[] b, int off, int len) {
        this.mdMD5.update(b, off, len);
        this.mdSHA.update(b, off, len);
    }

    private byte[] getDigest() throws SignatureException {
        try {
            byte[] data = new byte[36];
            this.mdMD5.digest(data, 0, 16);
            this.mdSHA.digest(data, 16, 20);
            return data;
        } catch (DigestException e) {
            throw new SignatureException(e);
        }
    }

    @Override // java.security.SignatureSpi
    protected byte[] engineSign() throws SignatureException {
        this.rawRsa.update(getDigest());
        return this.rawRsa.sign();
    }

    @Override // java.security.SignatureSpi
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    @Override // java.security.SignatureSpi
    protected boolean engineVerify(byte[] sigBytes, int offset, int length) throws SignatureException {
        this.rawRsa.update(getDigest());
        return this.rawRsa.verify(sigBytes, offset, length);
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override // java.security.SignatureSpi
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameters accepted");
        }
    }

    @Override // java.security.SignatureSpi
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override // java.security.SignatureSpi
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }
}