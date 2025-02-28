package org.openjsse.sun.security.ssl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HKDF.class */
final class HKDF {
    private final String hmacAlg;
    private final Mac hmacObj;
    private final int hmacLen;

    /* JADX INFO: Access modifiers changed from: package-private */
    public HKDF(String hashAlg) throws NoSuchAlgorithmException {
        Objects.requireNonNull(hashAlg, "Must provide underlying HKDF Digest algorithm.");
        this.hmacAlg = "Hmac" + hashAlg.replace("-", "");
        this.hmacObj = JsseJce.getMac(this.hmacAlg);
        this.hmacLen = this.hmacObj.getMacLength();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecretKey extract(SecretKey salt, SecretKey inputKey, String keyAlg) throws InvalidKeyException {
        if (salt == null) {
            salt = new SecretKeySpec(new byte[this.hmacLen], "HKDF-Salt");
        }
        this.hmacObj.init(salt);
        return new SecretKeySpec(this.hmacObj.doFinal(inputKey.getEncoded()), keyAlg);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecretKey extract(byte[] salt, SecretKey inputKey, String keyAlg) throws InvalidKeyException {
        if (salt == null) {
            salt = new byte[this.hmacLen];
        }
        return extract(new SecretKeySpec(salt, "HKDF-Salt"), inputKey, keyAlg);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecretKey expand(SecretKey pseudoRandKey, byte[] info, int outLen, String keyAlg) throws InvalidKeyException {
        Objects.requireNonNull(pseudoRandKey, "A null PRK is not allowed.");
        if (outLen > GF2Field.MASK * this.hmacLen) {
            throw new IllegalArgumentException("Requested output length exceeds maximum length allowed for HKDF expansion");
        }
        this.hmacObj.init(pseudoRandKey);
        if (info == null) {
            info = new byte[0];
        }
        int rounds = ((outLen + this.hmacLen) - 1) / this.hmacLen;
        byte[] kdfOutput = new byte[rounds * this.hmacLen];
        int offset = 0;
        int tLength = 0;
        for (int i = 0; i < rounds; i++) {
            try {
                this.hmacObj.update(kdfOutput, Math.max(0, offset - this.hmacLen), tLength);
                this.hmacObj.update(info);
                this.hmacObj.update((byte) (i + 1));
                this.hmacObj.doFinal(kdfOutput, offset);
                tLength = this.hmacLen;
                offset += this.hmacLen;
            } catch (ShortBufferException sbe) {
                throw new RuntimeException(sbe);
            }
        }
        return new SecretKeySpec(kdfOutput, 0, outLen, keyAlg);
    }
}