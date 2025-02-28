package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.Cipher;
import kotlin.UByte;
import org.bouncycastle.jcajce.spec.TLSRSAPremasterSecretParameterSpec;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class JceDefaultTlsCredentialedDecryptor implements TlsCredentialedDecryptor {
    protected Certificate certificate;
    protected JcaTlsCrypto crypto;
    protected PrivateKey privateKey;

    public JceDefaultTlsCredentialedDecryptor(JcaTlsCrypto jcaTlsCrypto, Certificate certificate, PrivateKey privateKey) {
        if (jcaTlsCrypto == null) {
            throw new IllegalArgumentException("'crypto' cannot be null");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty()) {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }
        if (!(privateKey instanceof RSAPrivateKey) && !"RSA".equals(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }
        this.crypto = jcaTlsCrypto;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override // org.bouncycastle.tls.TlsCredentialedDecryptor
    public TlsSecret decrypt(TlsCryptoParameters tlsCryptoParameters, byte[] bArr) throws IOException {
        return safeDecryptPreMasterSecret(tlsCryptoParameters, this.privateKey, bArr);
    }

    @Override // org.bouncycastle.tls.TlsCredentials
    public Certificate getCertificate() {
        return this.certificate;
    }

    protected TlsSecret safeDecryptPreMasterSecret(TlsCryptoParameters tlsCryptoParameters, PrivateKey privateKey, byte[] bArr) {
        byte[] bArr2;
        SecureRandom secureRandom = this.crypto.getSecureRandom();
        ProtocolVersion rSAPreMasterSecretVersion = tlsCryptoParameters.getRSAPreMasterSecretVersion();
        try {
            Cipher createRSAEncryptionCipher = this.crypto.createRSAEncryptionCipher();
            createRSAEncryptionCipher.init(2, privateKey, new TLSRSAPremasterSecretParameterSpec(rSAPreMasterSecretVersion.getFullVersion()), secureRandom);
            bArr2 = createRSAEncryptionCipher.doFinal(bArr);
        } catch (Exception unused) {
            byte[] bArr3 = new byte[48];
            secureRandom.nextBytes(bArr3);
            byte[] clone = Arrays.clone(bArr3);
            try {
                Cipher createRSAEncryptionCipher2 = this.crypto.createRSAEncryptionCipher();
                createRSAEncryptionCipher2.init(2, privateKey, secureRandom);
                byte[] doFinal = createRSAEncryptionCipher2.doFinal(bArr);
                if (doFinal != null) {
                    if (doFinal.length == 48) {
                        clone = doFinal;
                    }
                }
            } catch (Exception unused2) {
            }
            int minorVersion = (((rSAPreMasterSecretVersion.getMinorVersion() ^ (clone[1] & UByte.MAX_VALUE)) | (rSAPreMasterSecretVersion.getMajorVersion() ^ (clone[0] & UByte.MAX_VALUE))) - 1) >> 31;
            for (int i = 0; i < 48; i++) {
                clone[i] = (byte) ((clone[i] & minorVersion) | (bArr3[i] & (~minorVersion)));
            }
            bArr2 = clone;
        }
        return this.crypto.createSecret(bArr2);
    }
}