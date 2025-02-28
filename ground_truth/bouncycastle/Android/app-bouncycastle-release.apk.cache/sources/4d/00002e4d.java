package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsEncryptor;

/* loaded from: classes2.dex */
final class JcaTlsRSAEncryptor implements TlsEncryptor {
    private final JcaTlsCrypto crypto;
    private final PublicKey pubKeyRSA;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JcaTlsRSAEncryptor(JcaTlsCrypto jcaTlsCrypto, PublicKey publicKey) {
        this.crypto = jcaTlsCrypto;
        this.pubKeyRSA = publicKey;
    }

    @Override // org.bouncycastle.tls.crypto.TlsEncryptor
    public byte[] encrypt(byte[] bArr, int i, int i2) throws IOException {
        try {
            Cipher createRSAEncryptionCipher = this.crypto.createRSAEncryptionCipher();
            try {
                createRSAEncryptionCipher.init(3, this.pubKeyRSA, this.crypto.getSecureRandom());
                return createRSAEncryptionCipher.wrap(new SecretKeySpec(bArr, i, i2, "TLS"));
            } catch (Exception e) {
                try {
                    createRSAEncryptionCipher.init(1, this.pubKeyRSA, this.crypto.getSecureRandom());
                    return createRSAEncryptionCipher.doFinal(bArr, i, i2);
                } catch (Exception unused) {
                    throw new TlsFatalAlert((short) 80, (Throwable) e);
                }
            }
        } catch (GeneralSecurityException e2) {
            throw new TlsFatalAlert((short) 80, (Throwable) e2);
        }
    }
}