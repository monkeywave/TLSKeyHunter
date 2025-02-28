package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.tls.crypto.TlsCryptoProvider;

/* loaded from: classes2.dex */
public class JcaTlsCryptoProvider implements TlsCryptoProvider {
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static class NonceEntropySource extends SecureRandom {

        /* loaded from: classes2.dex */
        private static class NonceEntropySourceSpi extends SecureRandomSpi {
            private final MessageDigest digest;
            private final byte[] seed;
            private final SecureRandom source;
            private final byte[] state;

            NonceEntropySourceSpi(SecureRandom secureRandom, MessageDigest messageDigest) {
                this.source = secureRandom;
                this.digest = messageDigest;
                byte[] generateSeed = secureRandom.generateSeed(messageDigest.getDigestLength());
                this.seed = generateSeed;
                this.state = new byte[generateSeed.length];
            }

            private void runDigest(byte[] bArr, byte[] bArr2, byte[] bArr3) {
                this.digest.update(bArr);
                this.digest.update(bArr2);
                try {
                    this.digest.digest(bArr3, 0, bArr3.length);
                } catch (DigestException e) {
                    throw Exceptions.illegalStateException("unable to generate nonce data: " + e.getMessage(), e);
                }
            }

            @Override // java.security.SecureRandomSpi
            protected byte[] engineGenerateSeed(int i) {
                return this.source.generateSeed(i);
            }

            @Override // java.security.SecureRandomSpi
            protected void engineNextBytes(byte[] bArr) {
                synchronized (this.digest) {
                    int length = this.state.length;
                    int i = 0;
                    while (i != bArr.length) {
                        byte[] bArr2 = this.state;
                        if (length == bArr2.length) {
                            this.source.nextBytes(bArr2);
                            byte[] bArr3 = this.seed;
                            byte[] bArr4 = this.state;
                            runDigest(bArr3, bArr4, bArr4);
                            length = 0;
                        }
                        bArr[i] = this.state[length];
                        i++;
                        length++;
                    }
                }
            }

            @Override // java.security.SecureRandomSpi
            protected void engineSetSeed(byte[] bArr) {
                synchronized (this.digest) {
                    byte[] bArr2 = this.seed;
                    runDigest(bArr2, bArr, bArr2);
                }
            }
        }

        NonceEntropySource(JcaJceHelper jcaJceHelper, SecureRandom secureRandom) throws GeneralSecurityException {
            super(new NonceEntropySourceSpi(secureRandom, jcaJceHelper.createMessageDigest("SHA-512")), secureRandom.getProvider());
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCryptoProvider
    public JcaTlsCrypto create(SecureRandom secureRandom) {
        try {
            JcaJceHelper helper = getHelper();
            if (secureRandom == null) {
                secureRandom = helper instanceof DefaultJcaJceHelper ? SecureRandom.getInstance("DEFAULT") : SecureRandom.getInstance("DEFAULT", helper.createMessageDigest("SHA-512").getProvider());
            }
            return create(secureRandom, (SecureRandom) new NonceEntropySource(helper, secureRandom));
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException("unable to create JcaTlsCrypto: " + e.getMessage(), e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCryptoProvider
    public JcaTlsCrypto create(SecureRandom secureRandom, SecureRandom secureRandom2) {
        return new JcaTlsCrypto(getHelper(), secureRandom, secureRandom2);
    }

    public JcaJceHelper getHelper() {
        return this.helper;
    }

    public JcaTlsCryptoProvider setProvider(String str) {
        this.helper = new NamedJcaJceHelper(str);
        return this;
    }

    public JcaTlsCryptoProvider setProvider(Provider provider) {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }
}