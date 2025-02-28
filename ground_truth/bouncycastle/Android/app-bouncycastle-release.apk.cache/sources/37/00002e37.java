package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;

/* loaded from: classes2.dex */
class JcaNonceGenerator implements TlsNonceGenerator {
    private final SP800SecureRandom random;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JcaNonceGenerator(SecureRandom secureRandom, byte[] bArr) {
        byte[] bArr2 = new byte[32];
        secureRandom.nextBytes(bArr2);
        this.random = new SP800SecureRandomBuilder(secureRandom, false).setPersonalizationString(bArr).buildHash(new SHA512Digest(), bArr2, false);
    }

    @Override // org.bouncycastle.tls.crypto.TlsNonceGenerator
    public byte[] generateNonce(int i) {
        byte[] bArr = new byte[i];
        this.random.nextBytes(bArr);
        return bArr;
    }
}