package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsNonceGenerator */
/* loaded from: classes2.dex */
final class BcTlsNonceGenerator implements TlsNonceGenerator {
    private final RandomGenerator randomGenerator;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsNonceGenerator(RandomGenerator randomGenerator) {
        this.randomGenerator = randomGenerator;
    }

    @Override // org.bouncycastle.tls.crypto.TlsNonceGenerator
    public byte[] generateNonce(int i) {
        byte[] bArr = new byte[i];
        this.randomGenerator.nextBytes(bArr);
        return bArr;
    }
}