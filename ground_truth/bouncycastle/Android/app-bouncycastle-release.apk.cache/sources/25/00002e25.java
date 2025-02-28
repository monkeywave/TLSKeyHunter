package org.bouncycastle.tls.crypto.impl.p018bc;

import java.math.BigInteger;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsSRP6VerifierGenerator */
/* loaded from: classes2.dex */
final class BcTlsSRP6VerifierGenerator implements TlsSRP6VerifierGenerator {
    private final SRP6VerifierGenerator srp6VerifierGenerator;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsSRP6VerifierGenerator(SRP6VerifierGenerator sRP6VerifierGenerator) {
        this.srp6VerifierGenerator = sRP6VerifierGenerator;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator
    public BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        return this.srp6VerifierGenerator.generateVerifier(bArr, bArr2, bArr3);
    }
}