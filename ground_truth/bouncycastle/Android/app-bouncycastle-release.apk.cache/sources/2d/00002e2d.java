package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.math.p016ec.rfc7748.X448;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcX448 */
/* loaded from: classes2.dex */
public class BcX448 implements TlsAgreement {
    protected final BcTlsCrypto crypto;
    protected final byte[] privateKey = new byte[56];
    protected final byte[] peerPublicKey = new byte[56];

    public BcX448(BcTlsCrypto bcTlsCrypto) {
        this.crypto = bcTlsCrypto;
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        try {
            byte[] bArr = new byte[56];
            if (X448.calculateAgreement(this.privateKey, 0, this.peerPublicKey, 0, bArr, 0)) {
                return this.crypto.adoptLocalSecret(bArr);
            }
            throw new TlsFatalAlert((short) 40);
        } finally {
            Arrays.fill(this.privateKey, (byte) 0);
            Arrays.fill(this.peerPublicKey, (byte) 0);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        this.crypto.getSecureRandom().nextBytes(this.privateKey);
        byte[] bArr = new byte[56];
        X448.scalarMultBase(this.privateKey, 0, bArr, 0);
        return bArr;
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] bArr) throws IOException {
        if (bArr == null || bArr.length != 56) {
            throw new TlsFatalAlert((short) 47);
        }
        System.arraycopy(bArr, 0, this.peerPublicKey, 0, 56);
    }
}