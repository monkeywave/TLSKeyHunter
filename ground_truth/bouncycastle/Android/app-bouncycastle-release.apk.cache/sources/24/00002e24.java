package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsSRP6Server;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsSRP6Server */
/* loaded from: classes2.dex */
final class BcTlsSRP6Server implements TlsSRP6Server {
    private final SRP6Server srp6Server;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsSRP6Server(SRP6Server sRP6Server) {
        this.srp6Server = sRP6Server;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSRP6Server
    public BigInteger calculateSecret(BigInteger bigInteger) throws IOException {
        try {
            return this.srp6Server.calculateSecret(bigInteger);
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsSRP6Server
    public BigInteger generateServerCredentials() {
        return this.srp6Server.generateServerCredentials();
    }
}