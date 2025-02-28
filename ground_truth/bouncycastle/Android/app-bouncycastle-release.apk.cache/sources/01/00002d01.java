package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/* loaded from: classes2.dex */
public abstract class AbstractTlsKeyExchangeFactory implements TlsKeyExchangeFactory {
    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeClient(int i, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeServer(int i, TlsDHConfig tlsDHConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHKeyExchange(int i) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeClient(int i, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeServer(int i, TlsDHConfig tlsDHConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeClient(int i) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeServer(int i, TlsECConfig tlsECConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHKeyExchange(int i) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeClient(int i) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeServer(int i, TlsECConfig tlsECConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeClient(int i, TlsPSKIdentity tlsPSKIdentity, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeServer(int i, TlsPSKIdentityManager tlsPSKIdentityManager, TlsDHConfig tlsDHConfig, TlsECConfig tlsECConfig) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createRSAKeyExchange(int i) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeClient(int i, TlsSRPIdentity tlsSRPIdentity, TlsSRPConfigVerifier tlsSRPConfigVerifier) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeServer(int i, TlsSRPLoginParameters tlsSRPLoginParameters) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }
}