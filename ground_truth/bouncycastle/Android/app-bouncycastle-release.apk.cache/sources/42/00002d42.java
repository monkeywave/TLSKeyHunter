package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/* loaded from: classes2.dex */
public class DefaultTlsKeyExchangeFactory extends AbstractTlsKeyExchangeFactory {
    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeClient(int i, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException {
        return new TlsDHEKeyExchange(i, tlsDHGroupVerifier);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHEKeyExchangeServer(int i, TlsDHConfig tlsDHConfig) throws IOException {
        return new TlsDHEKeyExchange(i, tlsDHConfig);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHKeyExchange(int i) throws IOException {
        return new TlsDHKeyExchange(i);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeClient(int i, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException {
        return new TlsDHanonKeyExchange(i, tlsDHGroupVerifier);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createDHanonKeyExchangeServer(int i, TlsDHConfig tlsDHConfig) throws IOException {
        return new TlsDHanonKeyExchange(i, tlsDHConfig);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeClient(int i) throws IOException {
        return new TlsECDHEKeyExchange(i);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHEKeyExchangeServer(int i, TlsECConfig tlsECConfig) throws IOException {
        return new TlsECDHEKeyExchange(i, tlsECConfig);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHKeyExchange(int i) throws IOException {
        return new TlsECDHKeyExchange(i);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeClient(int i) throws IOException {
        return new TlsECDHanonKeyExchange(i);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createECDHanonKeyExchangeServer(int i, TlsECConfig tlsECConfig) throws IOException {
        return new TlsECDHanonKeyExchange(i, tlsECConfig);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeClient(int i, TlsPSKIdentity tlsPSKIdentity, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException {
        return new TlsPSKKeyExchange(i, tlsPSKIdentity, tlsDHGroupVerifier);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createPSKKeyExchangeServer(int i, TlsPSKIdentityManager tlsPSKIdentityManager, TlsDHConfig tlsDHConfig, TlsECConfig tlsECConfig) throws IOException {
        return new TlsPSKKeyExchange(i, tlsPSKIdentityManager, tlsDHConfig, tlsECConfig);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createRSAKeyExchange(int i) throws IOException {
        return new TlsRSAKeyExchange(i);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeClient(int i, TlsSRPIdentity tlsSRPIdentity, TlsSRPConfigVerifier tlsSRPConfigVerifier) throws IOException {
        return new TlsSRPKeyExchange(i, tlsSRPIdentity, tlsSRPConfigVerifier);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchangeFactory, org.bouncycastle.tls.TlsKeyExchangeFactory
    public TlsKeyExchange createSRPKeyExchangeServer(int i, TlsSRPLoginParameters tlsSRPLoginParameters) throws IOException {
        return new TlsSRPKeyExchange(i, tlsSRPLoginParameters);
    }
}