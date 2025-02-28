package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/* loaded from: classes2.dex */
public interface TlsKeyExchangeFactory {
    TlsKeyExchange createDHEKeyExchangeClient(int i, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException;

    TlsKeyExchange createDHEKeyExchangeServer(int i, TlsDHConfig tlsDHConfig) throws IOException;

    TlsKeyExchange createDHKeyExchange(int i) throws IOException;

    TlsKeyExchange createDHanonKeyExchangeClient(int i, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException;

    TlsKeyExchange createDHanonKeyExchangeServer(int i, TlsDHConfig tlsDHConfig) throws IOException;

    TlsKeyExchange createECDHEKeyExchangeClient(int i) throws IOException;

    TlsKeyExchange createECDHEKeyExchangeServer(int i, TlsECConfig tlsECConfig) throws IOException;

    TlsKeyExchange createECDHKeyExchange(int i) throws IOException;

    TlsKeyExchange createECDHanonKeyExchangeClient(int i) throws IOException;

    TlsKeyExchange createECDHanonKeyExchangeServer(int i, TlsECConfig tlsECConfig) throws IOException;

    TlsKeyExchange createPSKKeyExchangeClient(int i, TlsPSKIdentity tlsPSKIdentity, TlsDHGroupVerifier tlsDHGroupVerifier) throws IOException;

    TlsKeyExchange createPSKKeyExchangeServer(int i, TlsPSKIdentityManager tlsPSKIdentityManager, TlsDHConfig tlsDHConfig, TlsECConfig tlsECConfig) throws IOException;

    TlsKeyExchange createRSAKeyExchange(int i) throws IOException;

    TlsKeyExchange createSRPKeyExchangeClient(int i, TlsSRPIdentity tlsSRPIdentity, TlsSRPConfigVerifier tlsSRPConfigVerifier) throws IOException;

    TlsKeyExchange createSRPKeyExchangeServer(int i, TlsSRPLoginParameters tlsSRPLoginParameters) throws IOException;
}