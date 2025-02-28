package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCrypto;

/* loaded from: classes2.dex */
public abstract class DefaultTlsServer extends AbstractTlsServer {
    private static final int[] DEFAULT_CIPHER_SUITES = {CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, 57, 51};

    public DefaultTlsServer(TlsCrypto tlsCrypto) {
        super(tlsCrypto);
    }

    public TlsCredentials getCredentials() throws IOException {
        SecurityParameters securityParametersHandshake = this.context.getSecurityParametersHandshake();
        int keyExchangeAlgorithm = securityParametersHandshake.getKeyExchangeAlgorithm();
        if (keyExchangeAlgorithm != 0) {
            if (keyExchangeAlgorithm != 1) {
                if (keyExchangeAlgorithm != 3) {
                    if (keyExchangeAlgorithm != 5) {
                        if (keyExchangeAlgorithm == 17) {
                            return getECDSASignerCredentials();
                        }
                        if (keyExchangeAlgorithm != 19) {
                            throw new TlsFatalAlert((short) 80);
                        }
                    }
                    return getRSASignerCredentials();
                }
                return getDSASignerCredentials();
            }
            return getRSAEncryptionCredentials();
        }
        throw new TlsFatalAlert((short) 80, securityParametersHandshake.getNegotiatedVersion() + " credentials unhandled");
    }

    protected TlsCredentialedSigner getDSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    protected TlsCredentialedSigner getECDSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.tls.AbstractTlsPeer
    public int[] getSupportedCipherSuites() {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }
}