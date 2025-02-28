package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import org.bouncycastle.tls.crypto.TlsCrypto;

/* loaded from: classes2.dex */
public class SRPTlsServer extends AbstractTlsServer {
    private static final int[] DEFAULT_CIPHER_SUITES = {CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA, CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA};
    protected byte[] srpIdentity;
    protected TlsSRPIdentityManager srpIdentityManager;
    protected TlsSRPLoginParameters srpLoginParameters;

    public SRPTlsServer(TlsCrypto tlsCrypto, TlsSRPIdentityManager tlsSRPIdentityManager) {
        super(tlsCrypto);
        this.srpIdentity = null;
        this.srpLoginParameters = null;
        this.srpIdentityManager = tlsSRPIdentityManager;
    }

    @Override // org.bouncycastle.tls.TlsServer
    public TlsCredentials getCredentials() throws IOException {
        switch (this.context.getSecurityParametersHandshake().getKeyExchangeAlgorithm()) {
            case 21:
                return null;
            case 22:
                return getDSASignerCredentials();
            case 23:
                return getRSASignerCredentials();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    protected TlsCredentialedSigner getDSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public TlsSRPLoginParameters getSRPLoginParameters() throws IOException {
        return this.srpLoginParameters;
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public int getSelectedCipherSuite() throws IOException {
        int selectedCipherSuite = super.getSelectedCipherSuite();
        if (TlsSRPUtils.isSRPCipherSuite(selectedCipherSuite)) {
            byte[] bArr = this.srpIdentity;
            if (bArr != null) {
                this.srpLoginParameters = this.srpIdentityManager.getLoginParameters(bArr);
            }
            if (this.srpLoginParameters == null) {
                throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
            }
        }
        return selectedCipherSuite;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.tls.AbstractTlsPeer
    public int[] getSupportedCipherSuites() {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.tls.AbstractTlsPeer
    public ProtocolVersion[] getSupportedVersions() {
        return ProtocolVersion.TLSv12.only();
    }

    @Override // org.bouncycastle.tls.AbstractTlsServer, org.bouncycastle.tls.TlsServer
    public void processClientExtensions(Hashtable hashtable) throws IOException {
        super.processClientExtensions(hashtable);
        this.srpIdentity = TlsSRPUtils.getSRPExtension(hashtable);
    }
}