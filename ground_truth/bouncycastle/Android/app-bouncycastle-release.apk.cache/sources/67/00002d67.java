package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCrypto;

/* loaded from: classes2.dex */
public class PSKTlsClient extends AbstractTlsClient {
    private static final int[] DEFAULT_CIPHER_SUITES = {CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA};
    protected TlsPSKIdentity pskIdentity;

    public PSKTlsClient(TlsCrypto tlsCrypto, TlsPSKIdentity tlsPSKIdentity) {
        super(tlsCrypto);
        this.pskIdentity = tlsPSKIdentity;
    }

    public PSKTlsClient(TlsCrypto tlsCrypto, byte[] bArr, byte[] bArr2) {
        this(tlsCrypto, new BasicTlsPSKIdentity(bArr, bArr2));
    }

    @Override // org.bouncycastle.tls.TlsClient
    public TlsAuthentication getAuthentication() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsClient
    public TlsPSKIdentity getPSKIdentity() {
        return this.pskIdentity;
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
}