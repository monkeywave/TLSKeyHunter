package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsSecret;

/* loaded from: classes2.dex */
public class TlsRSAKeyExchange extends AbstractTlsKeyExchange {
    protected TlsSecret preMasterSecret;
    protected TlsCredentialedDecryptor serverCredentials;
    protected TlsEncryptor serverEncryptor;

    public TlsRSAKeyExchange(int i) {
        super(checkKeyExchange(i));
        this.serverCredentials = null;
    }

    private static int checkKeyExchange(int i) {
        if (i == 1) {
            return i;
        }
        throw new IllegalArgumentException("unsupported key exchange algorithm");
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream outputStream) throws IOException {
        this.preMasterSecret = TlsUtils.generateEncryptedPreMasterSecret(this.context, this.serverEncryptor, outputStream);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        TlsSecret tlsSecret = this.preMasterSecret;
        this.preMasterSecret = null;
        return tlsSecret;
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public short[] getClientCertificateTypes() {
        return new short[]{1, 2, 64};
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        TlsUtils.requireSignerCredentials(tlsCredentials);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processClientKeyExchange(InputStream inputStream) throws IOException {
        this.preMasterSecret = this.serverCredentials.decrypt(new TlsCryptoParameters(this.context), TlsUtils.readEncryptedPMS(this.context, inputStream));
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processServerCertificate(Certificate certificate) throws IOException {
        this.serverEncryptor = certificate.getCertificateAt(0).createEncryptor(3);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials tlsCredentials) throws IOException {
        this.serverCredentials = TlsUtils.requireDecryptorCredentials(tlsCredentials);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }
}