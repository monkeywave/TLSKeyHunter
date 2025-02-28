package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.p019io.TeeInputStream;

/* loaded from: classes2.dex */
public class TlsDHEKeyExchange extends AbstractTlsKeyExchange {
    protected TlsAgreement agreement;
    protected TlsDHConfig dhConfig;
    protected TlsDHGroupVerifier dhGroupVerifier;
    protected TlsCertificate serverCertificate;
    protected TlsCredentialedSigner serverCredentials;

    public TlsDHEKeyExchange(int i, TlsDHGroupVerifier tlsDHGroupVerifier) {
        this(i, tlsDHGroupVerifier, null);
    }

    private TlsDHEKeyExchange(int i, TlsDHGroupVerifier tlsDHGroupVerifier, TlsDHConfig tlsDHConfig) {
        super(checkKeyExchange(i));
        this.serverCredentials = null;
        this.serverCertificate = null;
        this.dhGroupVerifier = tlsDHGroupVerifier;
        this.dhConfig = tlsDHConfig;
    }

    public TlsDHEKeyExchange(int i, TlsDHConfig tlsDHConfig) {
        this(i, null, tlsDHConfig);
    }

    private static int checkKeyExchange(int i) {
        if (i == 3 || i == 5) {
            return i;
        }
        throw new IllegalArgumentException("unsupported key exchange algorithm");
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque16(this.agreement.generateEphemeral(), outputStream);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        return this.agreement.calculateSecret();
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        DigestInputBuffer digestInputBuffer = new DigestInputBuffer();
        TlsDHUtils.writeDHConfig(this.dhConfig, digestInputBuffer);
        TlsAgreement createDH = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
        this.agreement = createDH;
        TlsUtils.writeOpaque16(createDH.generateEphemeral(), digestInputBuffer);
        TlsUtils.generateServerKeyExchangeSignature(this.context, this.serverCredentials, null, digestInputBuffer);
        return digestInputBuffer.toByteArray();
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public short[] getClientCertificateTypes() {
        return new short[]{2, 64, 1};
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        TlsUtils.requireSignerCredentials(tlsCredentials);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processClientKeyExchange(InputStream inputStream) throws IOException {
        this.agreement.receivePeerValue(TlsUtils.readOpaque16(inputStream, 1));
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processServerCertificate(Certificate certificate) throws IOException {
        this.serverCertificate = certificate.getCertificateAt(0);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials tlsCredentials) throws IOException {
        this.serverCredentials = TlsUtils.requireSignerCredentials(tlsCredentials);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processServerKeyExchange(InputStream inputStream) throws IOException {
        DigestInputBuffer digestInputBuffer = new DigestInputBuffer();
        TeeInputStream teeInputStream = new TeeInputStream(inputStream, digestInputBuffer);
        this.dhConfig = TlsDHUtils.receiveDHConfig(this.context, this.dhGroupVerifier, teeInputStream);
        byte[] readOpaque16 = TlsUtils.readOpaque16(teeInputStream, 1);
        TlsUtils.verifyServerKeyExchangeSignature(this.context, inputStream, this.serverCertificate, null, digestInputBuffer);
        TlsAgreement createDH = this.context.getCrypto().createDHDomain(this.dhConfig).createDH();
        this.agreement = createDH;
        createDH.receivePeerValue(readOpaque16);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public boolean requiresServerKeyExchange() {
        return true;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }
}