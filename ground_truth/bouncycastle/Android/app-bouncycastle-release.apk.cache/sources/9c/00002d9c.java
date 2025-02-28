package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/* loaded from: classes2.dex */
public class TlsECDHanonKeyExchange extends AbstractTlsKeyExchange {
    protected TlsAgreement agreement;
    protected TlsECConfig ecConfig;

    public TlsECDHanonKeyExchange(int i) {
        this(i, null);
    }

    public TlsECDHanonKeyExchange(int i, TlsECConfig tlsECConfig) {
        super(checkKeyExchange(i));
        this.ecConfig = tlsECConfig;
    }

    private static int checkKeyExchange(int i) {
        if (i == 20) {
            return i;
        }
        throw new IllegalArgumentException("unsupported key exchange algorithm");
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void generateClientKeyExchange(OutputStream outputStream) throws IOException {
        generateEphemeral(outputStream);
    }

    protected void generateEphemeral(OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque8(this.agreement.generateEphemeral(), outputStream);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public TlsSecret generatePreMasterSecret() throws IOException {
        return this.agreement.calculateSecret();
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public byte[] generateServerKeyExchange() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsECCUtils.writeECConfig(this.ecConfig, byteArrayOutputStream);
        this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
        generateEphemeral(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public short[] getClientCertificateTypes() {
        return null;
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processClientCertificate(Certificate certificate) throws IOException {
        throw new TlsFatalAlert((short) 10);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processClientCredentials(TlsCredentials tlsCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processClientKeyExchange(InputStream inputStream) throws IOException {
        processEphemeral(TlsUtils.readOpaque8(inputStream, 1));
    }

    protected void processEphemeral(byte[] bArr) throws IOException {
        TlsECCUtils.checkPointEncoding(this.ecConfig.getNamedGroup(), bArr);
        this.agreement.receivePeerValue(bArr);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processServerCertificate(Certificate certificate) throws IOException {
        throw new TlsFatalAlert((short) 10);
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void processServerCredentials(TlsCredentials tlsCredentials) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public void processServerKeyExchange(InputStream inputStream) throws IOException {
        this.ecConfig = TlsECCUtils.receiveECDHConfig(this.context, inputStream);
        byte[] readOpaque8 = TlsUtils.readOpaque8(inputStream, 1);
        this.agreement = this.context.getCrypto().createECDomain(this.ecConfig).createECDH();
        processEphemeral(readOpaque8);
    }

    @Override // org.bouncycastle.tls.AbstractTlsKeyExchange, org.bouncycastle.tls.TlsKeyExchange
    public boolean requiresServerKeyExchange() {
        return true;
    }

    @Override // org.bouncycastle.tls.TlsKeyExchange
    public void skipServerCredentials() throws IOException {
    }
}