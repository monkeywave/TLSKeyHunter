package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCrypto;

/* loaded from: classes2.dex */
public abstract class AbstractTlsPeer implements TlsPeer {
    private volatile TlsCloseable closeHandle;
    private final TlsCrypto crypto;

    /* JADX INFO: Access modifiers changed from: protected */
    public AbstractTlsPeer(TlsCrypto tlsCrypto) {
        this.crypto = tlsCrypto;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public boolean allowLegacyResumption() {
        return false;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void cancel() throws IOException {
        TlsCloseable tlsCloseable = this.closeHandle;
        if (tlsCloseable != null) {
            tlsCloseable.close();
        }
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public TlsCrypto getCrypto() {
        return this.crypto;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public int getHandshakeResendTimeMillis() {
        return 1000;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public int getHandshakeTimeoutMillis() {
        return 0;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public TlsHeartbeat getHeartbeat() {
        return null;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public short getHeartbeatPolicy() {
        return (short) 2;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public TlsKeyExchangeFactory getKeyExchangeFactory() throws IOException {
        return new DefaultTlsKeyExchangeFactory();
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public int getMaxCertificateChainLength() {
        return 10;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public int getMaxHandshakeMessageSize() {
        return 32768;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public short[] getPskKeyExchangeModes() {
        return new short[]{1};
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public int getRenegotiationPolicy() {
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract int[] getSupportedCipherSuites();

    /* JADX INFO: Access modifiers changed from: protected */
    public ProtocolVersion[] getSupportedVersions() {
        return ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv12);
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void notifyAlertRaised(short s, short s2, String str, Throwable th) {
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void notifyAlertReceived(short s, short s2) {
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void notifyCloseHandle(TlsCloseable tlsCloseable) {
        this.closeHandle = tlsCloseable;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void notifyConnectionClosed() {
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void notifyHandshakeBeginning() throws IOException {
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void notifyHandshakeComplete() throws IOException {
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public void notifySecureRenegotiation(boolean z) throws IOException {
        if (!z) {
            throw new TlsFatalAlert((short) 40);
        }
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public boolean requiresCloseNotify() {
        return true;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public boolean requiresExtendedMasterSecret() {
        return false;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public boolean shouldCheckSigAlgOfPeerCerts() {
        return true;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public boolean shouldUseExtendedMasterSecret() {
        return true;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public boolean shouldUseExtendedPadding() {
        return false;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public boolean shouldUseGMTUnixTime() {
        return false;
    }
}