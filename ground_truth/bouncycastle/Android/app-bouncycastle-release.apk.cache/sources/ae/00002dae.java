package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCrypto;

/* loaded from: classes2.dex */
public interface TlsPeer {
    boolean allowLegacyResumption();

    void cancel() throws IOException;

    int[] getCipherSuites();

    TlsCrypto getCrypto();

    int getHandshakeResendTimeMillis();

    int getHandshakeTimeoutMillis();

    TlsHeartbeat getHeartbeat();

    short getHeartbeatPolicy();

    TlsKeyExchangeFactory getKeyExchangeFactory() throws IOException;

    int getMaxCertificateChainLength();

    int getMaxHandshakeMessageSize();

    ProtocolVersion[] getProtocolVersions();

    short[] getPskKeyExchangeModes();

    int getRenegotiationPolicy();

    void notifyAlertRaised(short s, short s2, String str, Throwable th);

    void notifyAlertReceived(short s, short s2);

    void notifyCloseHandle(TlsCloseable tlsCloseable);

    void notifyConnectionClosed();

    void notifyHandshakeBeginning() throws IOException;

    void notifyHandshakeComplete() throws IOException;

    void notifySecureRenegotiation(boolean z) throws IOException;

    boolean requiresCloseNotify();

    boolean requiresExtendedMasterSecret();

    boolean shouldCheckSigAlgOfPeerCerts();

    boolean shouldUseExtendedMasterSecret();

    boolean shouldUseExtendedPadding();

    boolean shouldUseGMTUnixTime();
}