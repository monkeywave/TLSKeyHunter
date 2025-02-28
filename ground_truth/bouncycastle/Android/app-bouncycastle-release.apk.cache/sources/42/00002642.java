package org.bouncycastle.jsse;

import java.io.IOException;
import javax.net.ssl.SSLSocket;

/* loaded from: classes2.dex */
public interface BCSSLSocket {
    void connect(String str, int i, int i2) throws IOException;

    String getApplicationProtocol();

    BCApplicationProtocolSelector<SSLSocket> getBCHandshakeApplicationProtocolSelector();

    BCExtendedSSLSession getBCHandshakeSession();

    BCExtendedSSLSession getBCSession();

    BCSSLConnection getConnection();

    String getHandshakeApplicationProtocol();

    BCSSLParameters getParameters();

    void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLSocket> bCApplicationProtocolSelector);

    void setBCSessionToResume(BCExtendedSSLSession bCExtendedSSLSession);

    void setHost(String str);

    void setParameters(BCSSLParameters bCSSLParameters);
}