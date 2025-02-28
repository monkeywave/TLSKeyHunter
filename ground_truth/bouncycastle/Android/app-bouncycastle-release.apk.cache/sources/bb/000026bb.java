package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.SecurityParameters;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public interface ProvTlsManager {
    void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws IOException;

    void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws IOException;

    BCX509Key chooseClientKey(String[] strArr, Principal[] principalArr);

    BCX509Key chooseServerKey(String[] strArr, Principal[] principalArr);

    ContextData getContextData();

    boolean getEnableSessionCreation();

    String getPeerHost();

    String getPeerHostSNI();

    int getPeerPort();

    int getTransportID();

    void notifyHandshakeComplete(ProvSSLConnection provSSLConnection);

    void notifyHandshakeSession(ProvSSLSessionContext provSSLSessionContext, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, ProvSSLSession provSSLSession);

    String selectApplicationProtocol(List<String> list);
}