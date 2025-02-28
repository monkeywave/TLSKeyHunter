package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.cert.X509Certificate;
import org.openjsse.sun.security.ssl.ClientHello;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHandshakeContext.class */
public class ClientHandshakeContext extends HandshakeContext {
    static final boolean allowUnsafeServerCertChange = Utilities.getBooleanProperty("jdk.tls.allowUnsafeServerCertChange", false);
    X509Certificate[] reservedServerCerts;
    X509Certificate[] deferredCerts;
    ClientHello.ClientHelloMessage initialClientHelloMsg;
    byte[] pskIdentity;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClientHandshakeContext(SSLContextImpl sslContext, TransportContext conContext) throws IOException {
        super(sslContext, conContext);
        this.reservedServerCerts = null;
        this.initialClientHelloMsg = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.HandshakeContext
    public void kickstart() throws IOException {
        if (this.kickstartMessageDelivered) {
            return;
        }
        SSLHandshake.kickstart(this);
        this.kickstartMessageDelivered = true;
    }
}