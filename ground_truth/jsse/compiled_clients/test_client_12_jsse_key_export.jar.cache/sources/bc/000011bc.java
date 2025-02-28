package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.PrivilegedAction;
import org.openjsse.sun.security.ssl.CertificateMessage;
import org.openjsse.sun.security.ssl.StatusResponseManager;
import sun.security.action.GetLongAction;
import sun.security.util.LegacyAlgorithmConstraints;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHandshakeContext.class */
public class ServerHandshakeContext extends HandshakeContext {
    static final boolean rejectClientInitiatedRenego = Utilities.getBooleanProperty("jdk.tls.rejectClientInitiatedRenegotiation", false);
    static final AlgorithmConstraints legacyAlgorithmConstraints = new LegacyAlgorithmConstraints("jdk.tls.legacyAlgorithms", new SSLAlgorithmDecomposer());
    SSLPossession interimAuthn;
    StatusResponseManager.StaplingParameters stapleParams;
    CertificateMessage.CertificateEntry currentCertEntry;
    private static final long DEFAULT_STATUS_RESP_DELAY = 5000;
    final long statusRespTimeout;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ServerHandshakeContext(SSLContextImpl sslContext, TransportContext conContext) throws IOException {
        super(sslContext, conContext);
        long respTimeOut = ((Long) AccessController.doPrivileged((PrivilegedAction<Object>) new GetLongAction("jdk.tls.stapling.responseTimeout", (long) DEFAULT_STATUS_RESP_DELAY))).longValue();
        this.statusRespTimeout = respTimeOut >= 0 ? respTimeOut : DEFAULT_STATUS_RESP_DELAY;
        this.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id), SSLHandshake.CLIENT_HELLO);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.HandshakeContext
    public void kickstart() throws IOException {
        if (!this.conContext.isNegotiated || this.kickstartMessageDelivered) {
            return;
        }
        SSLHandshake.kickstart(this);
        this.kickstartMessageDelivered = true;
    }
}