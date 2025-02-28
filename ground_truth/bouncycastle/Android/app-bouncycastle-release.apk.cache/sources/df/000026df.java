package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class TransportData {
    private final BCExtendedSSLSession handshakeSession;
    private final BCSSLParameters parameters;

    private TransportData(BCSSLParameters bCSSLParameters, BCExtendedSSLSession bCExtendedSSLSession) {
        this.parameters = bCSSLParameters;
        this.handshakeSession = bCExtendedSSLSession;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TransportData from(Socket socket) {
        SSLSocket sSLSocket;
        BCSSLParameters importSSLParameters;
        if ((socket instanceof SSLSocket) && socket.isConnected() && (importSSLParameters = SSLSocketUtil.importSSLParameters((sSLSocket = (SSLSocket) socket))) != null) {
            return new TransportData(importSSLParameters, SSLSocketUtil.importHandshakeSession(sSLSocket));
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TransportData from(SSLEngine sSLEngine) {
        BCSSLParameters importSSLParameters;
        if (sSLEngine == null || (importSSLParameters = SSLEngineUtil.importSSLParameters(sSLEngine)) == null) {
            return null;
        }
        return new TransportData(importSSLParameters, SSLEngineUtil.importHandshakeSession(sSLEngine));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BCAlgorithmConstraints getAlgorithmConstraints(TransportData transportData, boolean z) {
        return transportData == null ? ProvAlgorithmConstraints.DEFAULT : transportData.getAlgorithmConstraints(z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<byte[]> getStatusResponses(TransportData transportData) {
        return transportData == null ? Collections.emptyList() : transportData.getStatusResponses();
    }

    BCAlgorithmConstraints getAlgorithmConstraints(boolean z) {
        BCAlgorithmConstraints algorithmConstraints = this.parameters.getAlgorithmConstraints();
        if (ProvAlgorithmConstraints.DEFAULT == algorithmConstraints) {
            algorithmConstraints = null;
        }
        BCExtendedSSLSession bCExtendedSSLSession = this.handshakeSession;
        if (bCExtendedSSLSession != null && JsseUtils.isTLSv12(bCExtendedSSLSession.getProtocol())) {
            String[] peerSupportedSignatureAlgorithmsBC = z ? this.handshakeSession.getPeerSupportedSignatureAlgorithmsBC() : this.handshakeSession.getLocalSupportedSignatureAlgorithmsBC();
            if (peerSupportedSignatureAlgorithmsBC != null) {
                return new ProvAlgorithmConstraints(algorithmConstraints, peerSupportedSignatureAlgorithmsBC, true);
            }
        }
        return algorithmConstraints == null ? ProvAlgorithmConstraints.DEFAULT : new ProvAlgorithmConstraints(algorithmConstraints, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCExtendedSSLSession getHandshakeSession() {
        return this.handshakeSession;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCSSLParameters getParameters() {
        return this.parameters;
    }

    List<byte[]> getStatusResponses() {
        BCExtendedSSLSession bCExtendedSSLSession = this.handshakeSession;
        return bCExtendedSSLSession == null ? Collections.emptyList() : bCExtendedSSLSession.getStatusResponses();
    }
}