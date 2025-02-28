package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/* loaded from: classes2.dex */
public interface TlsServer extends TlsPeer {
    CertificateRequest getCertificateRequest() throws IOException;

    CertificateStatus getCertificateStatus() throws IOException;

    TlsCredentials getCredentials() throws IOException;

    TlsDHConfig getDHConfig() throws IOException;

    TlsECConfig getECDHConfig() throws IOException;

    TlsPSKExternal getExternalPSK(Vector vector);

    byte[] getNewSessionID();

    NewSessionTicket getNewSessionTicket() throws IOException;

    TlsPSKIdentityManager getPSKIdentityManager() throws IOException;

    TlsSRPLoginParameters getSRPLoginParameters() throws IOException;

    int getSelectedCipherSuite() throws IOException;

    Hashtable getServerExtensions() throws IOException;

    void getServerExtensionsForConnection(Hashtable hashtable) throws IOException;

    Vector getServerSupplementalData() throws IOException;

    ProtocolVersion getServerVersion() throws IOException;

    TlsSession getSessionToResume(byte[] bArr);

    int[] getSupportedGroups() throws IOException;

    void init(TlsServerContext tlsServerContext);

    void notifyClientCertificate(Certificate certificate) throws IOException;

    void notifyClientVersion(ProtocolVersion protocolVersion) throws IOException;

    void notifyFallback(boolean z) throws IOException;

    void notifyOfferedCipherSuites(int[] iArr) throws IOException;

    void notifySession(TlsSession tlsSession);

    void processClientExtensions(Hashtable hashtable) throws IOException;

    void processClientSupplementalData(Vector vector) throws IOException;
}