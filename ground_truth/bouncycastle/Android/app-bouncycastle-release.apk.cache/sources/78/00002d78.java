package org.bouncycastle.tls;

import java.util.Vector;
import org.bouncycastle.tls.crypto.TlsSecret;

/* loaded from: classes2.dex */
public class SecurityParameters {
    byte[] connectionIDLocal;
    byte[] connectionIDPeer;
    int entity = -1;
    boolean resumedSession = false;
    boolean renegotiating = false;
    boolean secureRenegotiation = false;
    int cipherSuite = 0;
    short maxFragmentLength = -1;
    int prfAlgorithm = -1;
    int prfCryptoHashAlgorithm = -1;
    int prfHashLength = -1;
    int verifyDataLength = -1;
    TlsSecret baseKeyClient = null;
    TlsSecret baseKeyServer = null;
    TlsSecret earlyExporterMasterSecret = null;
    TlsSecret earlySecret = null;
    TlsSecret exporterMasterSecret = null;
    TlsSecret handshakeSecret = null;
    TlsSecret masterSecret = null;
    TlsSecret trafficSecretClient = null;
    TlsSecret trafficSecretServer = null;
    byte[] clientRandom = null;
    byte[] serverRandom = null;
    byte[] sessionHash = null;
    byte[] sessionID = null;
    byte[] pskIdentity = null;
    byte[] srpIdentity = null;
    byte[] tlsServerEndPoint = null;
    byte[] tlsUnique = null;
    boolean encryptThenMAC = false;
    boolean extendedMasterSecret = false;
    boolean extendedPadding = false;
    boolean truncatedHMac = false;
    ProtocolName applicationProtocol = null;
    boolean applicationProtocolSet = false;
    short[] clientCertTypes = null;
    Vector clientServerNames = null;
    Vector clientSigAlgs = null;
    Vector clientSigAlgsCert = null;
    int[] clientSupportedGroups = null;
    Vector serverSigAlgs = null;
    Vector serverSigAlgsCert = null;
    int[] serverSupportedGroups = null;
    int keyExchangeAlgorithm = -1;
    Certificate localCertificate = null;
    Certificate peerCertificate = null;
    ProtocolVersion negotiatedVersion = null;
    int statusRequestVersion = 0;
    short clientCertificateType = 0;
    short serverCertificateType = 0;
    byte[] localVerifyData = null;
    byte[] peerVerifyData = null;

    private static TlsSecret clearSecret(TlsSecret tlsSecret) {
        if (tlsSecret != null) {
            tlsSecret.destroy();
            return null;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void clear() {
        this.sessionHash = null;
        this.sessionID = null;
        this.clientCertTypes = null;
        this.clientServerNames = null;
        this.clientSigAlgs = null;
        this.clientSigAlgsCert = null;
        this.clientSupportedGroups = null;
        this.serverSigAlgs = null;
        this.serverSigAlgsCert = null;
        this.serverSupportedGroups = null;
        this.statusRequestVersion = 0;
        this.baseKeyClient = clearSecret(this.baseKeyClient);
        this.baseKeyServer = clearSecret(this.baseKeyServer);
        this.earlyExporterMasterSecret = clearSecret(this.earlyExporterMasterSecret);
        this.earlySecret = clearSecret(this.earlySecret);
        this.exporterMasterSecret = clearSecret(this.exporterMasterSecret);
        this.handshakeSecret = clearSecret(this.handshakeSecret);
        this.masterSecret = clearSecret(this.masterSecret);
    }

    public ProtocolName getApplicationProtocol() {
        return this.applicationProtocol;
    }

    public TlsSecret getBaseKeyClient() {
        return this.baseKeyClient;
    }

    public TlsSecret getBaseKeyServer() {
        return this.baseKeyServer;
    }

    public int getCipherSuite() {
        return this.cipherSuite;
    }

    public short[] getClientCertTypes() {
        return this.clientCertTypes;
    }

    public short getClientCertificateType() {
        return this.clientCertificateType;
    }

    public byte[] getClientRandom() {
        return this.clientRandom;
    }

    public Vector getClientServerNames() {
        return this.clientServerNames;
    }

    public Vector getClientSigAlgs() {
        return this.clientSigAlgs;
    }

    public Vector getClientSigAlgsCert() {
        return this.clientSigAlgsCert;
    }

    public int[] getClientSupportedGroups() {
        return this.clientSupportedGroups;
    }

    public short getCompressionAlgorithm() {
        return (short) 0;
    }

    public byte[] getConnectionIDLocal() {
        return this.connectionIDLocal;
    }

    public byte[] getConnectionIDPeer() {
        return this.connectionIDPeer;
    }

    public TlsSecret getEarlyExporterMasterSecret() {
        return this.earlyExporterMasterSecret;
    }

    public TlsSecret getEarlySecret() {
        return this.earlySecret;
    }

    public int getEntity() {
        return this.entity;
    }

    public TlsSecret getExporterMasterSecret() {
        return this.exporterMasterSecret;
    }

    public TlsSecret getHandshakeSecret() {
        return this.handshakeSecret;
    }

    public int getKeyExchangeAlgorithm() {
        return this.keyExchangeAlgorithm;
    }

    public Certificate getLocalCertificate() {
        return this.localCertificate;
    }

    public byte[] getLocalVerifyData() {
        return this.localVerifyData;
    }

    public TlsSecret getMasterSecret() {
        return this.masterSecret;
    }

    public short getMaxFragmentLength() {
        return this.maxFragmentLength;
    }

    public ProtocolVersion getNegotiatedVersion() {
        return this.negotiatedVersion;
    }

    public int getPRFAlgorithm() {
        return this.prfAlgorithm;
    }

    public int getPRFCryptoHashAlgorithm() {
        return this.prfCryptoHashAlgorithm;
    }

    public int getPRFHashLength() {
        return this.prfHashLength;
    }

    public byte[] getPSKIdentity() {
        return this.pskIdentity;
    }

    public Certificate getPeerCertificate() {
        return this.peerCertificate;
    }

    public byte[] getPeerVerifyData() {
        return this.peerVerifyData;
    }

    public int getPrfAlgorithm() {
        return this.prfAlgorithm;
    }

    public byte[] getSRPIdentity() {
        return this.srpIdentity;
    }

    public short getServerCertificateType() {
        return this.serverCertificateType;
    }

    public byte[] getServerRandom() {
        return this.serverRandom;
    }

    public Vector getServerSigAlgs() {
        return this.serverSigAlgs;
    }

    public Vector getServerSigAlgsCert() {
        return this.serverSigAlgsCert;
    }

    public int[] getServerSupportedGroups() {
        return this.serverSupportedGroups;
    }

    public byte[] getSessionHash() {
        return this.sessionHash;
    }

    public byte[] getSessionID() {
        return this.sessionID;
    }

    public int getStatusRequestVersion() {
        return this.statusRequestVersion;
    }

    public byte[] getTLSServerEndPoint() {
        return this.tlsServerEndPoint;
    }

    public byte[] getTLSUnique() {
        return this.tlsUnique;
    }

    public TlsSecret getTrafficSecretClient() {
        return this.trafficSecretClient;
    }

    public TlsSecret getTrafficSecretServer() {
        return this.trafficSecretServer;
    }

    public int getVerifyDataLength() {
        return this.verifyDataLength;
    }

    public boolean isApplicationProtocolSet() {
        return this.applicationProtocolSet;
    }

    public boolean isEncryptThenMAC() {
        return this.encryptThenMAC;
    }

    public boolean isExtendedMasterSecret() {
        return this.extendedMasterSecret;
    }

    public boolean isExtendedPadding() {
        return this.extendedPadding;
    }

    public boolean isRenegotiating() {
        return this.renegotiating;
    }

    public boolean isResumedSession() {
        return this.resumedSession;
    }

    public boolean isSecureRenegotiation() {
        return this.secureRenegotiation;
    }

    public boolean isTruncatedHMac() {
        return this.truncatedHMac;
    }
}