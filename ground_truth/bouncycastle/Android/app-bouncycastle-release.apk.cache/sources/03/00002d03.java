package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Integers;

/* loaded from: classes2.dex */
public abstract class AbstractTlsServer extends AbstractTlsPeer implements TlsServer {
    protected CertificateStatusRequest certificateStatusRequest;
    protected int[] cipherSuites;
    protected Hashtable clientExtensions;
    protected Vector clientProtocolNames;
    protected boolean clientSentECPointFormats;
    protected TlsServerContext context;
    protected boolean encryptThenMACOffered;
    protected short maxFragmentLengthOffered;
    protected int[] offeredCipherSuites;
    protected ProtocolVersion[] protocolVersions;
    protected int selectedCipherSuite;
    protected ProtocolName selectedProtocolName;
    protected final Hashtable serverExtensions;
    protected Vector statusRequestV2;
    protected boolean truncatedHMacOffered;
    protected Vector trustedCAKeys;

    public AbstractTlsServer(TlsCrypto tlsCrypto) {
        super(tlsCrypto);
        this.serverExtensions = new Hashtable();
    }

    protected boolean allowCertificateStatus() {
        return true;
    }

    protected boolean allowEncryptThenMAC() {
        return true;
    }

    protected boolean allowMultiCertStatus() {
        return false;
    }

    protected boolean allowTruncatedHMac() {
        return false;
    }

    protected boolean allowTrustedCAIndication() {
        return false;
    }

    protected Hashtable checkServerExtensions() {
        return this.serverExtensions;
    }

    protected short[] getAllowedClientCertificateTypes() {
        return null;
    }

    public CertificateRequest getCertificateRequest() throws IOException {
        return null;
    }

    public CertificateStatus getCertificateStatus() throws IOException {
        return null;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public int[] getCipherSuites() {
        return this.cipherSuites;
    }

    public TlsDHConfig getDHConfig() throws IOException {
        return TlsDHUtils.createNamedDHConfig(this.context, selectDH(TlsDHUtils.getMinimumFiniteFieldBits(this.selectedCipherSuite)));
    }

    protected String getDetailMessageNoCipherSuite() {
        return "No selectable cipher suite";
    }

    @Override // org.bouncycastle.tls.TlsServer
    public TlsECConfig getECDHConfig() throws IOException {
        return TlsECCUtils.createNamedECConfig(this.context, selectECDH(TlsECCUtils.getMinimumCurveBits(this.selectedCipherSuite)));
    }

    @Override // org.bouncycastle.tls.TlsServer
    public TlsPSKExternal getExternalPSK(Vector vector) {
        return null;
    }

    protected int getMaximumDefaultCurveBits() {
        return NamedGroup.getCurveBits(25);
    }

    protected int getMaximumDefaultFiniteFieldBits() {
        return NamedGroup.getFiniteFieldBits(NamedGroup.ffdhe8192);
    }

    protected int getMaximumNegotiableCurveBits() {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups != null) {
            int i = 0;
            for (int i2 : clientSupportedGroups) {
                i = Math.max(i, NamedGroup.getCurveBits(i2));
            }
            return i;
        }
        return getMaximumDefaultCurveBits();
    }

    protected int getMaximumNegotiableFiniteFieldBits() {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        int i = 0;
        int i2 = 0;
        if (clientSupportedGroups != null) {
            int i3 = 0;
            while (i < clientSupportedGroups.length) {
                i3 |= NamedGroup.isFiniteField(clientSupportedGroups[i]) ? 1 : 0;
                i2 = Math.max(i2, NamedGroup.getFiniteFieldBits(clientSupportedGroups[i]));
                i++;
            }
            i = i3;
        }
        return i == 0 ? getMaximumDefaultFiniteFieldBits() : i2;
    }

    protected byte[] getNewConnectionID() {
        return null;
    }

    public byte[] getNewSessionID() {
        return null;
    }

    @Override // org.bouncycastle.tls.TlsServer
    public NewSessionTicket getNewSessionTicket() throws IOException {
        return new NewSessionTicket(0L, TlsUtils.EMPTY_BYTES);
    }

    @Override // org.bouncycastle.tls.TlsServer
    public TlsPSKIdentityManager getPSKIdentityManager() throws IOException {
        return null;
    }

    protected Vector getProtocolNames() {
        return null;
    }

    @Override // org.bouncycastle.tls.TlsPeer
    public ProtocolVersion[] getProtocolVersions() {
        return this.protocolVersions;
    }

    @Override // org.bouncycastle.tls.TlsServer
    public TlsSRPLoginParameters getSRPLoginParameters() throws IOException {
        return null;
    }

    public int getSelectedCipherSuite() throws IOException {
        int[] commonCipherSuites;
        SecurityParameters securityParametersHandshake = this.context.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
        if (TlsUtils.isTLSv13(negotiatedVersion)) {
            int commonCipherSuite13 = TlsUtils.getCommonCipherSuite13(negotiatedVersion, this.offeredCipherSuites, getCipherSuites(), preferLocalCipherSuites());
            if (commonCipherSuite13 >= 0 && selectCipherSuite(commonCipherSuite13)) {
                return commonCipherSuite13;
            }
        } else {
            Vector usableSignatureAlgorithms = TlsUtils.getUsableSignatureAlgorithms(securityParametersHandshake.getClientSigAlgs());
            int maximumNegotiableCurveBits = getMaximumNegotiableCurveBits();
            int maximumNegotiableFiniteFieldBits = getMaximumNegotiableFiniteFieldBits();
            for (int i : TlsUtils.getCommonCipherSuites(this.offeredCipherSuites, getCipherSuites(), preferLocalCipherSuites())) {
                if (isSelectableCipherSuite(i, maximumNegotiableCurveBits, maximumNegotiableFiniteFieldBits, usableSignatureAlgorithms) && selectCipherSuite(i)) {
                    return i;
                }
            }
        }
        throw new TlsFatalAlert((short) 40, getDetailMessageNoCipherSuite());
    }

    public Hashtable getServerExtensions() throws IOException {
        Hashtable hashtable;
        Integer num;
        short[] allowedClientCertificateTypes;
        short s;
        TlsCredentials credentials;
        boolean isTLSv13 = TlsUtils.isTLSv13(this.context);
        if (!isTLSv13) {
            if (this.encryptThenMACOffered && allowEncryptThenMAC() && TlsUtils.isBlockCipherSuite(this.selectedCipherSuite)) {
                TlsExtensionsUtils.addEncryptThenMACExtension(this.serverExtensions);
            }
            if (this.truncatedHMacOffered && allowTruncatedHMac()) {
                TlsExtensionsUtils.addTruncatedHMacExtension(this.serverExtensions);
            }
            if (this.clientSentECPointFormats && TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite)) {
                TlsExtensionsUtils.addSupportedPointFormatsExtension(this.serverExtensions, new short[]{0});
            }
            if (this.statusRequestV2 == null || !allowMultiCertStatus()) {
                if (this.certificateStatusRequest != null && allowCertificateStatus()) {
                    hashtable = this.serverExtensions;
                    num = TlsExtensionsUtils.EXT_status_request;
                }
                if (this.trustedCAKeys != null && allowTrustedCAIndication()) {
                    TlsExtensionsUtils.addTrustedCAKeysExtensionServer(this.serverExtensions);
                }
            } else {
                hashtable = this.serverExtensions;
                num = TlsExtensionsUtils.EXT_status_request_v2;
            }
            TlsExtensionsUtils.addEmptyExtensionData(hashtable, num);
            if (this.trustedCAKeys != null) {
                TlsExtensionsUtils.addTrustedCAKeysExtensionServer(this.serverExtensions);
            }
        } else if (this.certificateStatusRequest != null) {
            allowCertificateStatus();
        }
        short s2 = this.maxFragmentLengthOffered;
        if (s2 >= 0 && MaxFragmentLength.isValid(s2)) {
            TlsExtensionsUtils.addMaxFragmentLengthExtension(this.serverExtensions, this.maxFragmentLengthOffered);
        }
        short[] serverCertificateTypeExtensionClient = TlsExtensionsUtils.getServerCertificateTypeExtensionClient(this.clientExtensions);
        if (serverCertificateTypeExtensionClient != null && (credentials = getCredentials()) != null) {
            short certificateType = credentials.getCertificate().getCertificateType();
            if (1 == certificateType && isTLSv13) {
                throw new TlsFatalAlert((short) 80, "The OpenPGP certificate type MUST NOT be used with TLS 1.3");
            }
            if (!TlsUtils.contains(serverCertificateTypeExtensionClient, 0, serverCertificateTypeExtensionClient.length, certificateType)) {
                throw new TlsFatalAlert((short) 43);
            }
            TlsExtensionsUtils.addServerCertificateTypeExtensionServer(this.serverExtensions, certificateType);
        }
        short[] clientCertificateTypeExtensionClient = TlsExtensionsUtils.getClientCertificateTypeExtensionClient(this.clientExtensions);
        if (clientCertificateTypeExtensionClient != null && (allowedClientCertificateTypes = getAllowedClientCertificateTypes()) != null) {
            if (preferLocalClientCertificateTypes()) {
                allowedClientCertificateTypes = clientCertificateTypeExtensionClient;
                clientCertificateTypeExtensionClient = allowedClientCertificateTypes;
            }
            int i = 0;
            while (true) {
                if (i >= clientCertificateTypeExtensionClient.length) {
                    s = -1;
                    break;
                }
                s = clientCertificateTypeExtensionClient[i];
                if (!(1 == s && isTLSv13) && TlsUtils.contains(allowedClientCertificateTypes, 0, allowedClientCertificateTypes.length, s)) {
                    break;
                }
                i++;
            }
            if (s == -1) {
                throw new TlsFatalAlert((short) 43);
            }
            TlsExtensionsUtils.addClientCertificateTypeExtensionServer(this.serverExtensions, s);
        }
        return this.serverExtensions;
    }

    @Override // org.bouncycastle.tls.TlsServer
    public void getServerExtensionsForConnection(Hashtable hashtable) throws IOException {
        Hashtable hashtable2;
        byte[] newConnectionID;
        Vector vector;
        if (!shouldSelectProtocolNameEarly() && (vector = this.clientProtocolNames) != null && !vector.isEmpty()) {
            this.selectedProtocolName = selectProtocolName();
        }
        ProtocolName protocolName = this.selectedProtocolName;
        if (protocolName == null) {
            hashtable.remove(TlsExtensionsUtils.EXT_application_layer_protocol_negotiation);
        } else {
            TlsExtensionsUtils.addALPNExtensionServer(hashtable, protocolName);
        }
        if (!ProtocolVersion.DTLSv12.equals(this.context.getServerVersion()) || (hashtable2 = this.clientExtensions) == null || !hashtable2.containsKey(Integers.valueOf(54)) || (newConnectionID = getNewConnectionID()) == null) {
            return;
        }
        TlsExtensionsUtils.addConnectionIDExtension(hashtable, newConnectionID);
    }

    @Override // org.bouncycastle.tls.TlsServer
    public Vector getServerSupplementalData() throws IOException {
        return null;
    }

    public ProtocolVersion getServerVersion() throws IOException {
        ProtocolVersion[] clientSupportedVersions;
        ProtocolVersion[] protocolVersions = getProtocolVersions();
        for (ProtocolVersion protocolVersion : this.context.getClientSupportedVersions()) {
            if (ProtocolVersion.contains(protocolVersions, protocolVersion)) {
                return protocolVersion;
            }
        }
        throw new TlsFatalAlert((short) 70);
    }

    public TlsSession getSessionToResume(byte[] bArr) {
        return null;
    }

    public int[] getSupportedGroups() throws IOException {
        return new int[]{29, 30, 23, 24, 256, 257, NamedGroup.ffdhe4096};
    }

    @Override // org.bouncycastle.tls.TlsServer
    public void init(TlsServerContext tlsServerContext) {
        this.context = tlsServerContext;
        this.protocolVersions = getSupportedVersions();
        this.cipherSuites = getSupportedCipherSuites();
    }

    protected boolean isSelectableCipherSuite(int i, int i2, int i3, Vector vector) {
        return TlsUtils.isValidVersionForCipherSuite(i, this.context.getServerVersion()) && i2 >= TlsECCUtils.getMinimumCurveBits(i) && i3 >= TlsDHUtils.getMinimumFiniteFieldBits(i) && TlsUtils.isValidCipherSuiteForSignatureAlgorithms(i, vector);
    }

    public void notifyClientCertificate(Certificate certificate) throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.TlsServer
    public void notifyClientVersion(ProtocolVersion protocolVersion) throws IOException {
    }

    @Override // org.bouncycastle.tls.TlsServer
    public void notifyFallback(boolean z) throws IOException {
        ProtocolVersion latestDTLS;
        if (z) {
            ProtocolVersion[] protocolVersions = getProtocolVersions();
            ProtocolVersion clientVersion = this.context.getClientVersion();
            if (clientVersion.isTLS()) {
                latestDTLS = ProtocolVersion.getLatestTLS(protocolVersions);
            } else if (!clientVersion.isDTLS()) {
                throw new TlsFatalAlert((short) 80);
            } else {
                latestDTLS = ProtocolVersion.getLatestDTLS(protocolVersions);
            }
            if (latestDTLS != null && latestDTLS.isLaterVersionOf(clientVersion)) {
                throw new TlsFatalAlert((short) 86);
            }
        }
    }

    @Override // org.bouncycastle.tls.AbstractTlsPeer, org.bouncycastle.tls.TlsPeer
    public void notifyHandshakeBeginning() throws IOException {
        super.notifyHandshakeBeginning();
        this.offeredCipherSuites = null;
        this.clientExtensions = null;
        this.encryptThenMACOffered = false;
        this.maxFragmentLengthOffered = (short) 0;
        this.truncatedHMacOffered = false;
        this.clientSentECPointFormats = false;
        this.certificateStatusRequest = null;
        this.selectedCipherSuite = -1;
        this.selectedProtocolName = null;
        this.serverExtensions.clear();
    }

    @Override // org.bouncycastle.tls.TlsServer
    public void notifyOfferedCipherSuites(int[] iArr) throws IOException {
        this.offeredCipherSuites = iArr;
    }

    public void notifySession(TlsSession tlsSession) {
    }

    protected boolean preferLocalCipherSuites() {
        return false;
    }

    protected boolean preferLocalClientCertificateTypes() {
        return false;
    }

    public void processClientExtensions(Hashtable hashtable) throws IOException {
        Vector vector;
        this.clientExtensions = hashtable;
        if (hashtable != null) {
            this.clientProtocolNames = TlsExtensionsUtils.getALPNExtensionClient(hashtable);
            if (shouldSelectProtocolNameEarly() && (vector = this.clientProtocolNames) != null && !vector.isEmpty()) {
                this.selectedProtocolName = selectProtocolName();
            }
            this.encryptThenMACOffered = TlsExtensionsUtils.hasEncryptThenMACExtension(hashtable);
            this.truncatedHMacOffered = TlsExtensionsUtils.hasTruncatedHMacExtension(hashtable);
            this.statusRequestV2 = TlsExtensionsUtils.getStatusRequestV2Extension(hashtable);
            this.trustedCAKeys = TlsExtensionsUtils.getTrustedCAKeysExtensionClient(hashtable);
            this.clientSentECPointFormats = TlsExtensionsUtils.getSupportedPointFormatsExtension(hashtable) != null;
            this.certificateStatusRequest = TlsExtensionsUtils.getStatusRequestExtension(hashtable);
            short maxFragmentLengthExtension = TlsExtensionsUtils.getMaxFragmentLengthExtension(hashtable);
            this.maxFragmentLengthOffered = maxFragmentLengthExtension;
            if (maxFragmentLengthExtension >= 0 && !MaxFragmentLength.isValid(maxFragmentLengthExtension)) {
                throw new TlsFatalAlert((short) 47);
            }
        }
    }

    @Override // org.bouncycastle.tls.TlsServer
    public void processClientSupplementalData(Vector vector) throws IOException {
        if (vector != null) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean selectCipherSuite(int i) throws IOException {
        this.selectedCipherSuite = i;
        return true;
    }

    protected int selectDH(int i) {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        int i2 = 0;
        if (clientSupportedGroups != null) {
            int i3 = 0;
            while (i2 < clientSupportedGroups.length) {
                int i4 = clientSupportedGroups[i2];
                i3 |= NamedGroup.isFiniteField(i4) ? 1 : 0;
                if (NamedGroup.getFiniteFieldBits(i4) >= i) {
                    return i4;
                }
                i2++;
            }
            i2 = i3;
        }
        if (i2 == 0) {
            return selectDHDefault(i);
        }
        return -1;
    }

    protected int selectDHDefault(int i) {
        if (i <= 2048) {
            return 256;
        }
        if (i <= 3072) {
            return 257;
        }
        if (i <= 4096) {
            return NamedGroup.ffdhe4096;
        }
        if (i <= 6144) {
            return NamedGroup.ffdhe6144;
        }
        if (i <= 8192) {
            return NamedGroup.ffdhe8192;
        }
        return -1;
    }

    protected int selectECDH(int i) {
        int[] clientSupportedGroups = this.context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null) {
            return selectECDHDefault(i);
        }
        for (int i2 : clientSupportedGroups) {
            if (NamedGroup.getCurveBits(i2) >= i) {
                return i2;
            }
        }
        return -1;
    }

    protected int selectECDHDefault(int i) {
        if (i <= 256) {
            return 23;
        }
        if (i <= 384) {
            return 24;
        }
        return i <= 521 ? 25 : -1;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ProtocolName selectProtocolName() throws IOException {
        Vector protocolNames = getProtocolNames();
        if (protocolNames == null || protocolNames.isEmpty()) {
            return null;
        }
        ProtocolName selectProtocolName = selectProtocolName(this.clientProtocolNames, protocolNames);
        if (selectProtocolName != null) {
            return selectProtocolName;
        }
        throw new TlsFatalAlert(AlertDescription.no_application_protocol);
    }

    protected ProtocolName selectProtocolName(Vector vector, Vector vector2) {
        for (int i = 0; i < vector2.size(); i++) {
            ProtocolName protocolName = (ProtocolName) vector2.elementAt(i);
            if (vector.contains(protocolName)) {
                return protocolName;
            }
        }
        return null;
    }

    protected boolean shouldSelectProtocolNameEarly() {
        return true;
    }
}