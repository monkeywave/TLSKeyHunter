package org.openjsse.sun.security.ssl;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.crypto.SecretKey;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.CertificateException;
import org.openjsse.javax.net.ssl.ExtendedSSLSession;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSessionImpl.class */
public final class SSLSessionImpl extends ExtendedSSLSession {
    private final ProtocolVersion protocolVersion;
    private final SessionId sessionId;
    private X509Certificate[] peerCerts;
    private CipherSuite cipherSuite;
    private SecretKey masterSecret;
    final boolean useExtendedMasterSecret;
    private final long creationTime;
    private long lastUsedTime;
    private final String host;
    private final int port;
    private SSLSessionContextImpl context;
    private boolean invalidated;
    private X509Certificate[] localCerts;
    private PrivateKey localPrivateKey;
    private final Collection<SignatureScheme> localSupportedSignAlgs;
    private String[] peerSupportedSignAlgs;
    private boolean useDefaultPeerSignAlgs;
    private List<byte[]> statusResponses;
    private SecretKey resumptionMasterSecret;
    private SecretKey preSharedKey;
    private byte[] pskIdentity;
    private final long ticketCreationTime;
    private int ticketAgeAdd;
    private int negotiatedMaxFragLen;
    private int maximumPacketSize;
    private final Queue<SSLSessionImpl> childSessions;
    private boolean isSessionResumption;
    private static boolean defaultRejoinable = true;
    final SNIServerName serverNameIndication;
    private final List<SNIServerName> requestedServerNames;
    private BigInteger ticketNonceCounter;
    private final String identificationProtocol;
    private X500Principal[] certificateAuthorities;
    private final ConcurrentHashMap<SecureKey, Object> boundValues;
    private boolean acceptLargeFragments;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl() {
        this.lastUsedTime = 0L;
        this.useDefaultPeerSignAlgs = false;
        this.ticketCreationTime = System.currentTimeMillis();
        this.negotiatedMaxFragLen = -1;
        this.childSessions = new ConcurrentLinkedQueue();
        this.isSessionResumption = false;
        this.ticketNonceCounter = BigInteger.ONE;
        this.acceptLargeFragments = Utilities.getBooleanProperty("jsse.SSLEngine.acceptLargeFragments", false);
        this.protocolVersion = ProtocolVersion.NONE;
        this.cipherSuite = CipherSuite.C_NULL;
        this.sessionId = new SessionId(false, null);
        this.host = null;
        this.port = -1;
        this.localSupportedSignAlgs = Collections.emptySet();
        this.serverNameIndication = null;
        this.requestedServerNames = Collections.emptyList();
        this.useExtendedMasterSecret = false;
        this.creationTime = System.currentTimeMillis();
        this.identificationProtocol = null;
        this.boundValues = new ConcurrentHashMap<>();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl(HandshakeContext hc, CipherSuite cipherSuite) {
        this(hc, cipherSuite, new SessionId(defaultRejoinable, hc.sslContext.getSecureRandom()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl(HandshakeContext hc, CipherSuite cipherSuite, SessionId id) {
        this(hc, cipherSuite, id, System.currentTimeMillis());
    }

    SSLSessionImpl(HandshakeContext hc, CipherSuite cipherSuite, SessionId id, long creationTime) {
        Collection<SignatureScheme> unmodifiableCollection;
        this.lastUsedTime = 0L;
        this.useDefaultPeerSignAlgs = false;
        this.ticketCreationTime = System.currentTimeMillis();
        this.negotiatedMaxFragLen = -1;
        this.childSessions = new ConcurrentLinkedQueue();
        this.isSessionResumption = false;
        this.ticketNonceCounter = BigInteger.ONE;
        this.acceptLargeFragments = Utilities.getBooleanProperty("jsse.SSLEngine.acceptLargeFragments", false);
        this.protocolVersion = hc.negotiatedProtocol;
        this.cipherSuite = cipherSuite;
        this.sessionId = id;
        this.host = hc.conContext.transport.getPeerHost();
        this.port = hc.conContext.transport.getPeerPort();
        if (hc.localSupportedSignAlgs == null) {
            unmodifiableCollection = Collections.emptySet();
        } else {
            unmodifiableCollection = Collections.unmodifiableCollection(new ArrayList(hc.localSupportedSignAlgs));
        }
        this.localSupportedSignAlgs = unmodifiableCollection;
        this.serverNameIndication = hc.negotiatedServerName;
        this.requestedServerNames = Collections.unmodifiableList(new ArrayList(hc.getRequestedServerNames()));
        if (hc.sslConfig.isClientMode) {
            this.useExtendedMasterSecret = (hc.handshakeExtensions.get(SSLExtension.CH_EXTENDED_MASTER_SECRET) == null || hc.handshakeExtensions.get(SSLExtension.SH_EXTENDED_MASTER_SECRET) == null) ? false : true;
        } else {
            this.useExtendedMasterSecret = (hc.handshakeExtensions.get(SSLExtension.CH_EXTENDED_MASTER_SECRET) == null || hc.negotiatedProtocol.useTLS13PlusSpec()) ? false : true;
        }
        this.creationTime = creationTime;
        this.identificationProtocol = hc.sslConfig.identificationProtocol;
        this.boundValues = new ConcurrentHashMap<>();
        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.finest("Session initialized:  " + this, new Object[0]);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl(SSLSessionImpl baseSession, SessionId newId) {
        this.lastUsedTime = 0L;
        this.useDefaultPeerSignAlgs = false;
        this.ticketCreationTime = System.currentTimeMillis();
        this.negotiatedMaxFragLen = -1;
        this.childSessions = new ConcurrentLinkedQueue();
        this.isSessionResumption = false;
        this.ticketNonceCounter = BigInteger.ONE;
        this.acceptLargeFragments = Utilities.getBooleanProperty("jsse.SSLEngine.acceptLargeFragments", false);
        this.protocolVersion = baseSession.getProtocolVersion();
        this.cipherSuite = baseSession.cipherSuite;
        this.sessionId = newId;
        this.host = baseSession.getPeerHost();
        this.port = baseSession.getPeerPort();
        this.localSupportedSignAlgs = baseSession.localSupportedSignAlgs == null ? Collections.emptySet() : baseSession.localSupportedSignAlgs;
        this.peerSupportedSignAlgs = baseSession.getPeerSupportedSignatureAlgorithms();
        this.serverNameIndication = baseSession.serverNameIndication;
        this.requestedServerNames = baseSession.getRequestedServerNames();
        this.masterSecret = baseSession.getMasterSecret();
        this.useExtendedMasterSecret = baseSession.useExtendedMasterSecret;
        this.creationTime = baseSession.getCreationTime();
        this.lastUsedTime = System.currentTimeMillis();
        this.identificationProtocol = baseSession.getIdentificationProtocol();
        this.localCerts = baseSession.localCerts;
        this.peerCerts = baseSession.peerCerts;
        this.statusResponses = baseSession.statusResponses;
        this.resumptionMasterSecret = baseSession.resumptionMasterSecret;
        this.context = baseSession.context;
        this.negotiatedMaxFragLen = baseSession.negotiatedMaxFragLen;
        this.maximumPacketSize = baseSession.maximumPacketSize;
        this.boundValues = baseSession.boundValues;
        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.finest("Session initialized:  " + this, new Object[0]);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setMasterSecret(SecretKey secret) {
        this.masterSecret = secret;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setResumptionMasterSecret(SecretKey secret) {
        this.resumptionMasterSecret = secret;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPreSharedKey(SecretKey key) {
        this.preSharedKey = key;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addChild(SSLSessionImpl session) {
        this.childSessions.add(session);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setTicketAgeAdd(int ticketAgeAdd) {
        this.ticketAgeAdd = ticketAgeAdd;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPskIdentity(byte[] pskIdentity) {
        this.pskIdentity = pskIdentity;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BigInteger incrTicketNonceCounter() {
        BigInteger result = this.ticketNonceCounter;
        this.ticketNonceCounter = this.ticketNonceCounter.add(BigInteger.valueOf(1L));
        return result;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecretKey getMasterSecret() {
        return this.masterSecret;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecretKey getResumptionMasterSecret() {
        return this.resumptionMasterSecret;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized SecretKey getPreSharedKey() {
        return this.preSharedKey;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized SecretKey consumePreSharedKey() {
        try {
            return this.preSharedKey;
        } finally {
            this.preSharedKey = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getTicketAgeAdd() {
        return this.ticketAgeAdd;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getIdentificationProtocol() {
        return this.identificationProtocol;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized byte[] consumePskIdentity() {
        try {
            return this.pskIdentity;
        } finally {
            this.pskIdentity = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPeerCertificates(X509Certificate[] peer) {
        if (this.peerCerts == null) {
            this.peerCerts = peer;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setLocalCertificates(X509Certificate[] local) {
        this.localCerts = local;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setLocalPrivateKey(PrivateKey privateKey) {
        this.localPrivateKey = privateKey;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPeerSupportedSignatureAlgorithms(Collection<SignatureScheme> signatureSchemes) {
        this.peerSupportedSignAlgs = SignatureScheme.getAlgorithmNames(signatureSchemes);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setUseDefaultPeerSignAlgs() {
        this.useDefaultPeerSignAlgs = true;
        this.peerSupportedSignAlgs = new String[]{"SHA1withRSA", "SHA1withDSA", "SHA1withECDSA"};
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSessionImpl finish() {
        if (this.useDefaultPeerSignAlgs) {
            this.peerSupportedSignAlgs = new String[0];
        }
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setStatusResponses(List<byte[]> responses) {
        if (responses != null && !responses.isEmpty()) {
            this.statusResponses = responses;
        } else {
            this.statusResponses = Collections.emptyList();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isRejoinable() {
        return (this.sessionId == null || this.sessionId.length() == 0 || this.invalidated || !isLocalAuthenticationValid()) ? false : true;
    }

    @Override // javax.net.ssl.SSLSession
    public synchronized boolean isValid() {
        return isRejoinable();
    }

    private boolean isLocalAuthenticationValid() {
        if (this.localPrivateKey != null) {
            try {
                this.localPrivateKey.getAlgorithm();
                return true;
            } catch (Exception e) {
                invalidate();
                return false;
            }
        }
        return true;
    }

    @Override // javax.net.ssl.SSLSession
    public byte[] getId() {
        return this.sessionId.getId();
    }

    @Override // javax.net.ssl.SSLSession
    public SSLSessionContext getSessionContext() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }
        return this.context;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SessionId getSessionId() {
        return this.sessionId;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CipherSuite getSuite() {
        return this.cipherSuite;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSuite(CipherSuite suite) {
        this.cipherSuite = suite;
        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.finest("Negotiating session:  " + this, new Object[0]);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isSessionResumption() {
        return this.isSessionResumption;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAsSessionResumption(boolean flag) {
        this.isSessionResumption = flag;
    }

    @Override // javax.net.ssl.SSLSession
    public String getCipherSuite() {
        return getSuite().name;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProtocolVersion getProtocolVersion() {
        return this.protocolVersion;
    }

    @Override // javax.net.ssl.SSLSession
    public String getProtocol() {
        return getProtocolVersion().name;
    }

    public int hashCode() {
        return this.sessionId.hashCode();
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SSLSessionImpl) {
            SSLSessionImpl sess = (SSLSessionImpl) obj;
            return this.sessionId != null && this.sessionId.equals(sess.getSessionId());
        }
        return false;
    }

    void setCertificateAuthorities(X500Principal[] certificateAuthorities) {
        this.certificateAuthorities = certificateAuthorities;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X500Principal[] getCertificateAuthorities() {
        return this.certificateAuthorities;
    }

    @Override // javax.net.ssl.SSLSession
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        if (this.peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }
        return (Certificate[]) this.peerCerts.clone();
    }

    @Override // javax.net.ssl.SSLSession
    public Certificate[] getLocalCertificates() {
        if (this.localCerts == null) {
            return null;
        }
        return (Certificate[]) this.localCerts.clone();
    }

    @Override // javax.net.ssl.SSLSession
    @Deprecated
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        if (this.peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }
        javax.security.cert.X509Certificate[] certs = new javax.security.cert.X509Certificate[this.peerCerts.length];
        for (int i = 0; i < this.peerCerts.length; i++) {
            try {
                byte[] der = this.peerCerts[i].getEncoded();
                certs[i] = javax.security.cert.X509Certificate.getInstance(der);
            } catch (CertificateEncodingException e) {
                throw new SSLPeerUnverifiedException(e.getMessage());
            } catch (CertificateException e2) {
                throw new SSLPeerUnverifiedException(e2.getMessage());
            }
        }
        return certs;
    }

    public X509Certificate[] getCertificateChain() throws SSLPeerUnverifiedException {
        if (this.peerCerts != null) {
            return (X509Certificate[]) this.peerCerts.clone();
        }
        throw new SSLPeerUnverifiedException("peer not authenticated");
    }

    @Override // org.openjsse.javax.net.ssl.ExtendedSSLSession
    public List<byte[]> getStatusResponses() {
        if (this.statusResponses == null || this.statusResponses.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList(this.statusResponses.size());
        for (byte[] respBytes : this.statusResponses) {
            arrayList.add(respBytes.clone());
        }
        return Collections.unmodifiableList(arrayList);
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (this.peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }
        return this.peerCerts[0].getSubjectX500Principal();
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getLocalPrincipal() {
        if (this.localCerts == null || this.localCerts.length == 0) {
            return null;
        }
        return this.localCerts[0].getSubjectX500Principal();
    }

    public long getTicketCreationTime() {
        return this.ticketCreationTime;
    }

    @Override // javax.net.ssl.SSLSession
    public long getCreationTime() {
        return this.creationTime;
    }

    @Override // javax.net.ssl.SSLSession
    public long getLastAccessedTime() {
        return this.lastUsedTime != 0 ? this.lastUsedTime : this.creationTime;
    }

    void setLastAccessedTime(long time) {
        this.lastUsedTime = time;
    }

    public InetAddress getPeerAddress() {
        try {
            return InetAddress.getByName(this.host);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    @Override // javax.net.ssl.SSLSession
    public String getPeerHost() {
        return this.host;
    }

    @Override // javax.net.ssl.SSLSession
    public int getPeerPort() {
        return this.port;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setContext(SSLSessionContextImpl ctx) {
        if (this.context == null) {
            this.context = ctx;
        }
    }

    @Override // javax.net.ssl.SSLSession
    public synchronized void invalidate() {
        if (this.context != null) {
            this.context.remove(this.sessionId);
            this.context = null;
        }
        if (this.invalidated) {
            return;
        }
        this.invalidated = true;
        if (SSLLogger.isOn && SSLLogger.isOn("session")) {
            SSLLogger.finest("Invalidated session:  " + this, new Object[0]);
        }
        for (SSLSessionImpl child : this.childSessions) {
            child.invalidate();
        }
    }

    @Override // javax.net.ssl.SSLSession
    public void putValue(String key, Object value) {
        if (key == null || value == null) {
            throw new IllegalArgumentException("arguments can not be null");
        }
        SecureKey secureKey = new SecureKey(key);
        Object oldValue = this.boundValues.put(secureKey, value);
        if (oldValue instanceof SSLSessionBindingListener) {
            SSLSessionBindingEvent e = new SSLSessionBindingEvent(this, key);
            ((SSLSessionBindingListener) oldValue).valueUnbound(e);
        }
        if (value instanceof SSLSessionBindingListener) {
            SSLSessionBindingEvent e2 = new SSLSessionBindingEvent(this, key);
            ((SSLSessionBindingListener) value).valueBound(e2);
        }
    }

    @Override // javax.net.ssl.SSLSession
    public Object getValue(String key) {
        if (key == null) {
            throw new IllegalArgumentException("argument can not be null");
        }
        SecureKey secureKey = new SecureKey(key);
        return this.boundValues.get(secureKey);
    }

    @Override // javax.net.ssl.SSLSession
    public void removeValue(String key) {
        if (key == null) {
            throw new IllegalArgumentException("argument can not be null");
        }
        SecureKey secureKey = new SecureKey(key);
        Object value = this.boundValues.remove(secureKey);
        if (value instanceof SSLSessionBindingListener) {
            SSLSessionBindingEvent e = new SSLSessionBindingEvent(this, key);
            ((SSLSessionBindingListener) value).valueUnbound(e);
        }
    }

    @Override // javax.net.ssl.SSLSession
    public String[] getValueNames() {
        ArrayList<Object> v = new ArrayList<>();
        Object securityCtx = SecureKey.getCurrentSecurityContext();
        Enumeration<SecureKey> e = this.boundValues.keys();
        while (e.hasMoreElements()) {
            SecureKey key = e.nextElement();
            if (securityCtx.equals(key.getSecurityContext())) {
                v.add(key.getAppKey());
            }
        }
        return (String[]) v.toArray(new String[0]);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public synchronized void expandBufferSizes() {
        this.acceptLargeFragments = true;
    }

    @Override // javax.net.ssl.SSLSession
    public synchronized int getPacketBufferSize() {
        int packetSize = 0;
        if (this.negotiatedMaxFragLen > 0) {
            packetSize = this.cipherSuite.calculatePacketSize(this.negotiatedMaxFragLen, this.protocolVersion, this.protocolVersion.isDTLS);
        }
        if (this.maximumPacketSize > 0) {
            return this.maximumPacketSize > packetSize ? this.maximumPacketSize : packetSize;
        } else if (packetSize != 0) {
            return packetSize;
        } else {
            if (this.protocolVersion.isDTLS) {
                return DTLSRecord.maxRecordSize;
            }
            return this.acceptLargeFragments ? SSLRecord.maxLargeRecordSize : SSLRecord.maxRecordSize;
        }
    }

    @Override // javax.net.ssl.SSLSession
    public synchronized int getApplicationBufferSize() {
        int fragmentSize = 0;
        if (this.maximumPacketSize > 0) {
            fragmentSize = this.cipherSuite.calculateFragSize(this.maximumPacketSize, this.protocolVersion, this.protocolVersion.isDTLS);
        }
        if (this.negotiatedMaxFragLen > 0) {
            return this.negotiatedMaxFragLen > fragmentSize ? this.negotiatedMaxFragLen : fragmentSize;
        } else if (fragmentSize != 0) {
            return fragmentSize;
        } else {
            if (this.protocolVersion.isDTLS) {
                return 16384;
            }
            int maxPacketSize = this.acceptLargeFragments ? SSLRecord.maxLargeRecordSize : SSLRecord.maxRecordSize;
            return maxPacketSize - 5;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void setNegotiatedMaxFragSize(int negotiatedMaxFragLen) {
        this.negotiatedMaxFragLen = negotiatedMaxFragLen;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized int getNegotiatedMaxFragSize() {
        return this.negotiatedMaxFragLen;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void setMaximumPacketSize(int maximumPacketSize) {
        this.maximumPacketSize = maximumPacketSize;
    }

    synchronized int getMaximumPacketSize() {
        return this.maximumPacketSize;
    }

    @Override // javax.net.ssl.ExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithms() {
        return SignatureScheme.getAlgorithmNames(this.localSupportedSignAlgs);
    }

    public Collection<SignatureScheme> getLocalSupportedSignatureSchemes() {
        return this.localSupportedSignAlgs;
    }

    @Override // javax.net.ssl.ExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithms() {
        if (this.peerSupportedSignAlgs != null) {
            return (String[]) this.peerSupportedSignAlgs.clone();
        }
        return new String[0];
    }

    @Override // javax.net.ssl.ExtendedSSLSession
    public List<SNIServerName> getRequestedServerNames() {
        return this.requestedServerNames;
    }

    public String toString() {
        return "Session(" + this.creationTime + "|" + getCipherSuite() + ")";
    }
}