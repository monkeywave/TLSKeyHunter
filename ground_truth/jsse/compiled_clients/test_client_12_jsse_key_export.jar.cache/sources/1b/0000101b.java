package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedVersionsExtension;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello.class */
public final class ClientHello {
    static final SSLProducer kickstartProducer = new ClientHelloKickstartProducer();
    static final SSLConsumer handshakeConsumer = new ClientHelloConsumer();
    static final HandshakeProducer handshakeProducer = new ClientHelloProducer();
    private static final HandshakeConsumer t12HandshakeConsumer = new T12ClientHelloConsumer();
    private static final HandshakeConsumer t13HandshakeConsumer = new T13ClientHelloConsumer();
    private static final HandshakeConsumer d12HandshakeConsumer = new D12ClientHelloConsumer();
    private static final HandshakeConsumer d13HandshakeConsumer = new D13ClientHelloConsumer();

    ClientHello() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$ClientHelloMessage.class */
    public static final class ClientHelloMessage extends SSLHandshake.HandshakeMessage {
        private final boolean isDTLS;
        final int clientVersion;
        final RandomCookie clientRandom;
        final SessionId sessionId;
        private byte[] cookie;
        final int[] cipherSuiteIds;
        final List<CipherSuite> cipherSuites;
        final byte[] compressionMethod;
        final SSLExtensions extensions;
        private static final byte[] NULL_COMPRESSION = {0};

        ClientHelloMessage(HandshakeContext handshakeContext, int clientVersion, SessionId sessionId, List<CipherSuite> cipherSuites, SecureRandom generator) {
            super(handshakeContext);
            this.isDTLS = handshakeContext.sslContext.isDTLS();
            this.clientVersion = clientVersion;
            this.clientRandom = new RandomCookie(generator);
            this.sessionId = sessionId;
            if (this.isDTLS) {
                this.cookie = new byte[0];
            } else {
                this.cookie = null;
            }
            this.cipherSuites = cipherSuites;
            this.cipherSuiteIds = getCipherSuiteIds(cipherSuites);
            this.extensions = new SSLExtensions(this);
            this.compressionMethod = NULL_COMPRESSION;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static void readPartial(TransportContext tc, ByteBuffer m) throws IOException {
            boolean isDTLS = tc.sslContext.isDTLS();
            Record.getInt16(m);
            new RandomCookie(m);
            Record.getBytes8(m);
            if (isDTLS) {
                Record.getBytes8(m);
            }
            Record.getBytes16(m);
            Record.getBytes8(m);
            if (m.remaining() >= 2) {
                int remaining = Record.getInt16(m);
                while (remaining > 0) {
                    int id = Record.getInt16(m);
                    int extLen = Record.getInt16(m);
                    remaining -= extLen + 4;
                    if (id == SSLExtension.CH_PRE_SHARED_KEY.f986id) {
                        if (remaining > 0) {
                            throw tc.fatal(Alert.ILLEGAL_PARAMETER, "pre_shared_key extension is not last");
                        }
                        Record.getBytes16(m);
                        return;
                    }
                    m.position(m.position() + extLen);
                }
            }
        }

        ClientHelloMessage(HandshakeContext handshakeContext, ByteBuffer m, SSLExtension[] supportedExtensions) throws IOException {
            super(handshakeContext);
            this.isDTLS = handshakeContext.sslContext.isDTLS();
            this.clientVersion = ((m.get() & 255) << 8) | (m.get() & 255);
            this.clientRandom = new RandomCookie(m);
            this.sessionId = new SessionId(Record.getBytes8(m));
            try {
                this.sessionId.checkLength(this.clientVersion);
                if (this.isDTLS) {
                    this.cookie = Record.getBytes8(m);
                } else {
                    this.cookie = null;
                }
                byte[] encodedIds = Record.getBytes16(m);
                if (encodedIds.length == 0 || (encodedIds.length & 1) != 0) {
                    throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid ClientHello message");
                }
                this.cipherSuiteIds = new int[encodedIds.length >> 1];
                int i = 0;
                int j = 0;
                while (i < encodedIds.length) {
                    int i2 = i;
                    int i3 = i + 1;
                    this.cipherSuiteIds[j] = ((encodedIds[i2] & 255) << 8) | (encodedIds[i3] & 255);
                    i = i3 + 1;
                    j++;
                }
                this.cipherSuites = getCipherSuites(this.cipherSuiteIds);
                this.compressionMethod = Record.getBytes8(m);
                if (m.hasRemaining()) {
                    this.extensions = new SSLExtensions(this, m, supportedExtensions);
                } else {
                    this.extensions = new SSLExtensions(this);
                }
            } catch (SSLProtocolException ex) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, ex);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void setHelloCookie(byte[] cookie) {
            this.cookie = cookie;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public byte[] getHelloCookieBytes() {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            try {
                hos.putInt8((byte) ((this.clientVersion >>> 8) & GF2Field.MASK));
                hos.putInt8((byte) (this.clientVersion & GF2Field.MASK));
                hos.write(this.clientRandom.randomBytes, 0, 32);
                hos.putBytes8(this.sessionId.getId());
                hos.putBytes16(getEncodedCipherSuites());
                hos.putBytes8(this.compressionMethod);
                this.extensions.send(hos);
            } catch (IOException e) {
            }
            return hos.toByteArray();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public byte[] getHeaderBytes() {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            try {
                hos.putInt8((byte) ((this.clientVersion >>> 8) & GF2Field.MASK));
                hos.putInt8((byte) (this.clientVersion & GF2Field.MASK));
                hos.write(this.clientRandom.randomBytes, 0, 32);
                hos.putBytes8(this.sessionId.getId());
                hos.putBytes16(getEncodedCipherSuites());
                hos.putBytes8(this.compressionMethod);
            } catch (IOException e) {
            }
            return hos.toByteArray();
        }

        private static int[] getCipherSuiteIds(List<CipherSuite> cipherSuites) {
            if (cipherSuites != null) {
                int[] ids = new int[cipherSuites.size()];
                int i = 0;
                for (CipherSuite cipherSuite : cipherSuites) {
                    int i2 = i;
                    i++;
                    ids[i2] = cipherSuite.f964id;
                }
                return ids;
            }
            return new int[0];
        }

        private static List<CipherSuite> getCipherSuites(int[] ids) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (int id : ids) {
                CipherSuite cipherSuite = CipherSuite.valueOf(id);
                if (cipherSuite != null) {
                    cipherSuites.add(cipherSuite);
                }
            }
            return Collections.unmodifiableList(cipherSuites);
        }

        private List<String> getCipherSuiteNames() {
            int[] iArr;
            List<String> names = new LinkedList<>();
            for (int id : this.cipherSuiteIds) {
                names.add(CipherSuite.nameOf(id) + "(" + Utilities.byte16HexString(id) + ")");
            }
            return names;
        }

        private byte[] getEncodedCipherSuites() {
            int[] iArr;
            byte[] encoded = new byte[this.cipherSuiteIds.length << 1];
            int i = 0;
            for (int id : this.cipherSuiteIds) {
                int i2 = i;
                int i3 = i + 1;
                encoded[i2] = (byte) (id >> 8);
                i = i3 + 1;
                encoded[i3] = (byte) id;
            }
            return encoded;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_HELLO;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 38 + this.sessionId.length() + (this.isDTLS ? 1 + this.cookie.length : 0) + (this.cipherSuiteIds.length * 2) + this.compressionMethod.length + this.extensions.length();
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            sendCore(hos);
            this.extensions.send(hos);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void sendCore(HandshakeOutStream hos) throws IOException {
            hos.putInt8((byte) (this.clientVersion >>> 8));
            hos.putInt8((byte) this.clientVersion);
            hos.write(this.clientRandom.randomBytes, 0, 32);
            hos.putBytes8(this.sessionId.getId());
            if (this.isDTLS) {
                hos.putBytes8(this.cookie);
            }
            hos.putBytes16(getEncodedCipherSuites());
            hos.putBytes8(this.compressionMethod);
        }

        public String toString() {
            if (this.isDTLS) {
                MessageFormat messageFormat = new MessageFormat("\"ClientHello\": '{'\n  \"client version\"      : \"{0}\",\n  \"random\"              : \"{1}\",\n  \"session id\"          : \"{2}\",\n  \"cookie\"              : \"{3}\",\n  \"cipher suites\"       : \"{4}\",\n  \"compression methods\" : \"{5}\",\n  \"extensions\"          : [\n{6}\n  ]\n'}'", Locale.ENGLISH);
                Object[] messageFields = {ProtocolVersion.nameOf(this.clientVersion), Utilities.toHexString(this.clientRandom.randomBytes), this.sessionId.toString(), Utilities.toHexString(this.cookie), getCipherSuiteNames().toString(), Utilities.toHexString(this.compressionMethod), Utilities.indent(Utilities.indent(this.extensions.toString()))};
                return messageFormat.format(messageFields);
            }
            MessageFormat messageFormat2 = new MessageFormat("\"ClientHello\": '{'\n  \"client version\"      : \"{0}\",\n  \"random\"              : \"{1}\",\n  \"session id\"          : \"{2}\",\n  \"cipher suites\"       : \"{3}\",\n  \"compression methods\" : \"{4}\",\n  \"extensions\"          : [\n{5}\n  ]\n'}'", Locale.ENGLISH);
            Object[] messageFields2 = {ProtocolVersion.nameOf(this.clientVersion), Utilities.toHexString(this.clientRandom.randomBytes), this.sessionId.toString(), getCipherSuiteNames().toString(), Utilities.toHexString(this.compressionMethod), Utilities.indent(Utilities.indent(this.extensions.toString()))};
            return messageFormat2.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$ClientHelloKickstartProducer.class */
    private static final class ClientHelloKickstartProducer implements SSLProducer {
        private ClientHelloKickstartProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLProducer
        public byte[] produce(ConnectionContext context) throws IOException {
            String identityAlg;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeProducers.remove(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id));
            ProtocolVersion maxProtocolVersion = chc.maximumActiveProtocol;
            SessionId sessionId = new SessionId(new byte[0]);
            List<CipherSuite> cipherSuites = chc.activeCipherSuites;
            SSLSessionContextImpl ssci = (SSLSessionContextImpl) chc.sslContext.engineGetClientSessionContext();
            SSLSessionImpl session = ssci.get(chc.conContext.transport.getPeerHost(), chc.conContext.transport.getPeerPort());
            if (session != null) {
                if (!ClientHandshakeContext.allowUnsafeServerCertChange && session.isSessionResumption()) {
                    try {
                        chc.reservedServerCerts = (X509Certificate[]) session.getPeerCertificates();
                    } catch (SSLPeerUnverifiedException e) {
                    }
                }
                if (!session.isRejoinable()) {
                    session = null;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Can't resume, the session is not rejoinable", new Object[0]);
                    }
                }
            }
            CipherSuite sessionSuite = null;
            if (session != null) {
                sessionSuite = session.getSuite();
                if (!chc.isNegotiable(sessionSuite)) {
                    session = null;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Can't resume, unavailable session cipher suite", new Object[0]);
                    }
                }
            }
            ProtocolVersion sessionVersion = null;
            if (session != null) {
                sessionVersion = session.getProtocolVersion();
                if (!chc.isNegotiable(sessionVersion)) {
                    session = null;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Can't resume, unavailable protocol version", new Object[0]);
                    }
                }
            }
            if (session != null && !sessionVersion.useTLS13PlusSpec() && SSLConfiguration.useExtendedMasterSecret) {
                boolean isEmsAvailable = chc.sslConfig.isAvailable(SSLExtension.CH_EXTENDED_MASTER_SECRET, sessionVersion);
                if (isEmsAvailable && !session.useExtendedMasterSecret && !SSLConfiguration.allowLegacyResumption) {
                    session = null;
                }
                if (session != null && !ClientHandshakeContext.allowUnsafeServerCertChange && ((identityAlg = chc.sslConfig.identificationProtocol) == null || identityAlg.length() == 0)) {
                    if (isEmsAvailable) {
                        if (!session.useExtendedMasterSecret) {
                            session = null;
                        }
                    } else {
                        session = null;
                    }
                }
            }
            String identityAlg2 = chc.sslConfig.identificationProtocol;
            if (session != null && identityAlg2 != null) {
                String sessionIdentityAlg = session.getIdentificationProtocol();
                if (!identityAlg2.equals(sessionIdentityAlg)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Can't resume, endpoint id algorithm does not match, requested: " + identityAlg2 + ", cached: " + sessionIdentityAlg, new Object[0]);
                    }
                    session = null;
                }
            }
            if (session != null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Try resuming session", session);
                }
                if (!session.getProtocolVersion().useTLS13PlusSpec()) {
                    sessionId = session.getSessionId();
                }
                if (!maxProtocolVersion.equals(sessionVersion)) {
                    maxProtocolVersion = sessionVersion;
                    chc.setVersion(sessionVersion);
                }
                if (!chc.sslConfig.enableSessionCreation) {
                    cipherSuites = (chc.conContext.isNegotiated || sessionVersion.useTLS13PlusSpec() || !cipherSuites.contains(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) ? Arrays.asList(sessionSuite) : Arrays.asList(sessionSuite, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("No new session is allowed, so try to resume the session cipher suite only", sessionSuite);
                    }
                }
                chc.isResumption = true;
                chc.resumingSession = session;
            }
            if (session == null) {
                if (!chc.sslConfig.enableSessionCreation) {
                    throw new SSLHandshakeException("No new session is allowed and no existing session can be resumed");
                }
                if (maxProtocolVersion.useTLS13PlusSpec() && SSLConfiguration.useCompatibilityMode) {
                    sessionId = new SessionId(true, chc.sslContext.getSecureRandom());
                }
            }
            ProtocolVersion minimumVersion = ProtocolVersion.NONE;
            for (ProtocolVersion pv : chc.activeProtocols) {
                if (minimumVersion == ProtocolVersion.NONE || pv.compare(minimumVersion) < 0) {
                    minimumVersion = pv;
                }
            }
            if (!minimumVersion.useTLS13PlusSpec() && chc.conContext.secureRenegotiation && cipherSuites.contains(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
                cipherSuites = new LinkedList<>(cipherSuites);
                cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }
            boolean negotiable = false;
            Iterator<CipherSuite> it = cipherSuites.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                CipherSuite suite = it.next();
                if (chc.isNegotiable(suite)) {
                    negotiable = true;
                    break;
                }
            }
            if (!negotiable) {
                throw new SSLHandshakeException("No negotiable cipher suite");
            }
            ProtocolVersion clientHelloVersion = maxProtocolVersion;
            if (clientHelloVersion.useTLS13PlusSpec()) {
                if (clientHelloVersion.isDTLS) {
                    clientHelloVersion = ProtocolVersion.DTLS12;
                } else {
                    clientHelloVersion = ProtocolVersion.TLS12;
                }
            }
            ClientHelloMessage chm = new ClientHelloMessage(chc, clientHelloVersion.f978id, sessionId, cipherSuites, chc.sslContext.getSecureRandom());
            chc.clientHelloRandom = chm.clientRandom;
            chc.clientHelloVersion = clientHelloVersion.f978id;
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO, chc.activeProtocols);
            chm.extensions.produce(chc, extTypes);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ClientHello handshake message", chm);
            }
            chm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            chc.initialClientHelloMsg = chm;
            chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id), SSLHandshake.SERVER_HELLO);
            if (chc.sslContext.isDTLS() && !minimumVersion.useTLS13PlusSpec()) {
                chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.HELLO_VERIFY_REQUEST.f987id), SSLHandshake.HELLO_VERIFY_REQUEST);
                return null;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$ClientHelloProducer.class */
    private static final class ClientHelloProducer implements HandshakeProducer {
        private ClientHelloProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            SSLHandshake ht = message.handshakeType();
            if (ht == null) {
                throw new UnsupportedOperationException("Not supported yet.");
            }
            switch (ht) {
                case HELLO_REQUEST:
                    try {
                        chc.kickstart();
                        return null;
                    } catch (IOException ioe) {
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, ioe);
                    }
                case HELLO_VERIFY_REQUEST:
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Produced ClientHello(cookie) handshake message", chc.initialClientHelloMsg);
                    }
                    chc.initialClientHelloMsg.write(chc.handshakeOutput);
                    chc.handshakeOutput.flush();
                    chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id), SSLHandshake.SERVER_HELLO);
                    ProtocolVersion minimumVersion = ProtocolVersion.NONE;
                    for (ProtocolVersion pv : chc.activeProtocols) {
                        if (minimumVersion == ProtocolVersion.NONE || pv.compare(minimumVersion) < 0) {
                            minimumVersion = pv;
                        }
                    }
                    if (chc.sslContext.isDTLS() && !minimumVersion.useTLS13PlusSpec()) {
                        chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.HELLO_VERIFY_REQUEST.f987id), SSLHandshake.HELLO_VERIFY_REQUEST);
                        return null;
                    }
                    return null;
                case HELLO_RETRY_REQUEST:
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Produced ClientHello(HRR) handshake message", chc.initialClientHelloMsg);
                    }
                    chc.initialClientHelloMsg.write(chc.handshakeOutput);
                    chc.handshakeOutput.flush();
                    chc.conContext.consumers.putIfAbsent(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id), ChangeCipherSpec.t13Consumer);
                    chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id), SSLHandshake.SERVER_HELLO);
                    return null;
                default:
                    throw new UnsupportedOperationException("Not supported yet.");
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$ClientHelloConsumer.class */
    private static final class ClientHelloConsumer implements SSLConsumer {
        private ClientHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id));
            if (!shc.handshakeConsumers.isEmpty()) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "No more handshake message allowed in a ClientHello flight");
            }
            SSLExtension[] enabledExtensions = shc.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO);
            ClientHelloMessage chm = new ClientHelloMessage(shc, message, enabledExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ClientHello handshake message", chm);
            }
            shc.clientHelloVersion = chm.clientVersion;
            onClientHello(shc, chm);
        }

        private void onClientHello(ServerHandshakeContext context, ClientHelloMessage clientHello) throws IOException {
            ProtocolVersion negotiatedProtocol;
            SSLExtension[] extTypes = {SSLExtension.CH_SUPPORTED_VERSIONS};
            clientHello.extensions.consumeOnLoad(context, extTypes);
            SupportedVersionsExtension.CHSupportedVersionsSpec svs = (SupportedVersionsExtension.CHSupportedVersionsSpec) context.handshakeExtensions.get(SSLExtension.CH_SUPPORTED_VERSIONS);
            if (svs != null) {
                negotiatedProtocol = negotiateProtocol(context, svs.requestedProtocols);
            } else {
                negotiatedProtocol = negotiateProtocol(context, clientHello.clientVersion);
            }
            context.negotiatedProtocol = negotiatedProtocol;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Negotiated protocol version: " + negotiatedProtocol.name, new Object[0]);
            }
            if (negotiatedProtocol.isDTLS) {
                if (negotiatedProtocol.useTLS13PlusSpec()) {
                    ClientHello.d13HandshakeConsumer.consume(context, clientHello);
                } else {
                    ClientHello.d12HandshakeConsumer.consume(context, clientHello);
                }
            } else if (negotiatedProtocol.useTLS13PlusSpec()) {
                ClientHello.t13HandshakeConsumer.consume(context, clientHello);
            } else {
                ClientHello.t12HandshakeConsumer.consume(context, clientHello);
            }
        }

        private ProtocolVersion negotiateProtocol(ServerHandshakeContext context, int clientHelloVersion) throws SSLException {
            int chv = clientHelloVersion;
            if (context.sslContext.isDTLS()) {
                if (chv < ProtocolVersion.DTLS12.f978id) {
                    chv = ProtocolVersion.DTLS12.f978id;
                }
            } else if (chv > ProtocolVersion.TLS12.f978id) {
                chv = ProtocolVersion.TLS12.f978id;
            }
            ProtocolVersion pv = ProtocolVersion.selectedFrom(context.activeProtocols, chv);
            if (pv == null || pv == ProtocolVersion.NONE || pv == ProtocolVersion.SSL20Hello) {
                throw context.conContext.fatal(Alert.PROTOCOL_VERSION, "Client requested protocol " + ProtocolVersion.nameOf(clientHelloVersion) + " is not enabled or supported in server context");
            }
            return pv;
        }

        private ProtocolVersion negotiateProtocol(ServerHandshakeContext context, int[] clientSupportedVersions) throws SSLException {
            for (ProtocolVersion spv : context.activeProtocols) {
                if (spv != ProtocolVersion.SSL20Hello) {
                    for (int cpv : clientSupportedVersions) {
                        if (cpv != ProtocolVersion.SSL20Hello.f978id && spv.f978id == cpv) {
                            return spv;
                        }
                    }
                    continue;
                }
            }
            throw context.conContext.fatal(Alert.PROTOCOL_VERSION, "The client supported protocol versions " + Arrays.toString(ProtocolVersion.toStringArray(clientSupportedVersions)) + " are not accepted by server preferences " + context.activeProtocols);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$T12ClientHelloConsumer.class */
    private static final class T12ClientHelloConsumer implements HandshakeConsumer {
        private T12ClientHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHelloMessage clientHello = (ClientHelloMessage) message;
            if (shc.conContext.isNegotiated) {
                if (!shc.conContext.secureRenegotiation && !HandshakeContext.allowUnsafeRenegotiation) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsafe renegotiation is not allowed");
                }
                if (ServerHandshakeContext.rejectClientInitiatedRenego && !shc.kickstartMessageDelivered) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Client initiated renegotiation is not allowed");
                }
            }
            if (clientHello.sessionId.length() != 0) {
                SSLSessionImpl previous = ((SSLSessionContextImpl) shc.sslContext.engineGetServerSessionContext()).get(clientHello.sessionId.getId());
                boolean resumingSession = previous != null && previous.isRejoinable();
                if (!resumingSession && SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Can't resume, the existing session is not rejoinable", new Object[0]);
                }
                if (resumingSession) {
                    ProtocolVersion sessionProtocol = previous.getProtocolVersion();
                    if (sessionProtocol != shc.negotiatedProtocol) {
                        resumingSession = false;
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, not the same protocol version", new Object[0]);
                        }
                    }
                }
                if (resumingSession && shc.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED) {
                    try {
                        previous.getPeerPrincipal();
                    } catch (SSLPeerUnverifiedException e) {
                        resumingSession = false;
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, client authentication is required", new Object[0]);
                        }
                    }
                }
                if (resumingSession) {
                    CipherSuite suite = previous.getSuite();
                    if (!shc.isNegotiable(suite) || !clientHello.cipherSuites.contains(suite)) {
                        resumingSession = false;
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, the session cipher suite is absent", new Object[0]);
                        }
                    }
                }
                String identityAlg = shc.sslConfig.identificationProtocol;
                if (resumingSession && identityAlg != null) {
                    String sessionIdentityAlg = previous.getIdentificationProtocol();
                    if (!identityAlg.equals(sessionIdentityAlg)) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, endpoint id algorithm does not match, requested: " + identityAlg + ", cached: " + sessionIdentityAlg, new Object[0]);
                        }
                        resumingSession = false;
                    }
                }
                shc.isResumption = resumingSession;
                shc.resumingSession = resumingSession ? previous : null;
            }
            shc.clientHelloRandom = clientHello.clientRandom;
            SSLExtension[] extTypes = shc.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO);
            clientHello.extensions.consumeOnLoad(shc, extTypes);
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }
            shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id), SSLHandshake.SERVER_HELLO);
            SSLHandshake[] probableHandshakeMessages = {SSLHandshake.SERVER_HELLO, SSLHandshake.CERTIFICATE, SSLHandshake.CERTIFICATE_STATUS, SSLHandshake.SERVER_KEY_EXCHANGE, SSLHandshake.CERTIFICATE_REQUEST, SSLHandshake.SERVER_HELLO_DONE, SSLHandshake.FINISHED};
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer = shc.handshakeProducers.remove(Byte.valueOf(hs.f987id));
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, clientHello);
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$T13ClientHelloConsumer.class */
    private static final class T13ClientHelloConsumer implements HandshakeConsumer {
        private T13ClientHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHelloMessage clientHello = (ClientHelloMessage) message;
            if (shc.conContext.isNegotiated) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Received unexpected renegotiation handshake message");
            }
            shc.conContext.consumers.putIfAbsent(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id), ChangeCipherSpec.t13Consumer);
            shc.isResumption = true;
            SSLExtension[] extTypes = {SSLExtension.PSK_KEY_EXCHANGE_MODES, SSLExtension.CH_PRE_SHARED_KEY};
            clientHello.extensions.consumeOnLoad(shc, extTypes);
            SSLExtension[] extTypes2 = shc.sslConfig.getExclusiveExtensions(SSLHandshake.CLIENT_HELLO, Arrays.asList(SSLExtension.PSK_KEY_EXCHANGE_MODES, SSLExtension.CH_PRE_SHARED_KEY, SSLExtension.CH_SUPPORTED_VERSIONS));
            clientHello.extensions.consumeOnLoad(shc, extTypes2);
            if (!shc.handshakeProducers.isEmpty()) {
                goHelloRetryRequest(shc, clientHello);
            } else {
                goServerHello(shc, clientHello);
            }
        }

        private void goHelloRetryRequest(ServerHandshakeContext shc, ClientHelloMessage clientHello) throws IOException {
            HandshakeProducer handshakeProducer = shc.handshakeProducers.remove(Byte.valueOf(SSLHandshake.HELLO_RETRY_REQUEST.f987id));
            if (handshakeProducer != null) {
                handshakeProducer.produce(shc, clientHello);
                if (!shc.handshakeProducers.isEmpty()) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "unknown handshake producers: " + shc.handshakeProducers);
                }
                return;
            }
            throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No HelloRetryRequest producer: " + shc.handshakeProducers);
        }

        private void goServerHello(ServerHandshakeContext shc, ClientHelloMessage clientHello) throws IOException {
            shc.clientHelloRandom = clientHello.clientRandom;
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }
            shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id), SSLHandshake.SERVER_HELLO);
            SSLHandshake[] probableHandshakeMessages = {SSLHandshake.SERVER_HELLO, SSLHandshake.ENCRYPTED_EXTENSIONS, SSLHandshake.CERTIFICATE_REQUEST, SSLHandshake.CERTIFICATE, SSLHandshake.CERTIFICATE_VERIFY, SSLHandshake.FINISHED};
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer = shc.handshakeProducers.remove(Byte.valueOf(hs.f987id));
                if (handshakeProducer != null) {
                    handshakeProducer.produce(shc, clientHello);
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$D12ClientHelloConsumer.class */
    private static final class D12ClientHelloConsumer implements HandshakeConsumer {
        private D12ClientHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHelloMessage clientHello = (ClientHelloMessage) message;
            if (shc.conContext.isNegotiated) {
                if (!shc.conContext.secureRenegotiation && !HandshakeContext.allowUnsafeRenegotiation) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsafe renegotiation is not allowed");
                }
                if (ServerHandshakeContext.rejectClientInitiatedRenego && !shc.kickstartMessageDelivered) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Client initiated renegotiation is not allowed");
                }
            }
            if (clientHello.sessionId.length() != 0) {
                SSLSessionImpl previous = ((SSLSessionContextImpl) shc.sslContext.engineGetServerSessionContext()).get(clientHello.sessionId.getId());
                boolean resumingSession = previous != null && previous.isRejoinable();
                if (!resumingSession && SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Can't resume, the existing session is not rejoinable", new Object[0]);
                }
                if (resumingSession) {
                    ProtocolVersion sessionProtocol = previous.getProtocolVersion();
                    if (sessionProtocol != shc.negotiatedProtocol) {
                        resumingSession = false;
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, not the same protocol version", new Object[0]);
                        }
                    }
                }
                if (resumingSession && shc.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED) {
                    try {
                        previous.getPeerPrincipal();
                    } catch (SSLPeerUnverifiedException e) {
                        resumingSession = false;
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, client authentication is required", new Object[0]);
                        }
                    }
                }
                if (resumingSession) {
                    CipherSuite suite = previous.getSuite();
                    if (!shc.isNegotiable(suite) || !clientHello.cipherSuites.contains(suite)) {
                        resumingSession = false;
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, the session cipher suite is absent", new Object[0]);
                        }
                    }
                }
                shc.isResumption = resumingSession;
                shc.resumingSession = resumingSession ? previous : null;
            }
            HelloCookieManager hcm = shc.sslContext.getHelloCookieManager(ProtocolVersion.DTLS10);
            if (!shc.isResumption && !hcm.isCookieValid(shc, clientHello, clientHello.cookie)) {
                shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.HELLO_VERIFY_REQUEST.f987id), SSLHandshake.HELLO_VERIFY_REQUEST);
                SSLHandshake.HELLO_VERIFY_REQUEST.produce(context, clientHello);
                return;
            }
            shc.clientHelloRandom = clientHello.clientRandom;
            SSLExtension[] extTypes = shc.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO);
            clientHello.extensions.consumeOnLoad(shc, extTypes);
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }
            shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id), SSLHandshake.SERVER_HELLO);
            SSLHandshake[] probableHandshakeMessages = {SSLHandshake.SERVER_HELLO, SSLHandshake.CERTIFICATE, SSLHandshake.CERTIFICATE_STATUS, SSLHandshake.SERVER_KEY_EXCHANGE, SSLHandshake.CERTIFICATE_REQUEST, SSLHandshake.SERVER_HELLO_DONE, SSLHandshake.FINISHED};
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer = shc.handshakeProducers.remove(Byte.valueOf(hs.f987id));
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, clientHello);
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientHello$D13ClientHelloConsumer.class */
    private static final class D13ClientHelloConsumer implements HandshakeConsumer {
        private D13ClientHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
}