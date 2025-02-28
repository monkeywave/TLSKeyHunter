package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmConstraints;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.ClientHello;
import org.openjsse.sun.security.ssl.SSLCipher;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedVersionsExtension;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello.class */
public final class ServerHello {
    static final SSLConsumer handshakeConsumer = new ServerHelloConsumer();
    static final HandshakeProducer t12HandshakeProducer = new T12ServerHelloProducer();
    static final HandshakeProducer t13HandshakeProducer = new T13ServerHelloProducer();
    static final HandshakeProducer hrrHandshakeProducer = new T13HelloRetryRequestProducer();
    static final HandshakeProducer hrrReproducer = new T13HelloRetryRequestReproducer();
    private static final HandshakeConsumer t12HandshakeConsumer = new T12ServerHelloConsumer();
    private static final HandshakeConsumer t13HandshakeConsumer = new T13ServerHelloConsumer();
    private static final HandshakeConsumer d12HandshakeConsumer = new T12ServerHelloConsumer();
    private static final HandshakeConsumer d13HandshakeConsumer = new T13ServerHelloConsumer();
    private static final HandshakeConsumer t13HrrHandshakeConsumer = new T13HelloRetryRequestConsumer();
    private static final HandshakeConsumer d13HrrHandshakeConsumer = new T13HelloRetryRequestConsumer();

    ServerHello() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$ServerHelloMessage.class */
    public static final class ServerHelloMessage extends SSLHandshake.HandshakeMessage {
        final ProtocolVersion serverVersion;
        final RandomCookie serverRandom;
        final SessionId sessionId;
        final CipherSuite cipherSuite;
        final byte compressionMethod;
        final SSLExtensions extensions;
        final ClientHello.ClientHelloMessage clientHello;
        final ByteBuffer handshakeRecord;

        ServerHelloMessage(HandshakeContext context, ProtocolVersion serverVersion, SessionId sessionId, CipherSuite cipherSuite, RandomCookie serverRandom, ClientHello.ClientHelloMessage clientHello) {
            super(context);
            this.serverVersion = serverVersion;
            this.serverRandom = serverRandom;
            this.sessionId = sessionId;
            this.cipherSuite = cipherSuite;
            this.compressionMethod = (byte) 0;
            this.extensions = new SSLExtensions(this);
            this.clientHello = clientHello;
            this.handshakeRecord = null;
        }

        ServerHelloMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            SSLExtension[] supportedExtensions;
            this.handshakeRecord = m.duplicate();
            byte major = m.get();
            byte minor = m.get();
            this.serverVersion = ProtocolVersion.valueOf(major, minor);
            if (this.serverVersion == null) {
                throw context.conContext.fatal(Alert.PROTOCOL_VERSION, "Unsupported protocol version: " + ProtocolVersion.nameOf(major, minor));
            }
            this.serverRandom = new RandomCookie(m);
            this.sessionId = new SessionId(Record.getBytes8(m));
            try {
                this.sessionId.checkLength(this.serverVersion.f978id);
                int cipherSuiteId = Record.getInt16(m);
                this.cipherSuite = CipherSuite.valueOf(cipherSuiteId);
                if (this.cipherSuite == null || !context.isNegotiable(this.cipherSuite)) {
                    throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Server selected improper ciphersuite " + CipherSuite.nameOf(cipherSuiteId));
                }
                this.compressionMethod = m.get();
                if (this.compressionMethod != 0) {
                    throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "compression type not supported, " + ((int) this.compressionMethod));
                }
                if (this.serverRandom.isHelloRetryRequest()) {
                    supportedExtensions = context.sslConfig.getEnabledExtensions(SSLHandshake.HELLO_RETRY_REQUEST);
                } else {
                    supportedExtensions = context.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO);
                }
                if (m.hasRemaining()) {
                    this.extensions = new SSLExtensions(this, m, supportedExtensions);
                } else {
                    this.extensions = new SSLExtensions(this);
                }
                this.clientHello = null;
            } catch (SSLProtocolException ex) {
                throw this.handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, ex);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return this.serverRandom.isHelloRetryRequest() ? SSLHandshake.HELLO_RETRY_REQUEST : SSLHandshake.SERVER_HELLO;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 38 + this.sessionId.length() + this.extensions.length();
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8(this.serverVersion.major);
            hos.putInt8(this.serverVersion.minor);
            hos.write(this.serverRandom.randomBytes);
            hos.putBytes8(this.sessionId.getId());
            hos.putInt8((this.cipherSuite.f964id >> 8) & GF2Field.MASK);
            hos.putInt8(this.cipherSuite.f964id & GF2Field.MASK);
            hos.putInt8(this.compressionMethod);
            this.extensions.send(hos);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"{0}\": '{'\n  \"server version\"      : \"{1}\",\n  \"random\"              : \"{2}\",\n  \"session id\"          : \"{3}\",\n  \"cipher suite\"        : \"{4}\",\n  \"compression methods\" : \"{5}\",\n  \"extensions\"          : [\n{6}\n  ]\n'}'", Locale.ENGLISH);
            Object[] messageFields = new Object[7];
            messageFields[0] = this.serverRandom.isHelloRetryRequest() ? "HelloRetryRequest" : "ServerHello";
            messageFields[1] = this.serverVersion.name;
            messageFields[2] = Utilities.toHexString(this.serverRandom.randomBytes);
            messageFields[3] = this.sessionId.toString();
            messageFields[4] = this.cipherSuite.name + "(" + Utilities.byte16HexString(this.cipherSuite.f964id) + ")";
            messageFields[5] = Utilities.toHexString(this.compressionMethod);
            messageFields[6] = Utilities.indent(this.extensions.toString(), "    ");
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T12ServerHelloProducer.class */
    private static final class T12ServerHelloProducer implements HandshakeProducer {
        private T12ServerHelloProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            Map.Entry<Byte, HandshakeProducer>[] handshakeProducers;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            if (!shc.isResumption || shc.resumingSession == null) {
                if (!shc.sslConfig.enableSessionCreation) {
                    throw new SSLException("Not resumption, and no new session is allowed");
                }
                if (shc.localSupportedSignAlgs == null) {
                    shc.localSupportedSignAlgs = SignatureScheme.getSupportedAlgorithms(shc.sslConfig, shc.algorithmConstraints, shc.activeProtocols);
                }
                SSLSessionImpl session = new SSLSessionImpl(shc, CipherSuite.C_NULL);
                session.setMaximumPacketSize(shc.sslConfig.maximumPacketSize);
                shc.handshakeSession = session;
                SSLExtension[] enabledExtensions = shc.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO, shc.negotiatedProtocol);
                clientHello.extensions.consumeOnTrade(shc, enabledExtensions);
                KeyExchangeProperties credentials = chooseCipherSuite(shc, clientHello);
                if (credentials == null) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common");
                }
                shc.negotiatedCipherSuite = credentials.cipherSuite;
                shc.handshakeKeyExchange = credentials.keyExchange;
                shc.handshakeSession.setSuite(credentials.cipherSuite);
                shc.handshakePossessions.addAll(Arrays.asList(credentials.possessions));
                shc.handshakeHash.determine(shc.negotiatedProtocol, shc.negotiatedCipherSuite);
                shc.stapleParams = StatusResponseManager.processStapling(shc);
                shc.staplingActive = shc.stapleParams != null;
                SSLKeyExchange ke = credentials.keyExchange;
                if (ke != null) {
                    for (Map.Entry<Byte, HandshakeProducer> me : ke.getHandshakeProducers(shc)) {
                        shc.handshakeProducers.put(me.getKey(), me.getValue());
                    }
                }
                if (ke != null && shc.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_NONE && !shc.negotiatedCipherSuite.isAnonymous()) {
                    SSLHandshake[] relatedHandshakers = ke.getRelatedHandshakers(shc);
                    int length = relatedHandshakers.length;
                    int i = 0;
                    while (true) {
                        if (i >= length) {
                            break;
                        }
                        SSLHandshake hs = relatedHandshakers[i];
                        if (hs != SSLHandshake.CERTIFICATE) {
                            i++;
                        } else {
                            shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_REQUEST.f987id), SSLHandshake.CERTIFICATE_REQUEST);
                            break;
                        }
                    }
                }
                shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO_DONE.f987id), SSLHandshake.SERVER_HELLO_DONE);
            } else {
                shc.handshakeSession = shc.resumingSession;
                shc.negotiatedProtocol = shc.resumingSession.getProtocolVersion();
                shc.negotiatedCipherSuite = shc.resumingSession.getSuite();
                shc.handshakeHash.determine(shc.negotiatedProtocol, shc.negotiatedCipherSuite);
            }
            ServerHelloMessage shm = new ServerHelloMessage(shc, shc.negotiatedProtocol, shc.handshakeSession.getSessionId(), shc.negotiatedCipherSuite, new RandomCookie(shc), clientHello);
            shc.serverHelloRandom = shm.serverRandom;
            SSLExtension[] serverHelloExtensions = shc.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO, shc.negotiatedProtocol);
            shm.extensions.produce(shc, serverHelloExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ServerHello handshake message", shm);
            }
            shm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            if (shc.isResumption && shc.resumingSession != null) {
                SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
                if (kdg == null) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
                }
                shc.handshakeKeyDerivation = kdg.createKeyDerivation(shc, shc.resumingSession.getMasterSecret());
                shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
                return null;
            }
            return null;
        }

        private static KeyExchangeProperties chooseCipherSuite(ServerHandshakeContext shc, ClientHello.ClientHelloMessage clientHello) throws IOException {
            List<CipherSuite> preferred;
            List<CipherSuite> proposed;
            SSLPossession[] hcds;
            if (shc.sslConfig.preferLocalCipherSuites) {
                preferred = shc.activeCipherSuites;
                proposed = clientHello.cipherSuites;
            } else {
                preferred = clientHello.cipherSuites;
                proposed = shc.activeCipherSuites;
            }
            List<CipherSuite> legacySuites = new LinkedList<>();
            for (CipherSuite cs : preferred) {
                if (HandshakeContext.isNegotiable(proposed, shc.negotiatedProtocol, cs) && (shc.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_REQUIRED || (cs.keyExchange != CipherSuite.KeyExchange.K_DH_ANON && cs.keyExchange != CipherSuite.KeyExchange.K_ECDH_ANON))) {
                    SSLKeyExchange ke = SSLKeyExchange.valueOf(cs.keyExchange, shc.negotiatedProtocol);
                    if (ke == null) {
                        continue;
                    } else if (!ServerHandshakeContext.legacyAlgorithmConstraints.permits(null, cs.name, null)) {
                        legacySuites.add(cs);
                    } else {
                        SSLPossession[] hcds2 = ke.createPossessions(shc);
                        if (hcds2 != null && hcds2.length != 0) {
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.fine("use cipher suite " + cs.name, new Object[0]);
                            }
                            return new KeyExchangeProperties(cs, ke, hcds2);
                        }
                    }
                }
            }
            for (CipherSuite cs2 : legacySuites) {
                SSLKeyExchange ke2 = SSLKeyExchange.valueOf(cs2.keyExchange, shc.negotiatedProtocol);
                if (ke2 != null && (hcds = ke2.createPossessions(shc)) != null && hcds.length != 0) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning("use legacy cipher suite " + cs2.name, new Object[0]);
                    }
                    return new KeyExchangeProperties(cs2, ke2, hcds);
                }
            }
            throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common");
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T12ServerHelloProducer$KeyExchangeProperties.class */
        public static final class KeyExchangeProperties {
            final CipherSuite cipherSuite;
            final SSLKeyExchange keyExchange;
            final SSLPossession[] possessions;

            private KeyExchangeProperties(CipherSuite cipherSuite, SSLKeyExchange keyExchange, SSLPossession[] possessions) {
                this.cipherSuite = cipherSuite;
                this.keyExchange = keyExchange;
                this.possessions = possessions;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T13ServerHelloProducer.class */
    private static final class T13ServerHelloProducer implements HandshakeProducer {
        private T13ServerHelloProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            if (!shc.isResumption || shc.resumingSession == null) {
                if (!shc.sslConfig.enableSessionCreation) {
                    throw new SSLException("Not resumption, and no new session is allowed");
                }
                if (shc.localSupportedSignAlgs == null) {
                    shc.localSupportedSignAlgs = SignatureScheme.getSupportedAlgorithms(shc.sslConfig, shc.algorithmConstraints, shc.activeProtocols);
                }
                SSLSessionImpl session = new SSLSessionImpl(shc, CipherSuite.C_NULL);
                session.setMaximumPacketSize(shc.sslConfig.maximumPacketSize);
                shc.handshakeSession = session;
                SSLExtension[] enabledExtensions = shc.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO, shc.negotiatedProtocol);
                clientHello.extensions.consumeOnTrade(shc, enabledExtensions);
                CipherSuite cipherSuite = chooseCipherSuite(shc, clientHello);
                if (cipherSuite == null) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common");
                }
                shc.negotiatedCipherSuite = cipherSuite;
                shc.handshakeSession.setSuite(cipherSuite);
                shc.handshakeHash.determine(shc.negotiatedProtocol, shc.negotiatedCipherSuite);
            } else {
                shc.handshakeSession = shc.resumingSession;
                SSLExtension[] enabledExtensions2 = shc.sslConfig.getEnabledExtensions(SSLHandshake.CLIENT_HELLO, shc.negotiatedProtocol);
                clientHello.extensions.consumeOnTrade(shc, enabledExtensions2);
                shc.negotiatedProtocol = shc.resumingSession.getProtocolVersion();
                shc.negotiatedCipherSuite = shc.resumingSession.getSuite();
                shc.handshakeHash.determine(shc.negotiatedProtocol, shc.negotiatedCipherSuite);
                ServerHello.setUpPskKD(shc, shc.resumingSession.consumePreSharedKey());
            }
            shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.ENCRYPTED_EXTENSIONS.f987id), SSLHandshake.ENCRYPTED_EXTENSIONS);
            shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
            ServerHelloMessage shm = new ServerHelloMessage(shc, ProtocolVersion.TLS12, clientHello.sessionId, shc.negotiatedCipherSuite, new RandomCookie(shc), clientHello);
            shc.serverHelloRandom = shm.serverRandom;
            SSLExtension[] serverHelloExtensions = shc.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO, shc.negotiatedProtocol);
            shm.extensions.produce(shc, serverHelloExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ServerHello handshake message", shm);
            }
            shm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeHash.update();
            SSLKeyExchange ke = shc.handshakeKeyExchange;
            if (ke == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not negotiated key shares");
            }
            SSLKeyDerivation handshakeKD = ke.createKeyDerivation(shc);
            SecretKey handshakeSecret = handshakeKD.deriveKey("TlsHandshakeSecret", null);
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
            if (kdg == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
            }
            SSLKeyDerivation kd = new SSLSecretDerivation(shc, handshakeSecret);
            SecretKey readSecret = kd.deriveKey("TlsClientHandshakeTrafficSecret", null);
            SSLKeyDerivation readKD = kdg.createKeyDerivation(shc, readSecret);
            SecretKey readKey = readKD.deriveKey("TlsKey", null);
            SecretKey readIvSecret = readKD.deriveKey("TlsIv", null);
            IvParameterSpec readIv = new IvParameterSpec(readIvSecret.getEncoded());
            try {
                SSLCipher.SSLReadCipher readCipher = shc.negotiatedCipherSuite.bulkCipher.createReadCipher(Authenticator.valueOf(shc.negotiatedProtocol), shc.negotiatedProtocol, readKey, readIv, shc.sslContext.getSecureRandom());
                if (readCipher == null) {
                    throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + shc.negotiatedCipherSuite + ") and protocol version (" + shc.negotiatedProtocol + ")");
                }
                shc.baseReadSecret = readSecret;
                shc.conContext.inputRecord.changeReadCiphers(readCipher);
                SecretKey writeSecret = kd.deriveKey("TlsServerHandshakeTrafficSecret", null);
                SSLKeyDerivation writeKD = kdg.createKeyDerivation(shc, writeSecret);
                SecretKey writeKey = writeKD.deriveKey("TlsKey", null);
                SecretKey writeIvSecret = writeKD.deriveKey("TlsIv", null);
                IvParameterSpec writeIv = new IvParameterSpec(writeIvSecret.getEncoded());
                try {
                    SSLCipher.SSLWriteCipher writeCipher = shc.negotiatedCipherSuite.bulkCipher.createWriteCipher(Authenticator.valueOf(shc.negotiatedProtocol), shc.negotiatedProtocol, writeKey, writeIv, shc.sslContext.getSecureRandom());
                    if (writeCipher == null) {
                        throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + shc.negotiatedCipherSuite + ") and protocol version (" + shc.negotiatedProtocol + ")");
                    }
                    shc.baseWriteSecret = writeSecret;
                    shc.conContext.outputRecord.changeWriteCiphers(writeCipher, clientHello.sessionId.length() != 0);
                    shc.handshakeKeyDerivation = kd;
                    return null;
                } catch (GeneralSecurityException gse) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", gse);
                }
            } catch (GeneralSecurityException gse2) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", gse2);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static CipherSuite chooseCipherSuite(ServerHandshakeContext shc, ClientHello.ClientHelloMessage clientHello) throws IOException {
            List<CipherSuite> preferred;
            List<CipherSuite> proposed;
            if (shc.sslConfig.preferLocalCipherSuites) {
                preferred = shc.activeCipherSuites;
                proposed = clientHello.cipherSuites;
            } else {
                preferred = clientHello.cipherSuites;
                proposed = shc.activeCipherSuites;
            }
            CipherSuite legacySuite = null;
            AlgorithmConstraints legacyConstraints = ServerHandshakeContext.legacyAlgorithmConstraints;
            for (CipherSuite cs : preferred) {
                if (HandshakeContext.isNegotiable(proposed, shc.negotiatedProtocol, cs)) {
                    if (legacySuite == null && !legacyConstraints.permits(null, cs.name, null)) {
                        legacySuite = cs;
                    } else {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.fine("use cipher suite " + cs.name, new Object[0]);
                        }
                        return cs;
                    }
                }
            }
            if (legacySuite != null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("use legacy cipher suite " + legacySuite.name, new Object[0]);
                }
                return legacySuite;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T13HelloRetryRequestProducer.class */
    private static final class T13HelloRetryRequestProducer implements HandshakeProducer {
        private T13HelloRetryRequestProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            CipherSuite cipherSuite = T13ServerHelloProducer.chooseCipherSuite(shc, clientHello);
            if (cipherSuite == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "no cipher suites in common for hello retry request");
            }
            ServerHelloMessage hhrm = new ServerHelloMessage(shc, ProtocolVersion.TLS12, clientHello.sessionId, cipherSuite, RandomCookie.hrrRandom, clientHello);
            shc.negotiatedCipherSuite = cipherSuite;
            shc.handshakeHash.determine(shc.negotiatedProtocol, shc.negotiatedCipherSuite);
            SSLExtension[] serverHelloExtensions = shc.sslConfig.getEnabledExtensions(SSLHandshake.HELLO_RETRY_REQUEST, shc.negotiatedProtocol);
            hhrm.extensions.produce(shc, serverHelloExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced HelloRetryRequest handshake message", hhrm);
            }
            hhrm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeHash.finish();
            shc.handshakeExtensions.clear();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id), SSLHandshake.CLIENT_HELLO);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T13HelloRetryRequestReproducer.class */
    private static final class T13HelloRetryRequestReproducer implements HandshakeProducer {
        private T13HelloRetryRequestReproducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            CipherSuite cipherSuite = shc.negotiatedCipherSuite;
            ServerHelloMessage hhrm = new ServerHelloMessage(shc, ProtocolVersion.TLS12, clientHello.sessionId, cipherSuite, RandomCookie.hrrRandom, clientHello);
            SSLExtension[] serverHelloExtensions = shc.sslConfig.getEnabledExtensions(SSLHandshake.MESSAGE_HASH, shc.negotiatedProtocol);
            hhrm.extensions.produce(shc, serverHelloExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Reproduced HelloRetryRequest handshake message", hhrm);
            }
            HandshakeOutStream hos = new HandshakeOutStream(null);
            hhrm.write(hos);
            return hos.toByteArray();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$ServerHelloConsumer.class */
    private static final class ServerHelloConsumer implements SSLConsumer {
        private ServerHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id));
            if (!chc.handshakeConsumers.isEmpty()) {
                chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.HELLO_VERIFY_REQUEST.f987id));
            }
            if (!chc.handshakeConsumers.isEmpty()) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "No more message expected before ServerHello is processed");
            }
            ServerHelloMessage shm = new ServerHelloMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ServerHello handshake message", shm);
            }
            if (shm.serverRandom.isHelloRetryRequest()) {
                onHelloRetryRequest(chc, shm);
            } else {
                onServerHello(chc, shm);
            }
        }

        private void onHelloRetryRequest(ClientHandshakeContext chc, ServerHelloMessage helloRetryRequest) throws IOException {
            ProtocolVersion serverVersion;
            SSLExtension[] extTypes = {SSLExtension.HRR_SUPPORTED_VERSIONS};
            helloRetryRequest.extensions.consumeOnLoad(chc, extTypes);
            SupportedVersionsExtension.SHSupportedVersionsSpec svs = (SupportedVersionsExtension.SHSupportedVersionsSpec) chc.handshakeExtensions.get(SSLExtension.HRR_SUPPORTED_VERSIONS);
            if (svs != null) {
                serverVersion = ProtocolVersion.valueOf(svs.selectedVersion);
            } else {
                serverVersion = helloRetryRequest.serverVersion;
            }
            if (!chc.activeProtocols.contains(serverVersion)) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "The server selected protocol version " + serverVersion + " is not accepted by client preferences " + chc.activeProtocols);
            }
            if (!serverVersion.useTLS13PlusSpec()) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "Unexpected HelloRetryRequest for " + serverVersion.name);
            }
            chc.negotiatedProtocol = serverVersion;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Negotiated protocol version: " + serverVersion.name, new Object[0]);
            }
            chc.handshakePossessions.clear();
            if (serverVersion.isDTLS) {
                ServerHello.d13HrrHandshakeConsumer.consume(chc, helloRetryRequest);
            } else {
                ServerHello.t13HrrHandshakeConsumer.consume(chc, helloRetryRequest);
            }
        }

        private void onServerHello(ClientHandshakeContext chc, ServerHelloMessage serverHello) throws IOException {
            ProtocolVersion serverVersion;
            SSLExtension[] extTypes = {SSLExtension.SH_SUPPORTED_VERSIONS};
            serverHello.extensions.consumeOnLoad(chc, extTypes);
            SupportedVersionsExtension.SHSupportedVersionsSpec svs = (SupportedVersionsExtension.SHSupportedVersionsSpec) chc.handshakeExtensions.get(SSLExtension.SH_SUPPORTED_VERSIONS);
            if (svs != null) {
                serverVersion = ProtocolVersion.valueOf(svs.selectedVersion);
            } else {
                serverVersion = serverHello.serverVersion;
            }
            if (!chc.activeProtocols.contains(serverVersion)) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "The server selected protocol version " + serverVersion + " is not accepted by client preferences " + chc.activeProtocols);
            }
            chc.negotiatedProtocol = serverVersion;
            if (!chc.conContext.isNegotiated) {
                chc.conContext.protocolVersion = chc.negotiatedProtocol;
                chc.conContext.outputRecord.setVersion(chc.negotiatedProtocol);
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Negotiated protocol version: " + serverVersion.name, new Object[0]);
            }
            if (serverHello.serverRandom.isVersionDowngrade(chc)) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "A potential protocol version downgrade attack");
            }
            if (serverVersion.isDTLS) {
                if (serverVersion.useTLS13PlusSpec()) {
                    ServerHello.d13HandshakeConsumer.consume(chc, serverHello);
                    return;
                }
                chc.handshakePossessions.clear();
                ServerHello.d12HandshakeConsumer.consume(chc, serverHello);
            } else if (serverVersion.useTLS13PlusSpec()) {
                ServerHello.t13HandshakeConsumer.consume(chc, serverHello);
            } else {
                chc.handshakePossessions.clear();
                ServerHello.t12HandshakeConsumer.consume(chc, serverHello);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T12ServerHelloConsumer.class */
    private static final class T12ServerHelloConsumer implements HandshakeConsumer {
        private T12ServerHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            SSLHandshake[] relatedHandshakers;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            ServerHelloMessage serverHello = (ServerHelloMessage) message;
            if (!chc.isNegotiable(serverHello.serverVersion)) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "Server chose " + serverHello.serverVersion + ", but that protocol version is not enabled or not supported by the client.");
            }
            chc.negotiatedCipherSuite = serverHello.cipherSuite;
            chc.handshakeHash.determine(chc.negotiatedProtocol, chc.negotiatedCipherSuite);
            chc.serverHelloRandom = serverHello.serverRandom;
            if (chc.negotiatedCipherSuite.keyExchange == null) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "TLS 1.2 or prior version does not support the server cipher suite: " + chc.negotiatedCipherSuite.name);
            }
            serverHello.extensions.consumeOnLoad(chc, new SSLExtension[]{SSLExtension.SH_RENEGOTIATION_INFO});
            if (chc.resumingSession != null) {
                if (serverHello.sessionId.equals(chc.resumingSession.getSessionId())) {
                    CipherSuite sessionSuite = chc.resumingSession.getSuite();
                    if (chc.negotiatedCipherSuite != sessionSuite) {
                        throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "Server returned wrong cipher suite for session");
                    }
                    ProtocolVersion sessionVersion = chc.resumingSession.getProtocolVersion();
                    if (chc.negotiatedProtocol != sessionVersion) {
                        throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "Server resumed with wrong protocol version");
                    }
                    chc.isResumption = true;
                    chc.resumingSession.setAsSessionResumption(true);
                    chc.handshakeSession = chc.resumingSession;
                } else {
                    if (chc.resumingSession != null) {
                        chc.resumingSession.invalidate();
                        chc.resumingSession = null;
                    }
                    chc.isResumption = false;
                    if (!chc.sslConfig.enableSessionCreation) {
                        throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "New session creation is disabled");
                    }
                }
            }
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO);
            serverHello.extensions.consumeOnLoad(chc, extTypes);
            if (!chc.isResumption) {
                if (chc.resumingSession != null) {
                    chc.resumingSession.invalidate();
                    chc.resumingSession = null;
                }
                if (!chc.sslConfig.enableSessionCreation) {
                    throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "New session creation is disabled");
                }
                chc.handshakeSession = new SSLSessionImpl(chc, chc.negotiatedCipherSuite, serverHello.sessionId);
                chc.handshakeSession.setMaximumPacketSize(chc.sslConfig.maximumPacketSize);
            }
            serverHello.extensions.consumeOnTrade(chc, extTypes);
            if (chc.isResumption) {
                SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
                if (kdg == null) {
                    throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + chc.negotiatedProtocol);
                }
                chc.handshakeKeyDerivation = kdg.createKeyDerivation(chc, chc.resumingSession.getMasterSecret());
                chc.conContext.consumers.putIfAbsent(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id), ChangeCipherSpec.t10Consumer);
                chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
                return;
            }
            SSLKeyExchange ke = SSLKeyExchange.valueOf(chc.negotiatedCipherSuite.keyExchange, chc.negotiatedProtocol);
            chc.handshakeKeyExchange = ke;
            if (ke != null) {
                for (SSLHandshake handshake : ke.getRelatedHandshakers(chc)) {
                    chc.handshakeConsumers.put(Byte.valueOf(handshake.f987id), handshake);
                }
            }
            chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.SERVER_HELLO_DONE.f987id), SSLHandshake.SERVER_HELLO_DONE);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void setUpPskKD(HandshakeContext hc, SecretKey psk) throws SSLHandshakeException {
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
            SSLLogger.fine("Using PSK to derive early secret", new Object[0]);
        }
        try {
            CipherSuite.HashAlg hashAlg = hc.negotiatedCipherSuite.hashAlg;
            HKDF hkdf = new HKDF(hashAlg.name);
            byte[] zeros = new byte[hashAlg.hashLength];
            SecretKey earlySecret = hkdf.extract(zeros, psk, "TlsEarlySecret");
            hc.handshakeKeyDerivation = new SSLSecretDerivation(hc, earlySecret);
        } catch (GeneralSecurityException gse) {
            throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate secret").initCause(gse));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T13ServerHelloConsumer.class */
    private static final class T13ServerHelloConsumer implements HandshakeConsumer {
        private T13ServerHelloConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            ServerHelloMessage serverHello = (ServerHelloMessage) message;
            if (serverHello.serverVersion != ProtocolVersion.TLS12) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "The ServerHello.legacy_version field is not TLS 1.2");
            }
            chc.negotiatedCipherSuite = serverHello.cipherSuite;
            chc.handshakeHash.determine(chc.negotiatedProtocol, chc.negotiatedCipherSuite);
            chc.serverHelloRandom = serverHello.serverRandom;
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(SSLHandshake.SERVER_HELLO);
            serverHello.extensions.consumeOnLoad(chc, extTypes);
            if (!chc.isResumption) {
                if (chc.resumingSession != null) {
                    chc.resumingSession.invalidate();
                    chc.resumingSession = null;
                }
                if (!chc.sslConfig.enableSessionCreation) {
                    throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "New session creation is disabled");
                }
                chc.handshakeSession = new SSLSessionImpl(chc, chc.negotiatedCipherSuite, serverHello.sessionId);
                chc.handshakeSession.setMaximumPacketSize(chc.sslConfig.maximumPacketSize);
            } else {
                SecretKey psk = chc.resumingSession.consumePreSharedKey();
                if (psk == null) {
                    throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "No PSK available. Unable to resume.");
                }
                chc.handshakeSession = chc.resumingSession;
                ServerHello.setUpPskKD(chc, psk);
            }
            serverHello.extensions.consumeOnTrade(chc, extTypes);
            chc.handshakeHash.update();
            SSLKeyExchange ke = chc.handshakeKeyExchange;
            if (ke == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Not negotiated key shares");
            }
            SSLKeyDerivation handshakeKD = ke.createKeyDerivation(chc);
            SecretKey handshakeSecret = handshakeKD.deriveKey("TlsHandshakeSecret", null);
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
            if (kdg == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + chc.negotiatedProtocol);
            }
            SSLKeyDerivation secretKD = new SSLSecretDerivation(chc, handshakeSecret);
            SecretKey readSecret = secretKD.deriveKey("TlsServerHandshakeTrafficSecret", null);
            SSLKeyDerivation readKD = kdg.createKeyDerivation(chc, readSecret);
            SecretKey readKey = readKD.deriveKey("TlsKey", null);
            SecretKey readIvSecret = readKD.deriveKey("TlsIv", null);
            IvParameterSpec readIv = new IvParameterSpec(readIvSecret.getEncoded());
            try {
                SSLCipher.SSLReadCipher readCipher = chc.negotiatedCipherSuite.bulkCipher.createReadCipher(Authenticator.valueOf(chc.negotiatedProtocol), chc.negotiatedProtocol, readKey, readIv, chc.sslContext.getSecureRandom());
                if (readCipher == null) {
                    throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + chc.negotiatedCipherSuite + ") and protocol version (" + chc.negotiatedProtocol + ")");
                }
                chc.baseReadSecret = readSecret;
                chc.conContext.inputRecord.changeReadCiphers(readCipher);
                SecretKey writeSecret = secretKD.deriveKey("TlsClientHandshakeTrafficSecret", null);
                SSLKeyDerivation writeKD = kdg.createKeyDerivation(chc, writeSecret);
                SecretKey writeKey = writeKD.deriveKey("TlsKey", null);
                SecretKey writeIvSecret = writeKD.deriveKey("TlsIv", null);
                IvParameterSpec writeIv = new IvParameterSpec(writeIvSecret.getEncoded());
                try {
                    SSLCipher.SSLWriteCipher writeCipher = chc.negotiatedCipherSuite.bulkCipher.createWriteCipher(Authenticator.valueOf(chc.negotiatedProtocol), chc.negotiatedProtocol, writeKey, writeIv, chc.sslContext.getSecureRandom());
                    if (writeCipher == null) {
                        throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + chc.negotiatedCipherSuite + ") and protocol version (" + chc.negotiatedProtocol + ")");
                    }
                    chc.baseWriteSecret = writeSecret;
                    chc.conContext.outputRecord.changeWriteCiphers(writeCipher, serverHello.sessionId.length() != 0);
                    chc.handshakeKeyDerivation = secretKD;
                    chc.conContext.consumers.putIfAbsent(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id), ChangeCipherSpec.t13Consumer);
                    chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.ENCRYPTED_EXTENSIONS.f987id), SSLHandshake.ENCRYPTED_EXTENSIONS);
                    chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_REQUEST.f987id), SSLHandshake.CERTIFICATE_REQUEST);
                    chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
                    chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
                    chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
                } catch (GeneralSecurityException gse) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", gse);
                }
            } catch (GeneralSecurityException gse2) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing cipher algorithm", gse2);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHello$T13HelloRetryRequestConsumer.class */
    private static final class T13HelloRetryRequestConsumer implements HandshakeConsumer {
        private T13HelloRetryRequestConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            ServerHelloMessage helloRetryRequest = (ServerHelloMessage) message;
            if (helloRetryRequest.serverVersion != ProtocolVersion.TLS12) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION, "The HelloRetryRequest.legacy_version is not TLS 1.2");
            }
            chc.negotiatedCipherSuite = helloRetryRequest.cipherSuite;
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(SSLHandshake.HELLO_RETRY_REQUEST);
            helloRetryRequest.extensions.consumeOnLoad(chc, extTypes);
            helloRetryRequest.extensions.consumeOnTrade(chc, extTypes);
            chc.handshakeHash.finish();
            HandshakeOutStream hos = new HandshakeOutStream(null);
            try {
                chc.initialClientHelloMsg.write(hos);
                chc.handshakeHash.deliver(hos.toByteArray());
                chc.handshakeHash.determine(chc.negotiatedProtocol, chc.negotiatedCipherSuite);
                byte[] clientHelloHash = chc.handshakeHash.digest();
                int hashLen = chc.negotiatedCipherSuite.hashAlg.hashLength;
                byte[] hashedClientHello = new byte[4 + hashLen];
                hashedClientHello[0] = SSLHandshake.MESSAGE_HASH.f987id;
                hashedClientHello[1] = 0;
                hashedClientHello[2] = 0;
                hashedClientHello[3] = (byte) (hashLen & GF2Field.MASK);
                System.arraycopy(clientHelloHash, 0, hashedClientHello, 4, hashLen);
                chc.handshakeHash.finish();
                chc.handshakeHash.deliver(hashedClientHello);
                int hrrBodyLen = helloRetryRequest.handshakeRecord.remaining();
                byte[] hrrMessage = new byte[4 + hrrBodyLen];
                hrrMessage[0] = SSLHandshake.HELLO_RETRY_REQUEST.f987id;
                hrrMessage[1] = (byte) ((hrrBodyLen >> 16) & GF2Field.MASK);
                hrrMessage[2] = (byte) ((hrrBodyLen >> 8) & GF2Field.MASK);
                hrrMessage[3] = (byte) (hrrBodyLen & GF2Field.MASK);
                ByteBuffer hrrBody = helloRetryRequest.handshakeRecord.duplicate();
                hrrBody.get(hrrMessage, 4, hrrBodyLen);
                chc.handshakeHash.receive(hrrMessage);
                chc.initialClientHelloMsg.extensions.reproduce(chc, new SSLExtension[]{SSLExtension.CH_COOKIE, SSLExtension.CH_KEY_SHARE, SSLExtension.CH_PRE_SHARED_KEY});
                SSLHandshake.CLIENT_HELLO.produce(context, helloRetryRequest);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Failed to construct message hash", ioe);
            }
        }
    }
}