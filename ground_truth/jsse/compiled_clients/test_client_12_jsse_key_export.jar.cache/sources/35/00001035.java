package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.DHKeyExchange;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHClientKeyExchange.class */
final class DHClientKeyExchange {
    static final DHClientKeyExchangeConsumer dhHandshakeConsumer = new DHClientKeyExchangeConsumer();
    static final DHClientKeyExchangeProducer dhHandshakeProducer = new DHClientKeyExchangeProducer();

    DHClientKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHClientKeyExchange$DHClientKeyExchangeMessage.class */
    private static final class DHClientKeyExchangeMessage extends SSLHandshake.HandshakeMessage {

        /* renamed from: y */
        private byte[] f966y;

        DHClientKeyExchangeMessage(HandshakeContext handshakeContext) throws IOException {
            super(handshakeContext);
            ClientHandshakeContext chc = (ClientHandshakeContext) handshakeContext;
            DHKeyExchange.DHEPossession dhePossession = null;
            Iterator<SSLPossession> it = chc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession possession = it.next();
                if (possession instanceof DHKeyExchange.DHEPossession) {
                    dhePossession = (DHKeyExchange.DHEPossession) possession;
                    break;
                }
            }
            if (dhePossession == null) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No DHE credentials negotiated for client key exchange");
            }
            DHPublicKey publicKey = dhePossession.publicKey;
            publicKey.getParams();
            this.f966y = Utilities.toByteArray(publicKey.getY());
        }

        DHClientKeyExchangeMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            ServerHandshakeContext shc = (ServerHandshakeContext) handshakeContext;
            if (m.remaining() < 3) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid DH ClientKeyExchange message: insufficient data");
            }
            this.f966y = Record.getBytes16(m);
            if (m.hasRemaining()) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid DH ClientKeyExchange message: unknown extra data");
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_KEY_EXCHANGE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return this.f966y.length + 2;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes16(this.f966y);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"DH ClientKeyExchange\": '{'\n  \"parameters\": '{'\n    \"dh_Yc\": '{'\n{0}\n    '}',\n  '}'\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {Utilities.indent(hexEncoder.encodeBuffer(this.f966y), "      ")};
            return messageFormat.format(messageFields);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHClientKeyExchange$DHClientKeyExchangeProducer.class */
    public static final class DHClientKeyExchangeProducer implements HandshakeProducer {
        private DHClientKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            DHKeyExchange.DHECredentials dheCredentials = null;
            Iterator<SSLCredentials> it = chc.handshakeCredentials.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLCredentials cd = it.next();
                if (cd instanceof DHKeyExchange.DHECredentials) {
                    dheCredentials = (DHKeyExchange.DHECredentials) cd;
                    break;
                }
            }
            if (dheCredentials == null) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No DHE credentials negotiated for client key exchange");
            }
            DHKeyExchange.DHEPossession dhePossession = new DHKeyExchange.DHEPossession(dheCredentials, chc.sslContext.getSecureRandom());
            chc.handshakePossessions.add(dhePossession);
            DHClientKeyExchangeMessage ckem = new DHClientKeyExchangeMessage(chc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced DH ClientKeyExchange handshake message", ckem);
            }
            ckem.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            SSLKeyExchange ke = SSLKeyExchange.valueOf(chc.negotiatedCipherSuite.keyExchange, chc.negotiatedProtocol);
            if (ke == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key exchange type");
            }
            SSLKeyDerivation masterKD = ke.createKeyDerivation(chc);
            SecretKey masterSecret = masterKD.deriveKey("MasterSecret", null);
            chc.handshakeSession.setMasterSecret(masterSecret);
            SSLTrafficKeyDerivation kd = SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
            if (kd == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + chc.negotiatedProtocol);
            }
            chc.handshakeKeyDerivation = kd.createKeyDerivation(chc, masterSecret);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHClientKeyExchange$DHClientKeyExchangeConsumer.class */
    public static final class DHClientKeyExchangeConsumer implements SSLConsumer {
        private DHClientKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            DHKeyExchange.DHEPossession dhePossession = null;
            Iterator<SSLPossession> it = shc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession possession = it.next();
                if (possession instanceof DHKeyExchange.DHEPossession) {
                    dhePossession = (DHKeyExchange.DHEPossession) possession;
                    break;
                }
            }
            if (dhePossession == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No expected DHE possessions for client key exchange");
            }
            SSLKeyExchange ke = SSLKeyExchange.valueOf(shc.negotiatedCipherSuite.keyExchange, shc.negotiatedProtocol);
            if (ke == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key exchange type");
            }
            DHClientKeyExchangeMessage ckem = new DHClientKeyExchangeMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming DH ClientKeyExchange handshake message", ckem);
            }
            try {
                DHParameterSpec params = dhePossession.publicKey.getParams();
                DHPublicKeySpec spec = new DHPublicKeySpec(new BigInteger(1, ckem.f966y), params.getP(), params.getG());
                KeyFactory kf = JsseJce.getKeyFactory("DiffieHellman");
                DHPublicKey peerPublicKey = (DHPublicKey) kf.generatePublic(spec);
                if (!shc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), peerPublicKey)) {
                    throw new SSLHandshakeException("DHPublicKey does not comply to algorithm constraints");
                }
                SupportedGroupsExtension.NamedGroup namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(params);
                shc.handshakeCredentials.add(new DHKeyExchange.DHECredentials(peerPublicKey, namedGroup));
                SSLKeyDerivation masterKD = ke.createKeyDerivation(shc);
                SecretKey masterSecret = masterKD.deriveKey("MasterSecret", null);
                shc.handshakeSession.setMasterSecret(masterSecret);
                SSLTrafficKeyDerivation kd = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
                if (kd == null) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
                }
                shc.handshakeKeyDerivation = kd.createKeyDerivation(shc, masterSecret);
            } catch (IOException | GeneralSecurityException e) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate DHPublicKey").initCause(e));
            }
        }
    }
}