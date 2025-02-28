package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmConstraints;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.ECDHKeyExchange;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.ssl.X509Authentication;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHClientKeyExchange.class */
final class ECDHClientKeyExchange {
    static final SSLConsumer ecdhHandshakeConsumer = new ECDHClientKeyExchangeConsumer();
    static final HandshakeProducer ecdhHandshakeProducer = new ECDHClientKeyExchangeProducer();
    static final SSLConsumer ecdheHandshakeConsumer = new ECDHEClientKeyExchangeConsumer();
    static final HandshakeProducer ecdheHandshakeProducer = new ECDHEClientKeyExchangeProducer();

    ECDHClientKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHClientKeyExchange$ECDHClientKeyExchangeMessage.class */
    private static final class ECDHClientKeyExchangeMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] encodedPoint;

        ECDHClientKeyExchangeMessage(HandshakeContext handshakeContext, ECPublicKey publicKey) {
            super(handshakeContext);
            ECPoint point = publicKey.getW();
            ECParameterSpec params = publicKey.getParams();
            this.encodedPoint = JsseJce.encodePoint(point, params.getCurve());
        }

        ECDHClientKeyExchangeMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.remaining() != 0) {
                this.encodedPoint = Record.getBytes8(m);
            } else {
                this.encodedPoint = new byte[0];
            }
        }

        static void checkConstraints(AlgorithmConstraints constraints, ECPublicKey publicKey, byte[] encodedPoint) throws SSLHandshakeException {
            try {
                ECParameterSpec params = publicKey.getParams();
                ECPoint point = JsseJce.decodePoint(encodedPoint, params.getCurve());
                ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
                KeyFactory kf = JsseJce.getKeyFactory("EC");
                ECPublicKey peerPublicKey = (ECPublicKey) kf.generatePublic(spec);
                if (!constraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), peerPublicKey)) {
                    throw new SSLHandshakeException("ECPublicKey does not comply to algorithm constraints");
                }
            } catch (IOException | GeneralSecurityException e) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate ECPublicKey").initCause(e));
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_KEY_EXCHANGE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            if (this.encodedPoint == null || this.encodedPoint.length == 0) {
                return 0;
            }
            return 1 + this.encodedPoint.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            if (this.encodedPoint != null && this.encodedPoint.length != 0) {
                hos.putBytes8(this.encodedPoint);
            }
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"ECDH ClientKeyExchange\": '{'\n  \"ecdh public\": '{'\n{0}\n  '}',\n'}'", Locale.ENGLISH);
            if (this.encodedPoint == null || this.encodedPoint.length == 0) {
                Object[] messageFields = {"    <implicit>"};
                return messageFormat.format(messageFields);
            }
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields2 = {Utilities.indent(hexEncoder.encodeBuffer(this.encodedPoint), "    ")};
            return messageFormat.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHClientKeyExchange$ECDHClientKeyExchangeProducer.class */
    private static final class ECDHClientKeyExchangeProducer implements HandshakeProducer {
        private ECDHClientKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            X509Authentication.X509Credentials x509Credentials = null;
            Iterator<SSLCredentials> it = chc.handshakeCredentials.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLCredentials credential = it.next();
                if (credential instanceof X509Authentication.X509Credentials) {
                    x509Credentials = (X509Authentication.X509Credentials) credential;
                    break;
                }
            }
            if (x509Credentials == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "No server certificate for ECDH client key exchange");
            }
            PublicKey publicKey = x509Credentials.popPublicKey;
            if (!publicKey.getAlgorithm().equals("EC")) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Not EC server certificate for ECDH client key exchange");
            }
            ECParameterSpec params = ((ECPublicKey) publicKey).getParams();
            SupportedGroupsExtension.NamedGroup namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(params);
            if (namedGroup == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unsupported EC server cert for ECDH client key exchange");
            }
            ECDHKeyExchange.ECDHEPossession ecdhePossession = new ECDHKeyExchange.ECDHEPossession(namedGroup, chc.sslContext.getSecureRandom());
            chc.handshakePossessions.add(ecdhePossession);
            ECDHClientKeyExchangeMessage cke = new ECDHClientKeyExchangeMessage(chc, ecdhePossession.publicKey);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ECDH ClientKeyExchange handshake message", cke);
            }
            cke.write(chc.handshakeOutput);
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

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHClientKeyExchange$ECDHClientKeyExchangeConsumer.class */
    private static final class ECDHClientKeyExchangeConsumer implements SSLConsumer {
        private ECDHClientKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = shc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession possession = it.next();
                if (possession instanceof X509Authentication.X509Possession) {
                    x509Possession = (X509Authentication.X509Possession) possession;
                    break;
                }
            }
            if (x509Possession == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "No expected EC server cert for ECDH client key exchange");
            }
            ECParameterSpec params = x509Possession.getECParameterSpec();
            if (params == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Not EC server cert for ECDH client key exchange");
            }
            SupportedGroupsExtension.NamedGroup namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(params);
            if (namedGroup == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unsupported EC server cert for ECDH client key exchange");
            }
            SSLKeyExchange ke = SSLKeyExchange.valueOf(shc.negotiatedCipherSuite.keyExchange, shc.negotiatedProtocol);
            if (ke == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key exchange type");
            }
            ECDHClientKeyExchangeMessage cke = new ECDHClientKeyExchangeMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ECDH ClientKeyExchange handshake message", cke);
            }
            try {
                ECPoint point = JsseJce.decodePoint(cke.encodedPoint, params.getCurve());
                ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
                KeyFactory kf = JsseJce.getKeyFactory("EC");
                ECPublicKey peerPublicKey = (ECPublicKey) kf.generatePublic(spec);
                if (!shc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), peerPublicKey)) {
                    throw new SSLHandshakeException("ECPublicKey does not comply to algorithm constraints");
                }
                shc.handshakeCredentials.add(new ECDHKeyExchange.ECDHECredentials(peerPublicKey, namedGroup));
                SSLKeyDerivation masterKD = ke.createKeyDerivation(shc);
                SecretKey masterSecret = masterKD.deriveKey("MasterSecret", null);
                shc.handshakeSession.setMasterSecret(masterSecret);
                SSLTrafficKeyDerivation kd = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
                if (kd == null) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
                }
                shc.handshakeKeyDerivation = kd.createKeyDerivation(shc, masterSecret);
            } catch (IOException | GeneralSecurityException e) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate ECPublicKey").initCause(e));
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHClientKeyExchange$ECDHEClientKeyExchangeProducer.class */
    private static final class ECDHEClientKeyExchangeProducer implements HandshakeProducer {
        private ECDHEClientKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            ECDHKeyExchange.ECDHECredentials ecdheCredentials = null;
            Iterator<SSLCredentials> it = chc.handshakeCredentials.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLCredentials cd = it.next();
                if (cd instanceof ECDHKeyExchange.ECDHECredentials) {
                    ecdheCredentials = (ECDHKeyExchange.ECDHECredentials) cd;
                    break;
                }
            }
            if (ecdheCredentials == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "No ECDHE credentials negotiated for client key exchange");
            }
            ECDHKeyExchange.ECDHEPossession ecdhePossession = new ECDHKeyExchange.ECDHEPossession(ecdheCredentials, chc.sslContext.getSecureRandom());
            chc.handshakePossessions.add(ecdhePossession);
            ECDHClientKeyExchangeMessage cke = new ECDHClientKeyExchangeMessage(chc, ecdhePossession.publicKey);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ECDHE ClientKeyExchange handshake message", cke);
            }
            cke.write(chc.handshakeOutput);
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

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHClientKeyExchange$ECDHEClientKeyExchangeConsumer.class */
    private static final class ECDHEClientKeyExchangeConsumer implements SSLConsumer {
        private ECDHEClientKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ECDHKeyExchange.ECDHEPossession ecdhePossession = null;
            Iterator<SSLPossession> it = shc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession possession = it.next();
                if (possession instanceof ECDHKeyExchange.ECDHEPossession) {
                    ecdhePossession = (ECDHKeyExchange.ECDHEPossession) possession;
                    break;
                }
            }
            if (ecdhePossession == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "No expected ECDHE possessions for client key exchange");
            }
            ECParameterSpec params = ecdhePossession.publicKey.getParams();
            SupportedGroupsExtension.NamedGroup namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(params);
            if (namedGroup == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unsupported EC server cert for ECDHE client key exchange");
            }
            SSLKeyExchange ke = SSLKeyExchange.valueOf(shc.negotiatedCipherSuite.keyExchange, shc.negotiatedProtocol);
            if (ke == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key exchange type");
            }
            ECDHClientKeyExchangeMessage cke = new ECDHClientKeyExchangeMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ECDHE ClientKeyExchange handshake message", cke);
            }
            try {
                ECPoint point = JsseJce.decodePoint(cke.encodedPoint, params.getCurve());
                ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
                KeyFactory kf = JsseJce.getKeyFactory("EC");
                ECPublicKey peerPublicKey = (ECPublicKey) kf.generatePublic(spec);
                if (!shc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), peerPublicKey)) {
                    throw new SSLHandshakeException("ECPublicKey does not comply to algorithm constraints");
                }
                shc.handshakeCredentials.add(new ECDHKeyExchange.ECDHECredentials(peerPublicKey, namedGroup));
                SSLKeyDerivation masterKD = ke.createKeyDerivation(shc);
                SecretKey masterSecret = masterKD.deriveKey("MasterSecret", null);
                shc.handshakeSession.setMasterSecret(masterSecret);
                SSLTrafficKeyDerivation kd = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
                if (kd == null) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
                }
                shc.handshakeKeyDerivation = kd.createKeyDerivation(shc, masterSecret);
            } catch (IOException | GeneralSecurityException e) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate ECPublicKey").initCause(e));
            }
        }
    }
}