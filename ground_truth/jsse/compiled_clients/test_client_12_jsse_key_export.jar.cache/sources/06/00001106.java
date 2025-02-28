package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.MessageFormat;
import java.util.Iterator;
import java.util.Locale;
import javax.crypto.SecretKey;
import org.openjsse.sun.security.ssl.RSAKeyExchange;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.X509Authentication;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAClientKeyExchange.class */
final class RSAClientKeyExchange {
    static final SSLConsumer rsaHandshakeConsumer = new RSAClientKeyExchangeConsumer();
    static final HandshakeProducer rsaHandshakeProducer = new RSAClientKeyExchangeProducer();

    RSAClientKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAClientKeyExchange$RSAClientKeyExchangeMessage.class */
    private static final class RSAClientKeyExchangeMessage extends SSLHandshake.HandshakeMessage {
        final int protocolVersion;
        final boolean useTLS10PlusSpec;
        final byte[] encrypted;

        RSAClientKeyExchangeMessage(HandshakeContext context, RSAKeyExchange.RSAPremasterSecret premaster, PublicKey publicKey) throws GeneralSecurityException {
            super(context);
            this.protocolVersion = context.clientHelloVersion;
            this.encrypted = premaster.getEncoded(publicKey, context.sslContext.getSecureRandom());
            this.useTLS10PlusSpec = ProtocolVersion.useTLS10PlusSpec(this.protocolVersion, context.sslContext.isDTLS());
        }

        RSAClientKeyExchangeMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            if (m.remaining() < 2) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid RSA ClientKeyExchange message: insufficient data");
            }
            this.protocolVersion = context.clientHelloVersion;
            this.useTLS10PlusSpec = ProtocolVersion.useTLS10PlusSpec(this.protocolVersion, context.sslContext.isDTLS());
            if (this.useTLS10PlusSpec) {
                this.encrypted = Record.getBytes16(m);
                return;
            }
            this.encrypted = new byte[m.remaining()];
            m.get(this.encrypted);
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_KEY_EXCHANGE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            if (this.useTLS10PlusSpec) {
                return this.encrypted.length + 2;
            }
            return this.encrypted.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            if (this.useTLS10PlusSpec) {
                hos.putBytes16(this.encrypted);
            } else {
                hos.write(this.encrypted);
            }
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"RSA ClientKeyExchange\": '{'\n  \"client_version\":  {0}\n  \"encncrypted\": '{'\n{1}\n  '}'\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {ProtocolVersion.nameOf(this.protocolVersion), Utilities.indent(hexEncoder.encodeBuffer(this.encrypted), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAClientKeyExchange$RSAClientKeyExchangeProducer.class */
    private static final class RSAClientKeyExchangeProducer implements HandshakeProducer {
        private RSAClientKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            RSAKeyExchange.EphemeralRSACredentials rsaCredentials = null;
            X509Authentication.X509Credentials x509Credentials = null;
            for (SSLCredentials credential : chc.handshakeCredentials) {
                if (credential instanceof RSAKeyExchange.EphemeralRSACredentials) {
                    rsaCredentials = (RSAKeyExchange.EphemeralRSACredentials) credential;
                    if (x509Credentials != null) {
                        break;
                    }
                } else if (credential instanceof X509Authentication.X509Credentials) {
                    x509Credentials = (X509Authentication.X509Credentials) credential;
                    if (rsaCredentials != null) {
                        break;
                    }
                } else {
                    continue;
                }
            }
            if (rsaCredentials == null && x509Credentials == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No RSA credentials negotiated for client key exchange");
            }
            PublicKey publicKey = rsaCredentials != null ? rsaCredentials.popPublicKey : x509Credentials.popPublicKey;
            if (!publicKey.getAlgorithm().equals("RSA")) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Not RSA public key for client key exchange");
            }
            try {
                RSAKeyExchange.RSAPremasterSecret premaster = RSAKeyExchange.RSAPremasterSecret.createPremasterSecret(chc);
                chc.handshakePossessions.add(premaster);
                RSAClientKeyExchangeMessage ckem = new RSAClientKeyExchangeMessage(chc, premaster, publicKey);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Produced RSA ClientKeyExchange handshake message", ckem);
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
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Cannot generate RSA premaster secret", gse);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAClientKeyExchange$RSAClientKeyExchangeConsumer.class */
    private static final class RSAClientKeyExchangeConsumer implements SSLConsumer {
        private RSAClientKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            RSAKeyExchange.EphemeralRSAPossession rsaPossession = null;
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = shc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession possession = it.next();
                if (possession instanceof RSAKeyExchange.EphemeralRSAPossession) {
                    rsaPossession = (RSAKeyExchange.EphemeralRSAPossession) possession;
                    break;
                } else if (possession instanceof X509Authentication.X509Possession) {
                    x509Possession = (X509Authentication.X509Possession) possession;
                    if (0 != 0) {
                        break;
                    }
                }
            }
            if (rsaPossession == null && x509Possession == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No RSA possessions negotiated for client key exchange");
            }
            PrivateKey privateKey = rsaPossession != null ? rsaPossession.popPrivateKey : x509Possession.popPrivateKey;
            if (!privateKey.getAlgorithm().equals("RSA")) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Not RSA private key for client key exchange");
            }
            RSAClientKeyExchangeMessage ckem = new RSAClientKeyExchangeMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming RSA ClientKeyExchange handshake message", ckem);
            }
            try {
                RSAKeyExchange.RSAPremasterSecret premaster = RSAKeyExchange.RSAPremasterSecret.decode(shc, privateKey, ckem.encrypted);
                shc.handshakeCredentials.add(premaster);
                SSLKeyExchange ke = SSLKeyExchange.valueOf(shc.negotiatedCipherSuite.keyExchange, shc.negotiatedProtocol);
                if (ke == null) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key exchange type");
                }
                SSLKeyDerivation masterKD = ke.createKeyDerivation(shc);
                SecretKey masterSecret = masterKD.deriveKey("MasterSecret", null);
                shc.handshakeSession.setMasterSecret(masterSecret);
                SSLTrafficKeyDerivation kd = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
                if (kd == null) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
                }
                shc.handshakeKeyDerivation = kd.createKeyDerivation(shc, masterSecret);
            } catch (GeneralSecurityException gse) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Cannot decode RSA premaster secret", gse);
            }
        }
    }
}