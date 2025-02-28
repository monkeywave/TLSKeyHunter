package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Locale;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.RSAKeyExchange;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.X509Authentication;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAServerKeyExchange.class */
final class RSAServerKeyExchange {
    static final SSLConsumer rsaHandshakeConsumer = new RSAServerKeyExchangeConsumer();
    static final HandshakeProducer rsaHandshakeProducer = new RSAServerKeyExchangeProducer();

    RSAServerKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAServerKeyExchange$RSAServerKeyExchangeMessage.class */
    private static final class RSAServerKeyExchangeMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] modulus;
        private final byte[] exponent;
        private final byte[] paramsSignature;

        private RSAServerKeyExchangeMessage(HandshakeContext handshakeContext, X509Authentication.X509Possession x509Possession, RSAKeyExchange.EphemeralRSAPossession rsaPossession) throws IOException {
            super(handshakeContext);
            ServerHandshakeContext shc = (ServerHandshakeContext) handshakeContext;
            RSAPublicKey publicKey = rsaPossession.popPublicKey;
            RSAPublicKeySpec spec = JsseJce.getRSAPublicKeySpec(publicKey);
            this.modulus = Utilities.toByteArray(spec.getModulus());
            this.exponent = Utilities.toByteArray(spec.getPublicExponent());
            try {
                Signature signer = RSASignature.getInstance();
                signer.initSign(x509Possession.popPrivateKey, shc.sslContext.getSecureRandom());
                updateSignature(signer, shc.clientHelloRandom.randomBytes, shc.serverHelloRandom.randomBytes);
                byte[] signature = signer.sign();
                this.paramsSignature = signature;
            } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Failed to sign ephemeral RSA parameters", ex);
            }
        }

        RSAServerKeyExchangeMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            ClientHandshakeContext chc = (ClientHandshakeContext) handshakeContext;
            this.modulus = Record.getBytes16(m);
            this.exponent = Record.getBytes16(m);
            this.paramsSignature = Record.getBytes16(m);
            X509Authentication.X509Credentials x509Credentials = null;
            Iterator<SSLCredentials> it = chc.handshakeCredentials.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLCredentials cd = it.next();
                if (cd instanceof X509Authentication.X509Credentials) {
                    x509Credentials = (X509Authentication.X509Credentials) cd;
                    break;
                }
            }
            if (x509Credentials == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No RSA credentials negotiated for server key exchange");
            }
            try {
                Signature signer = RSASignature.getInstance();
                signer.initVerify(x509Credentials.popPublicKey);
                updateSignature(signer, chc.clientHelloRandom.randomBytes, chc.serverHelloRandom.randomBytes);
                if (!signer.verify(this.paramsSignature)) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid signature of RSA ServerKeyExchange message");
                }
            } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Failed to sign ephemeral RSA parameters", ex);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.SERVER_KEY_EXCHANGE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        int messageLength() {
            return 6 + this.modulus.length + this.exponent.length + this.paramsSignature.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes16(this.modulus);
            hos.putBytes16(this.exponent);
            hos.putBytes16(this.paramsSignature);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"RSA ServerKeyExchange\": '{'\n  \"parameters\": '{'\n    \"rsa_modulus\": '{'\n{0}\n    '}',\n    \"rsa_exponent\": '{'\n{1}\n    '}'\n  '}',\n  \"digital signature\":  '{'\n    \"signature\": '{'\n{2}\n    '}',\n  '}'\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {Utilities.indent(hexEncoder.encodeBuffer(this.modulus), "      "), Utilities.indent(hexEncoder.encodeBuffer(this.exponent), "      "), Utilities.indent(hexEncoder.encodeBuffer(this.paramsSignature), "      ")};
            return messageFormat.format(messageFields);
        }

        private void updateSignature(Signature signature, byte[] clntNonce, byte[] svrNonce) throws SignatureException {
            signature.update(clntNonce);
            signature.update(svrNonce);
            signature.update((byte) (this.modulus.length >> 8));
            signature.update((byte) (this.modulus.length & GF2Field.MASK));
            signature.update(this.modulus);
            signature.update((byte) (this.exponent.length >> 8));
            signature.update((byte) (this.exponent.length & GF2Field.MASK));
            signature.update(this.exponent);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAServerKeyExchange$RSAServerKeyExchangeProducer.class */
    private static final class RSAServerKeyExchangeProducer implements HandshakeProducer {
        private RSAServerKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            RSAKeyExchange.EphemeralRSAPossession rsaPossession = null;
            X509Authentication.X509Possession x509Possession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof RSAKeyExchange.EphemeralRSAPossession) {
                    rsaPossession = (RSAKeyExchange.EphemeralRSAPossession) possession;
                    if (x509Possession != null) {
                        break;
                    }
                } else if (possession instanceof X509Authentication.X509Possession) {
                    x509Possession = (X509Authentication.X509Possession) possession;
                    if (rsaPossession != null) {
                        break;
                    }
                } else {
                    continue;
                }
            }
            if (rsaPossession == null) {
                return null;
            }
            if (x509Possession == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No RSA certificate negotiated for server key exchange");
            }
            if (!"RSA".equals(x509Possession.popPrivateKey.getAlgorithm())) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No X.509 possession can be used for ephemeral RSA ServerKeyExchange");
            }
            RSAServerKeyExchangeMessage skem = new RSAServerKeyExchangeMessage(shc, x509Possession, rsaPossession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced RSA ServerKeyExchange handshake message", skem);
            }
            skem.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RSAServerKeyExchange$RSAServerKeyExchangeConsumer.class */
    private static final class RSAServerKeyExchangeConsumer implements SSLConsumer {
        private RSAServerKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            RSAServerKeyExchangeMessage skem = new RSAServerKeyExchangeMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming RSA ServerKeyExchange handshake message", skem);
            }
            try {
                KeyFactory kf = JsseJce.getKeyFactory("RSA");
                RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, skem.modulus), new BigInteger(1, skem.exponent));
                RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(spec);
                if (!chc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), publicKey)) {
                    throw chc.conContext.fatal(Alert.INSUFFICIENT_SECURITY, "RSA ServerKeyExchange does not comply to algorithm constraints");
                }
                chc.handshakeCredentials.add(new RSAKeyExchange.EphemeralRSACredentials(publicKey));
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.INSUFFICIENT_SECURITY, "Could not generate RSAPublicKey", gse);
            }
        }
    }
}