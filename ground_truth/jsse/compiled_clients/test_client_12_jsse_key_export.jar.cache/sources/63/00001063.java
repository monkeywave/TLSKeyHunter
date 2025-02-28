package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.CryptoPrimitive;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.ECDHKeyExchange;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.ssl.X509Authentication;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHServerKeyExchange.class */
final class ECDHServerKeyExchange {
    static final SSLConsumer ecdheHandshakeConsumer = new ECDHServerKeyExchangeConsumer();
    static final HandshakeProducer ecdheHandshakeProducer = new ECDHServerKeyExchangeProducer();

    ECDHServerKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHServerKeyExchange$ECDHServerKeyExchangeMessage.class */
    private static final class ECDHServerKeyExchangeMessage extends SSLHandshake.HandshakeMessage {
        private static final byte CURVE_NAMED_CURVE = 3;
        private final SupportedGroupsExtension.NamedGroup namedGroup;
        private final byte[] publicPoint;
        private final byte[] paramsSignature;
        private final ECPublicKey publicKey;
        private final boolean useExplicitSigAlgorithm;
        private final SignatureScheme signatureScheme;

        ECDHServerKeyExchangeMessage(HandshakeContext handshakeContext) throws IOException {
            super(handshakeContext);
            Signature signer;
            ServerHandshakeContext shc = (ServerHandshakeContext) handshakeContext;
            ECDHKeyExchange.ECDHEPossession ecdhePossession = null;
            X509Authentication.X509Possession x509Possession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof ECDHKeyExchange.ECDHEPossession) {
                    ecdhePossession = (ECDHKeyExchange.ECDHEPossession) possession;
                    if (x509Possession != null) {
                        break;
                    }
                } else if (possession instanceof X509Authentication.X509Possession) {
                    x509Possession = (X509Authentication.X509Possession) possession;
                    if (ecdhePossession != null) {
                        break;
                    }
                } else {
                    continue;
                }
            }
            if (ecdhePossession == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No ECDHE credentials negotiated for server key exchange");
            }
            this.publicKey = ecdhePossession.publicKey;
            ECParameterSpec params = this.publicKey.getParams();
            ECPoint point = this.publicKey.getW();
            this.publicPoint = JsseJce.encodePoint(point, params.getCurve());
            this.namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(params);
            if (this.namedGroup == null || this.namedGroup.oid == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unnamed EC parameter spec: " + params);
            }
            if (x509Possession == null) {
                this.paramsSignature = null;
                this.signatureScheme = null;
                this.useExplicitSigAlgorithm = false;
                return;
            }
            this.useExplicitSigAlgorithm = shc.negotiatedProtocol.useTLS12PlusSpec();
            if (this.useExplicitSigAlgorithm) {
                Map.Entry<SignatureScheme, Signature> schemeAndSigner = SignatureScheme.getSignerOfPreferableAlgorithm(shc.peerRequestedSignatureSchemes, x509Possession, shc.negotiatedProtocol);
                if (schemeAndSigner == null) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "No supported signature algorithm for " + x509Possession.popPrivateKey.getAlgorithm() + "  key");
                }
                this.signatureScheme = schemeAndSigner.getKey();
                signer = schemeAndSigner.getValue();
            } else {
                this.signatureScheme = null;
                try {
                    signer = getSignature(x509Possession.popPrivateKey.getAlgorithm(), x509Possession.popPrivateKey);
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm: " + x509Possession.popPrivateKey.getAlgorithm(), e);
                }
            }
            try {
                updateSignature(signer, shc.clientHelloRandom.randomBytes, shc.serverHelloRandom.randomBytes, this.namedGroup.f1009id, this.publicPoint);
                byte[] signature = signer.sign();
                this.paramsSignature = signature;
            } catch (SignatureException ex) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Failed to sign ecdhe parameters: " + x509Possession.popPrivateKey.getAlgorithm(), ex);
            }
        }

        ECDHServerKeyExchangeMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            Signature signer;
            ClientHandshakeContext chc = (ClientHandshakeContext) handshakeContext;
            byte curveType = (byte) Record.getInt8(m);
            if (curveType != 3) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unsupported ECCurveType: " + ((int) curveType));
            }
            int namedGroupId = Record.getInt16(m);
            this.namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(namedGroupId);
            if (this.namedGroup == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unknown named group ID: " + namedGroupId);
            }
            if (!SupportedGroupsExtension.SupportedGroups.isSupported(this.namedGroup)) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unsupported named group: " + this.namedGroup);
            }
            if (this.namedGroup.oid == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Unknown named EC curve: " + this.namedGroup);
            }
            ECParameterSpec parameters = JsseJce.getECParameterSpec(this.namedGroup.oid);
            if (parameters == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No supported EC parameter: " + this.namedGroup);
            }
            this.publicPoint = Record.getBytes8(m);
            if (this.publicPoint.length == 0) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Insufficient ECPoint data: " + this.namedGroup);
            }
            try {
                ECPoint point = JsseJce.decodePoint(this.publicPoint, parameters.getCurve());
                KeyFactory factory = JsseJce.getKeyFactory("EC");
                ECPublicKey ecPublicKey = (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(point, parameters));
                this.publicKey = ecPublicKey;
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
                    if (m.hasRemaining()) {
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid DH ServerKeyExchange: unknown extra data");
                    }
                    this.signatureScheme = null;
                    this.paramsSignature = null;
                    this.useExplicitSigAlgorithm = false;
                    return;
                }
                this.useExplicitSigAlgorithm = chc.negotiatedProtocol.useTLS12PlusSpec();
                if (this.useExplicitSigAlgorithm) {
                    int ssid = Record.getInt16(m);
                    this.signatureScheme = SignatureScheme.valueOf(ssid);
                    if (this.signatureScheme == null) {
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid signature algorithm (" + ssid + ") used in ECDH ServerKeyExchange handshake message");
                    }
                    if (!chc.localSupportedSignAlgs.contains(this.signatureScheme)) {
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsupported signature algorithm (" + this.signatureScheme.name + ") used in ECDH ServerKeyExchange handshake message");
                    }
                } else {
                    this.signatureScheme = null;
                }
                this.paramsSignature = Record.getBytes16(m);
                if (this.useExplicitSigAlgorithm) {
                    try {
                        signer = this.signatureScheme.getVerifier(x509Credentials.popPublicKey);
                    } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException nsae) {
                        throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm: " + this.signatureScheme.name, nsae);
                    }
                } else {
                    try {
                        signer = getSignature(x509Credentials.popPublicKey.getAlgorithm(), x509Credentials.popPublicKey);
                    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                        throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm: " + x509Credentials.popPublicKey.getAlgorithm(), e);
                    }
                }
                try {
                    updateSignature(signer, chc.clientHelloRandom.randomBytes, chc.serverHelloRandom.randomBytes, this.namedGroup.f1009id, this.publicPoint);
                    if (!signer.verify(this.paramsSignature)) {
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid ECDH ServerKeyExchange signature");
                    }
                } catch (SignatureException ex) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot verify ECDH ServerKeyExchange signature", ex);
                }
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex2) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid ECPoint: " + this.namedGroup, ex2);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.SERVER_KEY_EXCHANGE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            int sigLen = 0;
            if (this.paramsSignature != null) {
                sigLen = 2 + this.paramsSignature.length;
                if (this.useExplicitSigAlgorithm) {
                    sigLen += SignatureScheme.sizeInRecord();
                }
            }
            return 4 + this.publicPoint.length + sigLen;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8(3);
            hos.putInt16(this.namedGroup.f1009id);
            hos.putBytes8(this.publicPoint);
            if (this.paramsSignature != null) {
                if (this.useExplicitSigAlgorithm) {
                    hos.putInt16(this.signatureScheme.f1007id);
                }
                hos.putBytes16(this.paramsSignature);
            }
        }

        public String toString() {
            if (this.useExplicitSigAlgorithm) {
                MessageFormat messageFormat = new MessageFormat("\"ECDH ServerKeyExchange\": '{'\n  \"parameters\": '{'\n    \"named group\": \"{0}\"\n    \"ecdh public\": '{'\n{1}\n    '}',\n  '}',\n  \"digital signature\":  '{'\n    \"signature algorithm\": \"{2}\"\n    \"signature\": '{'\n{3}\n    '}',\n  '}'\n'}'", Locale.ENGLISH);
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {this.namedGroup.name, Utilities.indent(hexEncoder.encodeBuffer(this.publicPoint), "      "), this.signatureScheme.name, Utilities.indent(hexEncoder.encodeBuffer(this.paramsSignature), "      ")};
                return messageFormat.format(messageFields);
            } else if (this.paramsSignature != null) {
                MessageFormat messageFormat2 = new MessageFormat("\"ECDH ServerKeyExchange\": '{'\n  \"parameters\":  '{'\n    \"named group\": \"{0}\"\n    \"ecdh public\": '{'\n{1}\n    '}',\n  '}',\n  \"signature\": '{'\n{2}\n  '}'\n'}'", Locale.ENGLISH);
                HexDumpEncoder hexEncoder2 = new HexDumpEncoder();
                Object[] messageFields2 = {this.namedGroup.name, Utilities.indent(hexEncoder2.encodeBuffer(this.publicPoint), "      "), Utilities.indent(hexEncoder2.encodeBuffer(this.paramsSignature), "    ")};
                return messageFormat2.format(messageFields2);
            } else {
                MessageFormat messageFormat3 = new MessageFormat("\"ECDH ServerKeyExchange\": '{'\n  \"parameters\":  '{'\n    \"named group\": \"{0}\"\n    \"ecdh public\": '{'\n{1}\n    '}',\n  '}'\n'}'", Locale.ENGLISH);
                Object[] messageFields3 = {this.namedGroup.name, Utilities.indent(new HexDumpEncoder().encodeBuffer(this.publicPoint), "      ")};
                return messageFormat3.format(messageFields3);
            }
        }

        private static Signature getSignature(String keyAlgorithm, Key key) throws NoSuchAlgorithmException, InvalidKeyException {
            Signature signer;
            boolean z = true;
            switch (keyAlgorithm.hashCode()) {
                case 2206:
                    if (keyAlgorithm.equals("EC")) {
                        z = false;
                        break;
                    }
                    break;
                case 81440:
                    if (keyAlgorithm.equals("RSA")) {
                        z = true;
                        break;
                    }
                    break;
            }
            switch (z) {
                case false:
                    signer = JsseJce.getSignature("SHA1withECDSA");
                    break;
                case true:
                    signer = RSASignature.getInstance();
                    break;
                default:
                    throw new NoSuchAlgorithmException("neither an RSA or a EC key : " + keyAlgorithm);
            }
            if (signer != null) {
                if (key instanceof PublicKey) {
                    signer.initVerify((PublicKey) key);
                } else {
                    signer.initSign((PrivateKey) key);
                }
            }
            return signer;
        }

        private static void updateSignature(Signature sig, byte[] clntNonce, byte[] svrNonce, int namedGroupId, byte[] publicPoint) throws SignatureException {
            sig.update(clntNonce);
            sig.update(svrNonce);
            sig.update((byte) 3);
            sig.update((byte) ((namedGroupId >> 8) & GF2Field.MASK));
            sig.update((byte) (namedGroupId & GF2Field.MASK));
            sig.update((byte) publicPoint.length);
            sig.update(publicPoint);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHServerKeyExchange$ECDHServerKeyExchangeProducer.class */
    private static final class ECDHServerKeyExchangeProducer implements HandshakeProducer {
        private ECDHServerKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ECDHServerKeyExchangeMessage skem = new ECDHServerKeyExchangeMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ECDH ServerKeyExchange handshake message", skem);
            }
            skem.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECDHServerKeyExchange$ECDHServerKeyExchangeConsumer.class */
    private static final class ECDHServerKeyExchangeConsumer implements SSLConsumer {
        private ECDHServerKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            ECDHServerKeyExchangeMessage skem = new ECDHServerKeyExchangeMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ECDH ServerKeyExchange handshake message", skem);
            }
            if (!chc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), skem.publicKey)) {
                throw chc.conContext.fatal(Alert.INSUFFICIENT_SECURITY, "ECDH ServerKeyExchange does not comply to algorithm constraints");
            }
            chc.handshakeCredentials.add(new ECDHKeyExchange.ECDHECredentials(skem.publicKey, skem.namedGroup));
        }
    }
}