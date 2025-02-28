package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.DHKeyExchange;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.ssl.X509Authentication;
import org.openjsse.sun.security.util.HexDumpEncoder;
import sun.security.util.KeyUtil;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHServerKeyExchange.class */
final class DHServerKeyExchange {
    static final SSLConsumer dhHandshakeConsumer = new DHServerKeyExchangeConsumer();
    static final HandshakeProducer dhHandshakeProducer = new DHServerKeyExchangeProducer();

    DHServerKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHServerKeyExchange$DHServerKeyExchangeMessage.class */
    private static final class DHServerKeyExchangeMessage extends SSLHandshake.HandshakeMessage {

        /* renamed from: p */
        private final byte[] f967p;

        /* renamed from: g */
        private final byte[] f968g;

        /* renamed from: y */
        private final byte[] f969y;
        private final boolean useExplicitSigAlgorithm;
        private final SignatureScheme signatureScheme;
        private final byte[] paramsSignature;

        DHServerKeyExchangeMessage(HandshakeContext handshakeContext) throws IOException {
            super(handshakeContext);
            Signature signer;
            ServerHandshakeContext shc = (ServerHandshakeContext) handshakeContext;
            DHKeyExchange.DHEPossession dhePossession = null;
            X509Authentication.X509Possession x509Possession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof DHKeyExchange.DHEPossession) {
                    dhePossession = (DHKeyExchange.DHEPossession) possession;
                    if (x509Possession != null) {
                        break;
                    }
                } else if (possession instanceof X509Authentication.X509Possession) {
                    x509Possession = (X509Authentication.X509Possession) possession;
                    if (dhePossession != null) {
                        break;
                    }
                } else {
                    continue;
                }
            }
            if (dhePossession == null) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No DHE credentials negotiated for server key exchange");
            }
            DHPublicKey publicKey = dhePossession.publicKey;
            DHParameterSpec params = publicKey.getParams();
            this.f967p = Utilities.toByteArray(params.getP());
            this.f968g = Utilities.toByteArray(params.getG());
            this.f969y = Utilities.toByteArray(publicKey.getY());
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
                updateSignature(signer, shc.clientHelloRandom.randomBytes, shc.serverHelloRandom.randomBytes);
                byte[] signature = signer.sign();
                this.paramsSignature = signature;
            } catch (SignatureException ex) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Failed to sign dhe parameters: " + x509Possession.popPrivateKey.getAlgorithm(), ex);
            }
        }

        DHServerKeyExchangeMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            Signature signer;
            ClientHandshakeContext chc = (ClientHandshakeContext) handshakeContext;
            this.f967p = Record.getBytes16(m);
            this.f968g = Record.getBytes16(m);
            this.f969y = Record.getBytes16(m);
            try {
                KeyUtil.validate(new DHPublicKeySpec(new BigInteger(1, this.f969y), new BigInteger(1, this.f967p), new BigInteger(1, this.f967p)));
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
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid signature algorithm (" + ssid + ") used in DH ServerKeyExchange handshake message");
                    }
                    if (!chc.localSupportedSignAlgs.contains(this.signatureScheme)) {
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsupported signature algorithm (" + this.signatureScheme.name + ") used in DH ServerKeyExchange handshake message");
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
                    updateSignature(signer, chc.clientHelloRandom.randomBytes, chc.serverHelloRandom.randomBytes);
                    if (!signer.verify(this.paramsSignature)) {
                        throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid signature on DH ServerKeyExchange message");
                    }
                } catch (SignatureException ex) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot verify DH ServerKeyExchange signature", ex);
                }
            } catch (InvalidKeyException ike) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid DH ServerKeyExchange: invalid parameters", ike);
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
            return 6 + this.f967p.length + this.f968g.length + this.f969y.length + sigLen;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes16(this.f967p);
            hos.putBytes16(this.f968g);
            hos.putBytes16(this.f969y);
            if (this.paramsSignature != null) {
                if (this.useExplicitSigAlgorithm) {
                    hos.putInt16(this.signatureScheme.f1007id);
                }
                hos.putBytes16(this.paramsSignature);
            }
        }

        public String toString() {
            if (this.paramsSignature == null) {
                MessageFormat messageFormat = new MessageFormat("\"DH ServerKeyExchange\": '{'\n  \"parameters\": '{'\n    \"dh_p\": '{'\n{0}\n    '}',\n    \"dh_g\": '{'\n{1}\n    '}',\n    \"dh_Ys\": '{'\n{2}\n    '}',\n  '}'\n'}'", Locale.ENGLISH);
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {Utilities.indent(hexEncoder.encodeBuffer(this.f967p), "      "), Utilities.indent(hexEncoder.encodeBuffer(this.f968g), "      "), Utilities.indent(hexEncoder.encodeBuffer(this.f969y), "      ")};
                return messageFormat.format(messageFields);
            } else if (this.useExplicitSigAlgorithm) {
                MessageFormat messageFormat2 = new MessageFormat("\"DH ServerKeyExchange\": '{'\n  \"parameters\": '{'\n    \"dh_p\": '{'\n{0}\n    '}',\n    \"dh_g\": '{'\n{1}\n    '}',\n    \"dh_Ys\": '{'\n{2}\n    '}',\n  '}',\n  \"digital signature\":  '{'\n    \"signature algorithm\": \"{3}\"\n    \"signature\": '{'\n{4}\n    '}',\n  '}'\n'}'", Locale.ENGLISH);
                HexDumpEncoder hexEncoder2 = new HexDumpEncoder();
                Object[] messageFields2 = {Utilities.indent(hexEncoder2.encodeBuffer(this.f967p), "      "), Utilities.indent(hexEncoder2.encodeBuffer(this.f968g), "      "), Utilities.indent(hexEncoder2.encodeBuffer(this.f969y), "      "), this.signatureScheme.name, Utilities.indent(hexEncoder2.encodeBuffer(this.paramsSignature), "      ")};
                return messageFormat2.format(messageFields2);
            } else {
                MessageFormat messageFormat3 = new MessageFormat("\"DH ServerKeyExchange\": '{'\n  \"parameters\": '{'\n    \"dh_p\": '{'\n{0}\n    '}',\n    \"dh_g\": '{'\n{1}\n    '}',\n    \"dh_Ys\": '{'\n{2}\n    '}',\n  '}',\n  \"signature\": '{'\n{3}\n  '}'\n'}'", Locale.ENGLISH);
                HexDumpEncoder hexEncoder3 = new HexDumpEncoder();
                Object[] messageFields3 = {Utilities.indent(hexEncoder3.encodeBuffer(this.f967p), "      "), Utilities.indent(hexEncoder3.encodeBuffer(this.f968g), "      "), Utilities.indent(hexEncoder3.encodeBuffer(this.f969y), "      "), Utilities.indent(hexEncoder3.encodeBuffer(this.paramsSignature), "    ")};
                return messageFormat3.format(messageFields3);
            }
        }

        private static Signature getSignature(String keyAlgorithm, Key key) throws NoSuchAlgorithmException, InvalidKeyException {
            Signature signer;
            boolean z = true;
            switch (keyAlgorithm.hashCode()) {
                case 67986:
                    if (keyAlgorithm.equals("DSA")) {
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
                    signer = JsseJce.getSignature("DSA");
                    break;
                case true:
                    signer = RSASignature.getInstance();
                    break;
                default:
                    throw new NoSuchAlgorithmException("neither an RSA or a DSA key : " + keyAlgorithm);
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

        private void updateSignature(Signature sig, byte[] clntNonce, byte[] svrNonce) throws SignatureException {
            sig.update(clntNonce);
            sig.update(svrNonce);
            sig.update((byte) (this.f967p.length >> 8));
            sig.update((byte) (this.f967p.length & GF2Field.MASK));
            sig.update(this.f967p);
            sig.update((byte) (this.f968g.length >> 8));
            sig.update((byte) (this.f968g.length & GF2Field.MASK));
            sig.update(this.f968g);
            sig.update((byte) (this.f969y.length >> 8));
            sig.update((byte) (this.f969y.length & GF2Field.MASK));
            sig.update(this.f969y);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHServerKeyExchange$DHServerKeyExchangeProducer.class */
    static final class DHServerKeyExchangeProducer implements HandshakeProducer {
        private DHServerKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            DHServerKeyExchangeMessage skem = new DHServerKeyExchangeMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced DH ServerKeyExchange handshake message", skem);
            }
            skem.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DHServerKeyExchange$DHServerKeyExchangeConsumer.class */
    static final class DHServerKeyExchangeConsumer implements SSLConsumer {
        private DHServerKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            DHServerKeyExchangeMessage skem = new DHServerKeyExchangeMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming DH ServerKeyExchange handshake message", skem);
            }
            try {
                KeyFactory kf = JsseJce.getKeyFactory("DiffieHellman");
                DHPublicKeySpec spec = new DHPublicKeySpec(new BigInteger(1, skem.f969y), new BigInteger(1, skem.f967p), new BigInteger(1, skem.f968g));
                DHPublicKey publicKey = (DHPublicKey) kf.generatePublic(spec);
                if (!chc.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), publicKey)) {
                    throw chc.conContext.fatal(Alert.INSUFFICIENT_SECURITY, "DH ServerKeyExchange does not comply to algorithm constraints");
                }
                SupportedGroupsExtension.NamedGroup namedGroup = SupportedGroupsExtension.NamedGroup.valueOf(publicKey.getParams());
                chc.handshakeCredentials.add(new DHKeyExchange.DHECredentials(publicKey, namedGroup));
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.INSUFFICIENT_SECURITY, "Could not generate DHPublicKey", gse);
            }
        }
    }
}