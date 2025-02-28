package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.X509Authentication;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify.class */
final class CertificateVerify {
    static final SSLConsumer s30HandshakeConsumer = new S30CertificateVerifyConsumer();
    static final HandshakeProducer s30HandshakeProducer = new S30CertificateVerifyProducer();
    static final SSLConsumer t10HandshakeConsumer = new T10CertificateVerifyConsumer();
    static final HandshakeProducer t10HandshakeProducer = new T10CertificateVerifyProducer();
    static final SSLConsumer t12HandshakeConsumer = new T12CertificateVerifyConsumer();
    static final HandshakeProducer t12HandshakeProducer = new T12CertificateVerifyProducer();
    static final SSLConsumer t13HandshakeConsumer = new T13CertificateVerifyConsumer();
    static final HandshakeProducer t13HandshakeProducer = new T13CertificateVerifyProducer();

    CertificateVerify() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$S30CertificateVerifyMessage.class */
    static final class S30CertificateVerifyMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] signature;

        S30CertificateVerifyMessage(HandshakeContext context, X509Authentication.X509Possession x509Possession) throws IOException {
            super(context);
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            String algorithm = x509Possession.popPrivateKey.getAlgorithm();
            try {
                Signature signer = getSignature(algorithm, x509Possession.popPrivateKey);
                byte[] hashes = chc.handshakeHash.digest(algorithm, chc.handshakeSession.getMasterSecret());
                signer.update(hashes);
                byte[] temproary = signer.sign();
                this.signature = temproary;
            } catch (NoSuchAlgorithmException nsae) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm (" + algorithm + ") used in CertificateVerify handshake message", nsae);
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot produce CertificateVerify signature", gse);
            }
        }

        S30CertificateVerifyMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (m.remaining() < 2) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateVerify message: no sufficient data");
            }
            this.signature = Record.getBytes16(m);
            X509Authentication.X509Credentials x509Credentials = null;
            Iterator<SSLCredentials> it = shc.handshakeCredentials.iterator();
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
            if (x509Credentials == null || x509Credentials.popPublicKey == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X509 credentials negotiated for CertificateVerify");
            }
            String algorithm = x509Credentials.popPublicKey.getAlgorithm();
            try {
                Signature signer = getSignature(algorithm, x509Credentials.popPublicKey);
                byte[] hashes = shc.handshakeHash.digest(algorithm, shc.handshakeSession.getMasterSecret());
                signer.update(hashes);
                if (!signer.verify(this.signature)) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid CertificateVerify message: invalid signature");
                }
            } catch (NoSuchAlgorithmException nsae) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm (" + algorithm + ") used in CertificateVerify handshake message", nsae);
            } catch (GeneralSecurityException gse) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot verify CertificateVerify signature", gse);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_VERIFY;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 2 + this.signature.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes16(this.signature);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"CertificateVerify\": '{'\n  \"signature\": '{'\n{0}\n  '}'\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {Utilities.indent(hexEncoder.encodeBuffer(this.signature), "    ")};
            return messageFormat.format(messageFields);
        }

        private static Signature getSignature(String algorithm, Key key) throws GeneralSecurityException {
            Signature signer;
            boolean z = true;
            switch (algorithm.hashCode()) {
                case 2206:
                    if (algorithm.equals("EC")) {
                        z = true;
                        break;
                    }
                    break;
                case 67986:
                    if (algorithm.equals("DSA")) {
                        z = true;
                        break;
                    }
                    break;
                case 81440:
                    if (algorithm.equals("RSA")) {
                        z = false;
                        break;
                    }
                    break;
            }
            switch (z) {
                case false:
                    signer = JsseJce.getSignature("NONEwithRSA");
                    break;
                case true:
                    signer = JsseJce.getSignature("RawDSA");
                    break;
                case true:
                    signer = JsseJce.getSignature("NONEwithECDSA");
                    break;
                default:
                    throw new SignatureException("Unrecognized algorithm: " + algorithm);
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
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$S30CertificateVerifyProducer.class */
    private static final class S30CertificateVerifyProducer implements HandshakeProducer {
        private S30CertificateVerifyProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = chc.handshakePossessions.iterator();
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
            if (x509Possession == null || x509Possession.popPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No X.509 credentials negotiated for CertificateVerify", new Object[0]);
                    return null;
                }
                return null;
            }
            S30CertificateVerifyMessage cvm = new S30CertificateVerifyMessage(chc, x509Possession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced CertificateVerify handshake message", cvm);
            }
            cvm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$S30CertificateVerifyConsumer.class */
    private static final class S30CertificateVerifyConsumer implements SSLConsumer {
        private S30CertificateVerifyConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id));
            if (shc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id))) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected CertificateVerify handshake message");
            }
            S30CertificateVerifyMessage cvm = new S30CertificateVerifyMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming CertificateVerify handshake message", cvm);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T10CertificateVerifyMessage.class */
    static final class T10CertificateVerifyMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] signature;

        T10CertificateVerifyMessage(HandshakeContext context, X509Authentication.X509Possession x509Possession) throws IOException {
            super(context);
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            String algorithm = x509Possession.popPrivateKey.getAlgorithm();
            try {
                Signature signer = getSignature(algorithm, x509Possession.popPrivateKey);
                byte[] hashes = chc.handshakeHash.digest(algorithm);
                signer.update(hashes);
                byte[] temproary = signer.sign();
                this.signature = temproary;
            } catch (NoSuchAlgorithmException nsae) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm (" + algorithm + ") used in CertificateVerify handshake message", nsae);
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot produce CertificateVerify signature", gse);
            }
        }

        T10CertificateVerifyMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (m.remaining() < 2) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateVerify message: no sufficient data");
            }
            this.signature = Record.getBytes16(m);
            X509Authentication.X509Credentials x509Credentials = null;
            Iterator<SSLCredentials> it = shc.handshakeCredentials.iterator();
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
            if (x509Credentials == null || x509Credentials.popPublicKey == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X509 credentials negotiated for CertificateVerify");
            }
            String algorithm = x509Credentials.popPublicKey.getAlgorithm();
            try {
                Signature signer = getSignature(algorithm, x509Credentials.popPublicKey);
                byte[] hashes = shc.handshakeHash.digest(algorithm);
                signer.update(hashes);
                if (!signer.verify(this.signature)) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid CertificateVerify message: invalid signature");
                }
            } catch (NoSuchAlgorithmException nsae) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm (" + algorithm + ") used in CertificateVerify handshake message", nsae);
            } catch (GeneralSecurityException gse) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot verify CertificateVerify signature", gse);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_VERIFY;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 2 + this.signature.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes16(this.signature);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"CertificateVerify\": '{'\n  \"signature\": '{'\n{0}\n  '}'\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {Utilities.indent(hexEncoder.encodeBuffer(this.signature), "    ")};
            return messageFormat.format(messageFields);
        }

        private static Signature getSignature(String algorithm, Key key) throws GeneralSecurityException {
            Signature signer;
            boolean z = true;
            switch (algorithm.hashCode()) {
                case 2206:
                    if (algorithm.equals("EC")) {
                        z = true;
                        break;
                    }
                    break;
                case 67986:
                    if (algorithm.equals("DSA")) {
                        z = true;
                        break;
                    }
                    break;
                case 81440:
                    if (algorithm.equals("RSA")) {
                        z = false;
                        break;
                    }
                    break;
            }
            switch (z) {
                case false:
                    signer = JsseJce.getSignature("NONEwithRSA");
                    break;
                case true:
                    signer = JsseJce.getSignature("RawDSA");
                    break;
                case true:
                    signer = JsseJce.getSignature("NONEwithECDSA");
                    break;
                default:
                    throw new SignatureException("Unrecognized algorithm: " + algorithm);
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
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T10CertificateVerifyProducer.class */
    private static final class T10CertificateVerifyProducer implements HandshakeProducer {
        private T10CertificateVerifyProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = chc.handshakePossessions.iterator();
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
            if (x509Possession == null || x509Possession.popPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No X.509 credentials negotiated for CertificateVerify", new Object[0]);
                    return null;
                }
                return null;
            }
            T10CertificateVerifyMessage cvm = new T10CertificateVerifyMessage(chc, x509Possession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced CertificateVerify handshake message", cvm);
            }
            cvm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T10CertificateVerifyConsumer.class */
    private static final class T10CertificateVerifyConsumer implements SSLConsumer {
        private T10CertificateVerifyConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id));
            if (shc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id))) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected CertificateVerify handshake message");
            }
            T10CertificateVerifyMessage cvm = new T10CertificateVerifyMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming CertificateVerify handshake message", cvm);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T12CertificateVerifyMessage.class */
    static final class T12CertificateVerifyMessage extends SSLHandshake.HandshakeMessage {
        private final SignatureScheme signatureScheme;
        private final byte[] signature;

        T12CertificateVerifyMessage(HandshakeContext context, X509Authentication.X509Possession x509Possession) throws IOException {
            super(context);
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            Map.Entry<SignatureScheme, Signature> schemeAndSigner = SignatureScheme.getSignerOfPreferableAlgorithm(chc.peerRequestedSignatureSchemes, x509Possession, chc.negotiatedProtocol);
            if (schemeAndSigner == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "No supported CertificateVerify signature algorithm for " + x509Possession.popPrivateKey.getAlgorithm() + "  key");
            }
            this.signatureScheme = schemeAndSigner.getKey();
            try {
                Signature signer = schemeAndSigner.getValue();
                signer.update(chc.handshakeHash.archived());
                byte[] temproary = signer.sign();
                this.signature = temproary;
            } catch (SignatureException ikse) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot produce CertificateVerify signature", ikse);
            }
        }

        T12CertificateVerifyMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            ServerHandshakeContext shc = (ServerHandshakeContext) handshakeContext;
            if (m.remaining() < 4) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateVerify message: no sufficient data");
            }
            int ssid = Record.getInt16(m);
            this.signatureScheme = SignatureScheme.valueOf(ssid);
            if (this.signatureScheme == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid signature algorithm (" + ssid + ") used in CertificateVerify handshake message");
            }
            if (!shc.localSupportedSignAlgs.contains(this.signatureScheme)) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsupported signature algorithm (" + this.signatureScheme.name + ") used in CertificateVerify handshake message");
            }
            X509Authentication.X509Credentials x509Credentials = null;
            Iterator<SSLCredentials> it = shc.handshakeCredentials.iterator();
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
            if (x509Credentials == null || x509Credentials.popPublicKey == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X509 credentials negotiated for CertificateVerify");
            }
            this.signature = Record.getBytes16(m);
            try {
                Signature signer = this.signatureScheme.getVerifier(x509Credentials.popPublicKey);
                signer.update(shc.handshakeHash.archived());
                if (!signer.verify(this.signature)) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid CertificateVerify signature");
                }
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException nsae) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm (" + this.signatureScheme.name + ") used in CertificateVerify handshake message", nsae);
            } catch (InvalidKeyException | SignatureException ikse) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot verify CertificateVerify signature", ikse);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_VERIFY;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 4 + this.signature.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt16(this.signatureScheme.f1007id);
            hos.putBytes16(this.signature);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"CertificateVerify\": '{'\n  \"signature algorithm\": {0}\n  \"signature\": '{'\n{1}\n  '}'\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {this.signatureScheme.name, Utilities.indent(hexEncoder.encodeBuffer(this.signature), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T12CertificateVerifyProducer.class */
    private static final class T12CertificateVerifyProducer implements HandshakeProducer {
        private T12CertificateVerifyProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = chc.handshakePossessions.iterator();
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
            if (x509Possession == null || x509Possession.popPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No X.509 credentials negotiated for CertificateVerify", new Object[0]);
                    return null;
                }
                return null;
            }
            T12CertificateVerifyMessage cvm = new T12CertificateVerifyMessage(chc, x509Possession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced CertificateVerify handshake message", cvm);
            }
            cvm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T12CertificateVerifyConsumer.class */
    private static final class T12CertificateVerifyConsumer implements SSLConsumer {
        private T12CertificateVerifyConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id));
            if (shc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id))) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected CertificateVerify handshake message");
            }
            T12CertificateVerifyMessage cvm = new T12CertificateVerifyMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming CertificateVerify handshake message", cvm);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T13CertificateVerifyMessage.class */
    public static final class T13CertificateVerifyMessage extends SSLHandshake.HandshakeMessage {
        private static final byte[] serverSignHead = {32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 76, 83, 32, 49, 46, 51, 44, 32, 115, 101, 114, 118, 101, 114, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121, 0};
        private static final byte[] clientSignHead = {32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 76, 83, 32, 49, 46, 51, 44, 32, 99, 108, 105, 101, 110, 116, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121, 0};
        private final SignatureScheme signatureScheme;
        private final byte[] signature;

        T13CertificateVerifyMessage(HandshakeContext context, X509Authentication.X509Possession x509Possession) throws IOException {
            super(context);
            byte[] contentCovered;
            Map.Entry<SignatureScheme, Signature> schemeAndSigner = SignatureScheme.getSignerOfPreferableAlgorithm(context.peerRequestedSignatureSchemes, x509Possession, context.negotiatedProtocol);
            if (schemeAndSigner == null) {
                throw context.conContext.fatal(Alert.INTERNAL_ERROR, "No supported CertificateVerify signature algorithm for " + x509Possession.popPrivateKey.getAlgorithm() + "  key");
            }
            this.signatureScheme = schemeAndSigner.getKey();
            byte[] hashValue = context.handshakeHash.digest();
            if (context.sslConfig.isClientMode) {
                contentCovered = Arrays.copyOf(clientSignHead, clientSignHead.length + hashValue.length);
                System.arraycopy(hashValue, 0, contentCovered, clientSignHead.length, hashValue.length);
            } else {
                contentCovered = Arrays.copyOf(serverSignHead, serverSignHead.length + hashValue.length);
                System.arraycopy(hashValue, 0, contentCovered, serverSignHead.length, hashValue.length);
            }
            try {
                Signature signer = schemeAndSigner.getValue();
                signer.update(contentCovered);
                byte[] temproary = signer.sign();
                this.signature = temproary;
            } catch (SignatureException ikse) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot produce CertificateVerify signature", ikse);
            }
        }

        T13CertificateVerifyMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            byte[] contentCovered;
            if (m.remaining() < 4) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateVerify message: no sufficient data");
            }
            int ssid = Record.getInt16(m);
            this.signatureScheme = SignatureScheme.valueOf(ssid);
            if (this.signatureScheme == null) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid signature algorithm (" + ssid + ") used in CertificateVerify handshake message");
            }
            if (!context.localSupportedSignAlgs.contains(this.signatureScheme)) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsupported signature algorithm (" + this.signatureScheme.name + ") used in CertificateVerify handshake message");
            }
            X509Authentication.X509Credentials x509Credentials = null;
            Iterator<SSLCredentials> it = context.handshakeCredentials.iterator();
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
            if (x509Credentials == null || x509Credentials.popPublicKey == null) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X509 credentials negotiated for CertificateVerify");
            }
            this.signature = Record.getBytes16(m);
            byte[] hashValue = context.handshakeHash.digest();
            if (context.sslConfig.isClientMode) {
                contentCovered = Arrays.copyOf(serverSignHead, serverSignHead.length + hashValue.length);
                System.arraycopy(hashValue, 0, contentCovered, serverSignHead.length, hashValue.length);
            } else {
                contentCovered = Arrays.copyOf(clientSignHead, clientSignHead.length + hashValue.length);
                System.arraycopy(hashValue, 0, contentCovered, clientSignHead.length, hashValue.length);
            }
            try {
                Signature signer = this.signatureScheme.getVerifier(x509Credentials.popPublicKey);
                signer.update(contentCovered);
                if (!signer.verify(this.signature)) {
                    throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Invalid CertificateVerify signature");
                }
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException nsae) {
                throw context.conContext.fatal(Alert.INTERNAL_ERROR, "Unsupported signature algorithm (" + this.signatureScheme.name + ") used in CertificateVerify handshake message", nsae);
            } catch (InvalidKeyException | SignatureException ikse) {
                throw context.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Cannot verify CertificateVerify signature", ikse);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_VERIFY;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 4 + this.signature.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt16(this.signatureScheme.f1007id);
            hos.putBytes16(this.signature);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"CertificateVerify\": '{'\n  \"signature algorithm\": {0}\n  \"signature\": '{'\n{1}\n  '}'\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {this.signatureScheme.name, Utilities.indent(hexEncoder.encodeBuffer(this.signature), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T13CertificateVerifyProducer.class */
    private static final class T13CertificateVerifyProducer implements HandshakeProducer {
        private T13CertificateVerifyProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = hc.handshakePossessions.iterator();
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
            if (x509Possession == null || x509Possession.popPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No X.509 credentials negotiated for CertificateVerify", new Object[0]);
                    return null;
                }
                return null;
            } else if (hc.sslConfig.isClientMode) {
                return onProduceCertificateVerify((ClientHandshakeContext) context, x509Possession);
            } else {
                return onProduceCertificateVerify((ServerHandshakeContext) context, x509Possession);
            }
        }

        private byte[] onProduceCertificateVerify(ServerHandshakeContext shc, X509Authentication.X509Possession x509Possession) throws IOException {
            T13CertificateVerifyMessage cvm = new T13CertificateVerifyMessage(shc, x509Possession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced server CertificateVerify handshake message", cvm);
            }
            cvm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }

        private byte[] onProduceCertificateVerify(ClientHandshakeContext chc, X509Authentication.X509Possession x509Possession) throws IOException {
            T13CertificateVerifyMessage cvm = new T13CertificateVerifyMessage(chc, x509Possession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced client CertificateVerify handshake message", cvm);
            }
            cvm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateVerify$T13CertificateVerifyConsumer.class */
    private static final class T13CertificateVerifyConsumer implements SSLConsumer {
        private T13CertificateVerifyConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            hc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id));
            T13CertificateVerifyMessage cvm = new T13CertificateVerifyMessage(hc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming CertificateVerify handshake message", cvm);
            }
        }
    }
}