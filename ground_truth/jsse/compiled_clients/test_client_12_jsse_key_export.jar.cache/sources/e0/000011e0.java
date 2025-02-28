package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension.class */
final class SignatureAlgorithmsExtension {
    static final HandshakeProducer chNetworkProducer = new CHSignatureSchemesProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHSignatureSchemesConsumer();
    static final HandshakeAbsence chOnLoadAbsence = new CHSignatureSchemesOnLoadAbsence();
    static final HandshakeConsumer chOnTradeConsumer = new CHSignatureSchemesUpdate();
    static final HandshakeAbsence chOnTradeAbsence = new CHSignatureSchemesOnTradeAbsence();
    static final HandshakeProducer crNetworkProducer = new CRSignatureSchemesProducer();
    static final SSLExtension.ExtensionConsumer crOnLoadConsumer = new CRSignatureSchemesConsumer();
    static final HandshakeAbsence crOnLoadAbsence = new CRSignatureSchemesAbsence();
    static final HandshakeConsumer crOnTradeConsumer = new CRSignatureSchemesUpdate();
    static final SSLStringizer ssStringizer = new SignatureSchemesStringizer();

    SignatureAlgorithmsExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$SignatureSchemesSpec.class */
    static final class SignatureSchemesSpec implements SSLExtension.SSLExtensionSpec {
        final int[] signatureSchemes;

        /* JADX INFO: Access modifiers changed from: package-private */
        public SignatureSchemesSpec(List<SignatureScheme> schemes) {
            if (schemes != null) {
                this.signatureSchemes = new int[schemes.size()];
                int i = 0;
                for (SignatureScheme scheme : schemes) {
                    int i2 = i;
                    i++;
                    this.signatureSchemes[i2] = scheme.f1007id;
                }
                return;
            }
            this.signatureSchemes = new int[0];
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public SignatureSchemesSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw new SSLProtocolException("Invalid signature_algorithms: insufficient data");
            }
            byte[] algs = Record.getBytes16(buffer);
            if (buffer.hasRemaining()) {
                throw new SSLProtocolException("Invalid signature_algorithms: unknown extra data");
            }
            if (algs == null || algs.length == 0 || (algs.length & 1) != 0) {
                throw new SSLProtocolException("Invalid signature_algorithms: incomplete data");
            }
            int[] schemes = new int[algs.length / 2];
            int i = 0;
            int j = 0;
            while (i < algs.length) {
                int i2 = i;
                int i3 = i + 1;
                byte hash = algs[i2];
                i = i3 + 1;
                byte sign = algs[i3];
                int i4 = j;
                j++;
                schemes[i4] = ((hash & 255) << 8) | (sign & 255);
            }
            this.signatureSchemes = schemes;
        }

        public String toString() {
            int[] iArr;
            MessageFormat messageFormat = new MessageFormat("\"signature schemes\": '['{0}']'", Locale.ENGLISH);
            if (this.signatureSchemes == null || this.signatureSchemes.length == 0) {
                Object[] messageFields = {"<no supported signature schemes specified>"};
                return messageFormat.format(messageFields);
            }
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (int pv : this.signatureSchemes) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(", ");
                }
                builder.append(SignatureScheme.nameOf(pv));
            }
            Object[] messageFields2 = {builder.toString()};
            return messageFormat.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$SignatureSchemesStringizer.class */
    private static final class SignatureSchemesStringizer implements SSLStringizer {
        private SignatureSchemesStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new SignatureSchemesSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CHSignatureSchemesProducer.class */
    private static final class CHSignatureSchemesProducer implements HandshakeProducer {
        private CHSignatureSchemesProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_SIGNATURE_ALGORITHMS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable signature_algorithms extension", new Object[0]);
                    return null;
                }
                return null;
            }
            if (chc.localSupportedSignAlgs == null) {
                chc.localSupportedSignAlgs = SignatureScheme.getSupportedAlgorithms(chc.sslConfig, chc.algorithmConstraints, chc.activeProtocols);
            }
            int vectorLen = SignatureScheme.sizeInRecord() * chc.localSupportedSignAlgs.size();
            byte[] extData = new byte[vectorLen + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, vectorLen);
            for (SignatureScheme ss : chc.localSupportedSignAlgs) {
                Record.putInt16(m, ss.f1007id);
            }
            chc.handshakeExtensions.put(SSLExtension.CH_SIGNATURE_ALGORITHMS, new SignatureSchemesSpec(chc.localSupportedSignAlgs));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CHSignatureSchemesConsumer.class */
    private static final class CHSignatureSchemesConsumer implements SSLExtension.ExtensionConsumer {
        private CHSignatureSchemesConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_SIGNATURE_ALGORITHMS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable signature_algorithms extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                SignatureSchemesSpec spec = new SignatureSchemesSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_SIGNATURE_ALGORITHMS, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CHSignatureSchemesUpdate.class */
    private static final class CHSignatureSchemesUpdate implements HandshakeConsumer {
        private CHSignatureSchemesUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            SignatureSchemesSpec spec = (SignatureSchemesSpec) shc.handshakeExtensions.get(SSLExtension.CH_SIGNATURE_ALGORITHMS);
            if (spec == null) {
                return;
            }
            List<SignatureScheme> sss = SignatureScheme.getSupportedAlgorithms(shc.sslConfig, shc.algorithmConstraints, shc.negotiatedProtocol, spec.signatureSchemes);
            shc.peerRequestedSignatureSchemes = sss;
            SignatureSchemesSpec certSpec = (SignatureSchemesSpec) shc.handshakeExtensions.get(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT);
            if (certSpec == null) {
                shc.peerRequestedCertSignSchemes = sss;
                shc.handshakeSession.setPeerSupportedSignatureAlgorithms(sss);
            }
            if (!shc.isResumption && shc.negotiatedProtocol.useTLS13PlusSpec()) {
                if (shc.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_NONE) {
                    shc.handshakeProducers.putIfAbsent(Byte.valueOf(SSLHandshake.CERTIFICATE_REQUEST.f987id), SSLHandshake.CERTIFICATE_REQUEST);
                }
                shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
                shc.handshakeProducers.putIfAbsent(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CHSignatureSchemesOnLoadAbsence.class */
    private static final class CHSignatureSchemesOnLoadAbsence implements HandshakeAbsence {
        private CHSignatureSchemesOnLoadAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.negotiatedProtocol.useTLS13PlusSpec()) {
                throw shc.conContext.fatal(Alert.MISSING_EXTENSION, "No mandatory signature_algorithms extension in the received CertificateRequest handshake message");
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CHSignatureSchemesOnTradeAbsence.class */
    private static final class CHSignatureSchemesOnTradeAbsence implements HandshakeAbsence {
        private CHSignatureSchemesOnTradeAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.negotiatedProtocol.useTLS12PlusSpec()) {
                List<SignatureScheme> schemes = Arrays.asList(SignatureScheme.RSA_PKCS1_SHA1, SignatureScheme.DSA_SHA1, SignatureScheme.ECDSA_SHA1);
                shc.peerRequestedSignatureSchemes = schemes;
                if (shc.peerRequestedCertSignSchemes == null || shc.peerRequestedCertSignSchemes.isEmpty()) {
                    shc.peerRequestedCertSignSchemes = schemes;
                }
                shc.handshakeSession.setUseDefaultPeerSignAlgs();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CRSignatureSchemesProducer.class */
    private static final class CRSignatureSchemesProducer implements HandshakeProducer {
        private CRSignatureSchemesProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CR_SIGNATURE_ALGORITHMS)) {
                throw shc.conContext.fatal(Alert.MISSING_EXTENSION, "No available signature_algorithms extension for client certificate authentication");
            }
            List<ProtocolVersion> protocols = Arrays.asList(shc.negotiatedProtocol);
            List<SignatureScheme> sigAlgs = SignatureScheme.getSupportedAlgorithms(shc.sslConfig, shc.algorithmConstraints, Collections.unmodifiableList(protocols));
            int vectorLen = SignatureScheme.sizeInRecord() * sigAlgs.size();
            byte[] extData = new byte[vectorLen + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, vectorLen);
            for (SignatureScheme ss : sigAlgs) {
                Record.putInt16(m, ss.f1007id);
            }
            shc.handshakeExtensions.put(SSLExtension.CR_SIGNATURE_ALGORITHMS, new SignatureSchemesSpec(shc.localSupportedSignAlgs));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CRSignatureSchemesConsumer.class */
    private static final class CRSignatureSchemesConsumer implements SSLExtension.ExtensionConsumer {
        private CRSignatureSchemesConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            int[] iArr;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CR_SIGNATURE_ALGORITHMS)) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No available signature_algorithms extension for client certificate authentication");
            }
            try {
                SignatureSchemesSpec spec = new SignatureSchemesSpec(buffer);
                List<SignatureScheme> knownSignatureSchemes = new LinkedList<>();
                for (int id : spec.signatureSchemes) {
                    SignatureScheme ss = SignatureScheme.valueOf(id);
                    if (ss != null) {
                        knownSignatureSchemes.add(ss);
                    }
                }
                chc.handshakeExtensions.put(SSLExtension.CR_SIGNATURE_ALGORITHMS, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CRSignatureSchemesUpdate.class */
    private static final class CRSignatureSchemesUpdate implements HandshakeConsumer {
        private CRSignatureSchemesUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            SignatureSchemesSpec spec = (SignatureSchemesSpec) chc.handshakeExtensions.get(SSLExtension.CR_SIGNATURE_ALGORITHMS);
            if (spec == null) {
                return;
            }
            List<SignatureScheme> sss = SignatureScheme.getSupportedAlgorithms(chc.sslConfig, chc.algorithmConstraints, chc.negotiatedProtocol, spec.signatureSchemes);
            chc.peerRequestedSignatureSchemes = sss;
            SignatureSchemesSpec certSpec = (SignatureSchemesSpec) chc.handshakeExtensions.get(SSLExtension.CR_SIGNATURE_ALGORITHMS_CERT);
            if (certSpec == null) {
                chc.peerRequestedCertSignSchemes = sss;
                chc.handshakeSession.setPeerSupportedSignatureAlgorithms(sss);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SignatureAlgorithmsExtension$CRSignatureSchemesAbsence.class */
    private static final class CRSignatureSchemesAbsence implements HandshakeAbsence {
        private CRSignatureSchemesAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            throw chc.conContext.fatal(Alert.MISSING_EXTENSION, "No mandatory signature_algorithms extension in the received CertificateRequest handshake message");
        }
    }
}