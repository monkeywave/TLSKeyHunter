package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SignatureAlgorithmsExtension;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension.class */
final class CertSignAlgsExtension {
    static final HandshakeProducer chNetworkProducer = new CHCertSignatureSchemesProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHCertSignatureSchemesConsumer();
    static final HandshakeConsumer chOnTradeConsumer = new CHCertSignatureSchemesUpdate();
    static final HandshakeProducer crNetworkProducer = new CRCertSignatureSchemesProducer();
    static final SSLExtension.ExtensionConsumer crOnLoadConsumer = new CRCertSignatureSchemesConsumer();
    static final HandshakeConsumer crOnTradeConsumer = new CRCertSignatureSchemesUpdate();
    static final SSLStringizer ssStringizer = new CertSignatureSchemesStringizer();

    CertSignAlgsExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension$CertSignatureSchemesStringizer.class */
    private static final class CertSignatureSchemesStringizer implements SSLStringizer {
        private CertSignatureSchemesStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new SignatureAlgorithmsExtension.SignatureSchemesSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension$CHCertSignatureSchemesProducer.class */
    private static final class CHCertSignatureSchemesProducer implements HandshakeProducer {
        private CHCertSignatureSchemesProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable signature_algorithms_cert extension", new Object[0]);
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
            chc.handshakeExtensions.put(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT, new SignatureAlgorithmsExtension.SignatureSchemesSpec(chc.localSupportedSignAlgs));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension$CHCertSignatureSchemesConsumer.class */
    private static final class CHCertSignatureSchemesConsumer implements SSLExtension.ExtensionConsumer {
        private CHCertSignatureSchemesConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable signature_algorithms_cert extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                SignatureAlgorithmsExtension.SignatureSchemesSpec spec = new SignatureAlgorithmsExtension.SignatureSchemesSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension$CHCertSignatureSchemesUpdate.class */
    private static final class CHCertSignatureSchemesUpdate implements HandshakeConsumer {
        private CHCertSignatureSchemesUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            SignatureAlgorithmsExtension.SignatureSchemesSpec spec = (SignatureAlgorithmsExtension.SignatureSchemesSpec) shc.handshakeExtensions.get(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT);
            if (spec == null) {
                return;
            }
            List<SignatureScheme> schemes = SignatureScheme.getSupportedAlgorithms(shc.sslConfig, shc.algorithmConstraints, shc.negotiatedProtocol, spec.signatureSchemes);
            shc.peerRequestedCertSignSchemes = schemes;
            shc.handshakeSession.setPeerSupportedSignatureAlgorithms(schemes);
            if (!shc.isResumption && shc.negotiatedProtocol.useTLS13PlusSpec()) {
                if (shc.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_NONE) {
                    shc.handshakeProducers.putIfAbsent(Byte.valueOf(SSLHandshake.CERTIFICATE_REQUEST.f987id), SSLHandshake.CERTIFICATE_REQUEST);
                }
                shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
                shc.handshakeProducers.putIfAbsent(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension$CRCertSignatureSchemesProducer.class */
    private static final class CRCertSignatureSchemesProducer implements HandshakeProducer {
        private CRCertSignatureSchemesProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable signature_algorithms_cert extension", new Object[0]);
                    return null;
                }
                return null;
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
            shc.handshakeExtensions.put(SSLExtension.CR_SIGNATURE_ALGORITHMS_CERT, new SignatureAlgorithmsExtension.SignatureSchemesSpec(shc.localSupportedSignAlgs));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension$CRCertSignatureSchemesConsumer.class */
    private static final class CRCertSignatureSchemesConsumer implements SSLExtension.ExtensionConsumer {
        private CRCertSignatureSchemesConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_SIGNATURE_ALGORITHMS_CERT)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable signature_algorithms_cert extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                SignatureAlgorithmsExtension.SignatureSchemesSpec spec = new SignatureAlgorithmsExtension.SignatureSchemesSpec(buffer);
                chc.handshakeExtensions.put(SSLExtension.CR_SIGNATURE_ALGORITHMS_CERT, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertSignAlgsExtension$CRCertSignatureSchemesUpdate.class */
    private static final class CRCertSignatureSchemesUpdate implements HandshakeConsumer {
        private CRCertSignatureSchemesUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            SignatureAlgorithmsExtension.SignatureSchemesSpec spec = (SignatureAlgorithmsExtension.SignatureSchemesSpec) chc.handshakeExtensions.get(SSLExtension.CR_SIGNATURE_ALGORITHMS_CERT);
            if (spec == null) {
                return;
            }
            List<SignatureScheme> schemes = SignatureScheme.getSupportedAlgorithms(chc.sslConfig, chc.algorithmConstraints, chc.negotiatedProtocol, spec.signatureSchemes);
            chc.peerRequestedCertSignSchemes = schemes;
            chc.handshakeSession.setPeerSupportedSignatureAlgorithms(schemes);
        }
    }
}