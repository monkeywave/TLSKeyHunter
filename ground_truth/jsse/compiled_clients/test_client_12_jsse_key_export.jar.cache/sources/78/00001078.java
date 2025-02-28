package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension.class */
final class ExtendedMasterSecretExtension {
    static final HandshakeProducer chNetworkProducer = new CHExtendedMasterSecretProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHExtendedMasterSecretConsumer();
    static final HandshakeAbsence chOnLoadAbsence = new CHExtendedMasterSecretAbsence();
    static final HandshakeProducer shNetworkProducer = new SHExtendedMasterSecretProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHExtendedMasterSecretConsumer();
    static final HandshakeAbsence shOnLoadAbsence = new SHExtendedMasterSecretAbsence();
    static final SSLStringizer emsStringizer = new ExtendedMasterSecretStringizer();

    ExtendedMasterSecretExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$ExtendedMasterSecretSpec.class */
    static final class ExtendedMasterSecretSpec implements SSLExtension.SSLExtensionSpec {
        static final ExtendedMasterSecretSpec NOMINAL = new ExtendedMasterSecretSpec();

        private ExtendedMasterSecretSpec() {
        }

        private ExtendedMasterSecretSpec(ByteBuffer m) throws IOException {
            if (m.hasRemaining()) {
                throw new SSLProtocolException("Invalid extended_master_secret extension data: not empty");
            }
        }

        public String toString() {
            return "<empty>";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$ExtendedMasterSecretStringizer.class */
    private static final class ExtendedMasterSecretStringizer implements SSLStringizer {
        private ExtendedMasterSecretStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new ExtendedMasterSecretSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$CHExtendedMasterSecretProducer.class */
    private static final class CHExtendedMasterSecretProducer implements HandshakeProducer {
        private CHExtendedMasterSecretProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_EXTENDED_MASTER_SECRET) || !SSLConfiguration.useExtendedMasterSecret || !chc.conContext.protocolVersion.useTLS10PlusSpec()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extended_master_secret extension", new Object[0]);
                    return null;
                }
                return null;
            } else if (chc.handshakeSession == null || chc.handshakeSession.useExtendedMasterSecret) {
                byte[] extData = new byte[0];
                chc.handshakeExtensions.put(SSLExtension.CH_EXTENDED_MASTER_SECRET, ExtendedMasterSecretSpec.NOMINAL);
                return extData;
            } else {
                return null;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$CHExtendedMasterSecretConsumer.class */
    private static final class CHExtendedMasterSecretConsumer implements SSLExtension.ExtensionConsumer {
        private CHExtendedMasterSecretConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_EXTENDED_MASTER_SECRET) || !SSLConfiguration.useExtendedMasterSecret || !shc.negotiatedProtocol.useTLS10PlusSpec()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.CH_EXTENDED_MASTER_SECRET.name, new Object[0]);
                    return;
                }
                return;
            }
            try {
                new ExtendedMasterSecretSpec(buffer);
                if (shc.isResumption && shc.resumingSession != null && !shc.resumingSession.useExtendedMasterSecret) {
                    shc.isResumption = false;
                    shc.resumingSession = null;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("abort session resumption which did not use Extended Master Secret extension", new Object[0]);
                    }
                }
                shc.handshakeExtensions.put(SSLExtension.CH_EXTENDED_MASTER_SECRET, ExtendedMasterSecretSpec.NOMINAL);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$CHExtendedMasterSecretAbsence.class */
    private static final class CHExtendedMasterSecretAbsence implements HandshakeAbsence {
        private CHExtendedMasterSecretAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_EXTENDED_MASTER_SECRET) || !SSLConfiguration.useExtendedMasterSecret) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.CH_EXTENDED_MASTER_SECRET.name, new Object[0]);
                }
            } else if (shc.negotiatedProtocol.useTLS10PlusSpec() && !SSLConfiguration.allowLegacyMasterSecret) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Extended Master Secret extension is required");
            } else {
                if (shc.isResumption && shc.resumingSession != null) {
                    if (shc.resumingSession.useExtendedMasterSecret) {
                        throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing Extended Master Secret extension on session resumption");
                    }
                    if (!SSLConfiguration.allowLegacyResumption) {
                        throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing Extended Master Secret extension on session resumption");
                    }
                    shc.isResumption = false;
                    shc.resumingSession = null;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("abort session resumption, missing Extended Master Secret extension", new Object[0]);
                    }
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$SHExtendedMasterSecretProducer.class */
    private static final class SHExtendedMasterSecretProducer implements HandshakeProducer {
        private SHExtendedMasterSecretProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.handshakeSession.useExtendedMasterSecret) {
                byte[] extData = new byte[0];
                shc.handshakeExtensions.put(SSLExtension.SH_EXTENDED_MASTER_SECRET, ExtendedMasterSecretSpec.NOMINAL);
                return extData;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$SHExtendedMasterSecretConsumer.class */
    private static final class SHExtendedMasterSecretConsumer implements SSLExtension.ExtensionConsumer {
        private SHExtendedMasterSecretConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            ExtendedMasterSecretSpec requstedSpec = (ExtendedMasterSecretSpec) chc.handshakeExtensions.get(SSLExtension.CH_EXTENDED_MASTER_SECRET);
            if (requstedSpec == null) {
                throw chc.conContext.fatal(Alert.UNSUPPORTED_EXTENSION, "Server sent the extended_master_secret extension improperly");
            }
            try {
                new ExtendedMasterSecretSpec(buffer);
                if (chc.isResumption && chc.resumingSession != null && !chc.resumingSession.useExtendedMasterSecret) {
                    throw chc.conContext.fatal(Alert.UNSUPPORTED_EXTENSION, "Server sent an unexpected extended_master_secret extension on session resumption");
                }
                chc.handshakeExtensions.put(SSLExtension.SH_EXTENDED_MASTER_SECRET, ExtendedMasterSecretSpec.NOMINAL);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ExtendedMasterSecretExtension$SHExtendedMasterSecretAbsence.class */
    private static final class SHExtendedMasterSecretAbsence implements HandshakeAbsence {
        private SHExtendedMasterSecretAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (SSLConfiguration.useExtendedMasterSecret && !SSLConfiguration.allowLegacyMasterSecret) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Extended Master Secret extension is required");
            }
            if (chc.isResumption && chc.resumingSession != null) {
                if (chc.resumingSession.useExtendedMasterSecret) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Missing Extended Master Secret extension on session resumption");
                }
                if (SSLConfiguration.useExtendedMasterSecret && !SSLConfiguration.allowLegacyResumption && chc.negotiatedProtocol.useTLS10PlusSpec()) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Extended Master Secret extension is required");
                }
            }
        }
    }
}