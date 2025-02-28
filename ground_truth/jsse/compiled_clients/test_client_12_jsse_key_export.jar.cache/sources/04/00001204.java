package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Locale;
import javax.net.ssl.SSLProtocolException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension.class */
final class SupportedVersionsExtension {
    static final HandshakeProducer chNetworkProducer = new CHSupportedVersionsProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHSupportedVersionsConsumer();
    static final SSLStringizer chStringizer = new CHSupportedVersionsStringizer();
    static final HandshakeProducer shNetworkProducer = new SHSupportedVersionsProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHSupportedVersionsConsumer();
    static final SSLStringizer shStringizer = new SHSupportedVersionsStringizer();
    static final HandshakeProducer hrrNetworkProducer = new HRRSupportedVersionsProducer();
    static final SSLExtension.ExtensionConsumer hrrOnLoadConsumer = new HRRSupportedVersionsConsumer();
    static final HandshakeProducer hrrReproducer = new HRRSupportedVersionsReproducer();
    static final SSLStringizer hrrStringizer = new SHSupportedVersionsStringizer();

    SupportedVersionsExtension() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$CHSupportedVersionsSpec.class */
    public static final class CHSupportedVersionsSpec implements SSLExtension.SSLExtensionSpec {
        final int[] requestedProtocols;

        private CHSupportedVersionsSpec(int[] requestedProtocols) {
            this.requestedProtocols = requestedProtocols;
        }

        private CHSupportedVersionsSpec(ByteBuffer m) throws IOException {
            if (m.remaining() < 3) {
                throw new SSLProtocolException("Invalid supported_versions extension: insufficient data");
            }
            byte[] vbs = Record.getBytes8(m);
            if (m.hasRemaining()) {
                throw new SSLProtocolException("Invalid supported_versions extension: unknown extra data");
            }
            if (vbs == null || vbs.length == 0 || (vbs.length & 1) != 0) {
                throw new SSLProtocolException("Invalid supported_versions extension: incomplete data");
            }
            int[] protocols = new int[vbs.length >> 1];
            int i = 0;
            int j = 0;
            while (i < vbs.length) {
                int i2 = i;
                int i3 = i + 1;
                byte major = vbs[i2];
                i = i3 + 1;
                byte minor = vbs[i3];
                int i4 = j;
                j++;
                protocols[i4] = ((major & 255) << 8) | (minor & 255);
            }
            this.requestedProtocols = protocols;
        }

        public String toString() {
            int[] iArr;
            MessageFormat messageFormat = new MessageFormat("\"versions\": '['{0}']'", Locale.ENGLISH);
            if (this.requestedProtocols == null || this.requestedProtocols.length == 0) {
                Object[] messageFields = {"<no supported version specified>"};
                return messageFormat.format(messageFields);
            }
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (int pv : this.requestedProtocols) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(", ");
                }
                builder.append(ProtocolVersion.nameOf(pv));
            }
            Object[] messageFields2 = {builder.toString()};
            return messageFormat.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$CHSupportedVersionsStringizer.class */
    private static final class CHSupportedVersionsStringizer implements SSLStringizer {
        private CHSupportedVersionsStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CHSupportedVersionsSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$CHSupportedVersionsProducer.class */
    private static final class CHSupportedVersionsProducer implements HandshakeProducer {
        private CHSupportedVersionsProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_SUPPORTED_VERSIONS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.CH_SUPPORTED_VERSIONS.name, new Object[0]);
                    return null;
                }
                return null;
            }
            int[] protocols = new int[chc.activeProtocols.size()];
            int verLen = protocols.length * 2;
            byte[] extData = new byte[verLen + 1];
            extData[0] = (byte) (verLen & GF2Field.MASK);
            int i = 0;
            int j = 1;
            for (ProtocolVersion pv : chc.activeProtocols) {
                int i2 = i;
                i++;
                protocols[i2] = pv.f978id;
                int i3 = j;
                int j2 = j + 1;
                extData[i3] = pv.major;
                j = j2 + 1;
                extData[j2] = pv.minor;
            }
            chc.handshakeExtensions.put(SSLExtension.CH_SUPPORTED_VERSIONS, new CHSupportedVersionsSpec(protocols));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$CHSupportedVersionsConsumer.class */
    private static final class CHSupportedVersionsConsumer implements SSLExtension.ExtensionConsumer {
        private CHSupportedVersionsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_SUPPORTED_VERSIONS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.CH_SUPPORTED_VERSIONS.name, new Object[0]);
                    return;
                }
                return;
            }
            try {
                CHSupportedVersionsSpec spec = new CHSupportedVersionsSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_SUPPORTED_VERSIONS, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$SHSupportedVersionsSpec.class */
    public static final class SHSupportedVersionsSpec implements SSLExtension.SSLExtensionSpec {
        final int selectedVersion;

        private SHSupportedVersionsSpec(ProtocolVersion selectedVersion) {
            this.selectedVersion = selectedVersion.f978id;
        }

        private SHSupportedVersionsSpec(ByteBuffer m) throws IOException {
            if (m.remaining() != 2) {
                throw new SSLProtocolException("Invalid supported_versions: insufficient data");
            }
            byte major = m.get();
            byte minor = m.get();
            this.selectedVersion = ((major & 255) << 8) | (minor & 255);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"selected version\": '['{0}']'", Locale.ENGLISH);
            Object[] messageFields = {ProtocolVersion.nameOf(this.selectedVersion)};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$SHSupportedVersionsStringizer.class */
    private static final class SHSupportedVersionsStringizer implements SSLStringizer {
        private SHSupportedVersionsStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new SHSupportedVersionsSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$SHSupportedVersionsProducer.class */
    private static final class SHSupportedVersionsProducer implements HandshakeProducer {
        private SHSupportedVersionsProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            CHSupportedVersionsSpec svs = (CHSupportedVersionsSpec) shc.handshakeExtensions.get(SSLExtension.CH_SUPPORTED_VERSIONS);
            if (svs == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore unavailable supported_versions extension", new Object[0]);
                    return null;
                }
                return null;
            } else if (!shc.sslConfig.isAvailable(SSLExtension.SH_SUPPORTED_VERSIONS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.SH_SUPPORTED_VERSIONS.name, new Object[0]);
                    return null;
                }
                return null;
            } else {
                byte[] extData = {shc.negotiatedProtocol.major, shc.negotiatedProtocol.minor};
                shc.handshakeExtensions.put(SSLExtension.SH_SUPPORTED_VERSIONS, new SHSupportedVersionsSpec(shc.negotiatedProtocol));
                return extData;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$SHSupportedVersionsConsumer.class */
    private static final class SHSupportedVersionsConsumer implements SSLExtension.ExtensionConsumer {
        private SHSupportedVersionsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.SH_SUPPORTED_VERSIONS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.SH_SUPPORTED_VERSIONS.name, new Object[0]);
                    return;
                }
                return;
            }
            try {
                SHSupportedVersionsSpec spec = new SHSupportedVersionsSpec(buffer);
                chc.handshakeExtensions.put(SSLExtension.SH_SUPPORTED_VERSIONS, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$HRRSupportedVersionsProducer.class */
    private static final class HRRSupportedVersionsProducer implements HandshakeProducer {
        private HRRSupportedVersionsProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.HRR_SUPPORTED_VERSIONS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.HRR_SUPPORTED_VERSIONS.name, new Object[0]);
                    return null;
                }
                return null;
            }
            byte[] extData = {shc.negotiatedProtocol.major, shc.negotiatedProtocol.minor};
            shc.handshakeExtensions.put(SSLExtension.HRR_SUPPORTED_VERSIONS, new SHSupportedVersionsSpec(shc.negotiatedProtocol));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$HRRSupportedVersionsConsumer.class */
    private static final class HRRSupportedVersionsConsumer implements SSLExtension.ExtensionConsumer {
        private HRRSupportedVersionsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.HRR_SUPPORTED_VERSIONS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.HRR_SUPPORTED_VERSIONS.name, new Object[0]);
                    return;
                }
                return;
            }
            try {
                SHSupportedVersionsSpec spec = new SHSupportedVersionsSpec(buffer);
                chc.handshakeExtensions.put(SSLExtension.HRR_SUPPORTED_VERSIONS, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SupportedVersionsExtension$HRRSupportedVersionsReproducer.class */
    private static final class HRRSupportedVersionsReproducer implements HandshakeProducer {
        private HRRSupportedVersionsReproducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.HRR_SUPPORTED_VERSIONS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("[Reproduce] Ignore unavailable extension: " + SSLExtension.HRR_SUPPORTED_VERSIONS.name, new Object[0]);
                    return null;
                }
                return null;
            }
            byte[] extData = {shc.negotiatedProtocol.major, shc.negotiatedProtocol.minor};
            return extData;
        }
    }
}