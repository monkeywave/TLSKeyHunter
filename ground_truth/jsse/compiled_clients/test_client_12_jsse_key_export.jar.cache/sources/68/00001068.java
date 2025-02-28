package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Locale;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECPointFormatsExtension.class */
final class ECPointFormatsExtension {
    static final HandshakeProducer chNetworkProducer = new CHECPointFormatsProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHECPointFormatsConsumer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHECPointFormatsConsumer();
    static final SSLStringizer epfStringizer = new ECPointFormatsStringizer();

    ECPointFormatsExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECPointFormatsExtension$ECPointFormatsSpec.class */
    static class ECPointFormatsSpec implements SSLExtension.SSLExtensionSpec {
        static final ECPointFormatsSpec DEFAULT = new ECPointFormatsSpec(new byte[]{ECPointFormat.UNCOMPRESSED.f970id});
        final byte[] formats;

        ECPointFormatsSpec(byte[] formats) {
            this.formats = formats;
        }

        private ECPointFormatsSpec(ByteBuffer m) throws IOException {
            if (!m.hasRemaining()) {
                throw new SSLProtocolException("Invalid ec_point_formats extension: insufficient data");
            }
            this.formats = Record.getBytes8(m);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean hasUncompressedFormat() {
            byte[] bArr;
            for (byte format : this.formats) {
                if (format == ECPointFormat.UNCOMPRESSED.f970id) {
                    return true;
                }
            }
            return false;
        }

        public String toString() {
            byte[] bArr;
            MessageFormat messageFormat = new MessageFormat("\"formats\": '['{0}']'", Locale.ENGLISH);
            if (this.formats == null || this.formats.length == 0) {
                Object[] messageFields = {"<no EC point format specified>"};
                return messageFormat.format(messageFields);
            }
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (byte pf : this.formats) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(", ");
                }
                builder.append(ECPointFormat.nameOf(pf));
            }
            Object[] messageFields2 = {builder.toString()};
            return messageFormat.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECPointFormatsExtension$ECPointFormatsStringizer.class */
    private static final class ECPointFormatsStringizer implements SSLStringizer {
        private ECPointFormatsStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new ECPointFormatsSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECPointFormatsExtension$ECPointFormat.class */
    public enum ECPointFormat {
        UNCOMPRESSED((byte) 0, "uncompressed"),
        ANSIX962_COMPRESSED_PRIME((byte) 1, "ansiX962_compressed_prime"),
        FMT_ANSIX962_COMPRESSED_CHAR2((byte) 2, "ansiX962_compressed_char2");
        

        /* renamed from: id */
        final byte f970id;
        final String name;

        ECPointFormat(byte id, String name) {
            this.f970id = id;
            this.name = name;
        }

        static String nameOf(int id) {
            ECPointFormat[] values;
            for (ECPointFormat pf : values()) {
                if (pf.f970id == id) {
                    return pf.name;
                }
            }
            return "UNDEFINED-EC-POINT-FORMAT(" + id + ")";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECPointFormatsExtension$CHECPointFormatsProducer.class */
    private static final class CHECPointFormatsProducer implements HandshakeProducer {
        private CHECPointFormatsProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_EC_POINT_FORMATS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable ec_point_formats extension", new Object[0]);
                    return null;
                }
                return null;
            } else if (SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE.isSupported(chc.activeCipherSuites)) {
                byte[] extData = {1, 0};
                chc.handshakeExtensions.put(SSLExtension.CH_EC_POINT_FORMATS, ECPointFormatsSpec.DEFAULT);
                return extData;
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Need no ec_point_formats extension", new Object[0]);
                return null;
            } else {
                return null;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECPointFormatsExtension$CHECPointFormatsConsumer.class */
    private static final class CHECPointFormatsConsumer implements SSLExtension.ExtensionConsumer {
        private CHECPointFormatsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_EC_POINT_FORMATS)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable ec_point_formats extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                ECPointFormatsSpec spec = new ECPointFormatsSpec(buffer);
                if (!spec.hasUncompressedFormat()) {
                    throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid ec_point_formats extension data: peer does not support uncompressed points");
                }
                shc.handshakeExtensions.put(SSLExtension.CH_EC_POINT_FORMATS, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ECPointFormatsExtension$SHECPointFormatsConsumer.class */
    private static final class SHECPointFormatsConsumer implements SSLExtension.ExtensionConsumer {
        private SHECPointFormatsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            ECPointFormatsSpec requestedSpec = (ECPointFormatsSpec) chc.handshakeExtensions.get(SSLExtension.CH_EC_POINT_FORMATS);
            if (requestedSpec == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected ec_point_formats extension in ServerHello");
            }
            try {
                ECPointFormatsSpec spec = new ECPointFormatsSpec(buffer);
                if (!spec.hasUncompressedFormat()) {
                    throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid ec_point_formats extension data: peer does not support uncompressed points");
                }
                chc.handshakeExtensions.put(SSLExtension.CH_EC_POINT_FORMATS, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }
}