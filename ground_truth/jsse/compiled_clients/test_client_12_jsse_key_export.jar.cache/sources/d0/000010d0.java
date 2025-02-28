package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import javassist.bytecode.AccessFlag;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension.class */
final class MaxFragExtension {
    static final HandshakeProducer chNetworkProducer = new CHMaxFragmentLengthProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHMaxFragmentLengthConsumer();
    static final HandshakeProducer shNetworkProducer = new SHMaxFragmentLengthProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHMaxFragmentLengthConsumer();
    static final HandshakeConsumer shOnTradeConsumer = new SHMaxFragmentLengthUpdate();
    static final HandshakeProducer eeNetworkProducer = new EEMaxFragmentLengthProducer();
    static final SSLExtension.ExtensionConsumer eeOnLoadConsumer = new EEMaxFragmentLengthConsumer();
    static final HandshakeConsumer eeOnTradeConsumer = new EEMaxFragmentLengthUpdate();
    static final SSLStringizer maxFragLenStringizer = new MaxFragLenStringizer();

    MaxFragExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$MaxFragLenSpec.class */
    static final class MaxFragLenSpec implements SSLExtension.SSLExtensionSpec {

        /* renamed from: id */
        byte f976id;

        private MaxFragLenSpec(byte id) {
            this.f976id = id;
        }

        private MaxFragLenSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() != 1) {
                throw new SSLProtocolException("Invalid max_fragment_length extension data");
            }
            this.f976id = buffer.get();
        }

        public String toString() {
            return MaxFragLenEnum.nameOf(this.f976id);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$MaxFragLenStringizer.class */
    private static final class MaxFragLenStringizer implements SSLStringizer {
        private MaxFragLenStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new MaxFragLenSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$MaxFragLenEnum.class */
    public enum MaxFragLenEnum {
        MFL_512((byte) 1, 512, "2^9"),
        MFL_1024((byte) 2, 1024, "2^10"),
        MFL_2048((byte) 3, 2048, "2^11"),
        MFL_4096((byte) 4, AccessFlag.SYNTHETIC, "2^12");
        

        /* renamed from: id */
        final byte f975id;
        final int fragmentSize;
        final String description;

        MaxFragLenEnum(byte id, int fragmentSize, String description) {
            this.f975id = id;
            this.fragmentSize = fragmentSize;
            this.description = description;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static MaxFragLenEnum valueOf(byte id) {
            MaxFragLenEnum[] values;
            for (MaxFragLenEnum mfl : values()) {
                if (mfl.f975id == id) {
                    return mfl;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String nameOf(byte id) {
            MaxFragLenEnum[] values;
            for (MaxFragLenEnum mfl : values()) {
                if (mfl.f975id == id) {
                    return mfl.description;
                }
            }
            return "UNDEFINED-MAX-FRAGMENT-LENGTH(" + ((int) id) + ")";
        }

        static MaxFragLenEnum valueOf(int fragmentSize) {
            if (fragmentSize <= 0) {
                return null;
            }
            if (fragmentSize < 1024) {
                return MFL_512;
            }
            if (fragmentSize < 2048) {
                return MFL_1024;
            }
            if (fragmentSize < 4096) {
                return MFL_2048;
            }
            if (fragmentSize == 4096) {
                return MFL_4096;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$CHMaxFragmentLengthProducer.class */
    private static final class CHMaxFragmentLengthProducer implements HandshakeProducer {
        private CHMaxFragmentLengthProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            int requestedMFLength;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_MAX_FRAGMENT_LENGTH)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable max_fragment_length extension", new Object[0]);
                    return null;
                }
                return null;
            }
            if (chc.isResumption && chc.resumingSession != null) {
                requestedMFLength = chc.resumingSession.getNegotiatedMaxFragSize();
            } else if (chc.sslConfig.maximumPacketSize != 0) {
                int requestedMFLength2 = chc.sslConfig.maximumPacketSize;
                if (chc.sslContext.isDTLS()) {
                    requestedMFLength = requestedMFLength2 - 333;
                } else {
                    requestedMFLength = requestedMFLength2 - 325;
                }
            } else {
                requestedMFLength = -1;
            }
            MaxFragLenEnum mfl = MaxFragLenEnum.valueOf(requestedMFLength);
            if (mfl != null) {
                chc.handshakeExtensions.put(SSLExtension.CH_MAX_FRAGMENT_LENGTH, new MaxFragLenSpec(mfl.f975id));
                return new byte[]{mfl.f975id};
            }
            chc.maxFragmentLength = -1;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("No available max_fragment_length extension can be used for fragment size of " + requestedMFLength + "bytes", new Object[0]);
                return null;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$CHMaxFragmentLengthConsumer.class */
    private static final class CHMaxFragmentLengthConsumer implements SSLExtension.ExtensionConsumer {
        private CHMaxFragmentLengthConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_MAX_FRAGMENT_LENGTH)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable max_fragment_length extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                MaxFragLenSpec spec = new MaxFragLenSpec(buffer);
                MaxFragLenEnum mfle = MaxFragLenEnum.valueOf(spec.f976id);
                if (mfle == null) {
                    throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "the requested maximum fragment length is other than the allowed values");
                }
                shc.maxFragmentLength = mfle.fragmentSize;
                shc.handshakeExtensions.put(SSLExtension.CH_MAX_FRAGMENT_LENGTH, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$SHMaxFragmentLengthProducer.class */
    private static final class SHMaxFragmentLengthProducer implements HandshakeProducer {
        private SHMaxFragmentLengthProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            MaxFragLenSpec spec = (MaxFragLenSpec) shc.handshakeExtensions.get(SSLExtension.CH_MAX_FRAGMENT_LENGTH);
            if (spec == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable max_fragment_length extension", new Object[0]);
                    return null;
                }
                return null;
            }
            if (shc.maxFragmentLength > 0 && shc.sslConfig.maximumPacketSize != 0) {
                int estimatedMaxFragSize = shc.negotiatedCipherSuite.calculatePacketSize(shc.maxFragmentLength, shc.negotiatedProtocol, shc.sslContext.isDTLS());
                if (estimatedMaxFragSize > shc.sslConfig.maximumPacketSize) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Abort the maximum fragment length negotiation, may overflow the maximum packet size limit.", new Object[0]);
                    }
                    shc.maxFragmentLength = -1;
                }
            }
            if (shc.maxFragmentLength > 0) {
                shc.handshakeSession.setNegotiatedMaxFragSize(shc.maxFragmentLength);
                shc.conContext.inputRecord.changeFragmentSize(shc.maxFragmentLength);
                shc.conContext.outputRecord.changeFragmentSize(shc.maxFragmentLength);
                shc.handshakeExtensions.put(SSLExtension.SH_MAX_FRAGMENT_LENGTH, spec);
                return new byte[]{spec.f976id};
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$SHMaxFragmentLengthConsumer.class */
    private static final class SHMaxFragmentLengthConsumer implements SSLExtension.ExtensionConsumer {
        private SHMaxFragmentLengthConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            MaxFragLenSpec requestedSpec = (MaxFragLenSpec) chc.handshakeExtensions.get(SSLExtension.CH_MAX_FRAGMENT_LENGTH);
            if (requestedSpec == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected max_fragment_length extension in ServerHello");
            }
            try {
                MaxFragLenSpec spec = new MaxFragLenSpec(buffer);
                if (spec.f976id == requestedSpec.f976id) {
                    MaxFragLenEnum mfle = MaxFragLenEnum.valueOf(spec.f976id);
                    if (mfle == null) {
                        throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "the requested maximum fragment length is other than the allowed values");
                    }
                    chc.maxFragmentLength = mfle.fragmentSize;
                    chc.handshakeExtensions.put(SSLExtension.SH_MAX_FRAGMENT_LENGTH, spec);
                    return;
                }
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "The maximum fragment length response is not requested");
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$SHMaxFragmentLengthUpdate.class */
    private static final class SHMaxFragmentLengthUpdate implements HandshakeConsumer {
        private SHMaxFragmentLengthUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            MaxFragLenSpec spec = (MaxFragLenSpec) chc.handshakeExtensions.get(SSLExtension.SH_MAX_FRAGMENT_LENGTH);
            if (spec == null) {
                return;
            }
            if (chc.maxFragmentLength > 0 && chc.sslConfig.maximumPacketSize != 0) {
                int estimatedMaxFragSize = chc.negotiatedCipherSuite.calculatePacketSize(chc.maxFragmentLength, chc.negotiatedProtocol, chc.sslContext.isDTLS());
                if (estimatedMaxFragSize > chc.sslConfig.maximumPacketSize) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Abort the maximum fragment length negotiation, may overflow the maximum packet size limit.", new Object[0]);
                    }
                    chc.maxFragmentLength = -1;
                }
            }
            if (chc.maxFragmentLength > 0) {
                chc.handshakeSession.setNegotiatedMaxFragSize(chc.maxFragmentLength);
                chc.conContext.inputRecord.changeFragmentSize(chc.maxFragmentLength);
                chc.conContext.outputRecord.changeFragmentSize(chc.maxFragmentLength);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$EEMaxFragmentLengthProducer.class */
    private static final class EEMaxFragmentLengthProducer implements HandshakeProducer {
        private EEMaxFragmentLengthProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            MaxFragLenSpec spec = (MaxFragLenSpec) shc.handshakeExtensions.get(SSLExtension.CH_MAX_FRAGMENT_LENGTH);
            if (spec == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable max_fragment_length extension", new Object[0]);
                    return null;
                }
                return null;
            }
            if (shc.maxFragmentLength > 0 && shc.sslConfig.maximumPacketSize != 0) {
                int estimatedMaxFragSize = shc.negotiatedCipherSuite.calculatePacketSize(shc.maxFragmentLength, shc.negotiatedProtocol, shc.sslContext.isDTLS());
                if (estimatedMaxFragSize > shc.sslConfig.maximumPacketSize) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Abort the maximum fragment length negotiation, may overflow the maximum packet size limit.", new Object[0]);
                    }
                    shc.maxFragmentLength = -1;
                }
            }
            if (shc.maxFragmentLength > 0) {
                shc.handshakeSession.setNegotiatedMaxFragSize(shc.maxFragmentLength);
                shc.conContext.inputRecord.changeFragmentSize(shc.maxFragmentLength);
                shc.conContext.outputRecord.changeFragmentSize(shc.maxFragmentLength);
                shc.handshakeExtensions.put(SSLExtension.EE_MAX_FRAGMENT_LENGTH, spec);
                return new byte[]{spec.f976id};
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$EEMaxFragmentLengthConsumer.class */
    private static final class EEMaxFragmentLengthConsumer implements SSLExtension.ExtensionConsumer {
        private EEMaxFragmentLengthConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            MaxFragLenSpec requestedSpec = (MaxFragLenSpec) chc.handshakeExtensions.get(SSLExtension.CH_MAX_FRAGMENT_LENGTH);
            if (requestedSpec == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected max_fragment_length extension in ServerHello");
            }
            try {
                MaxFragLenSpec spec = new MaxFragLenSpec(buffer);
                if (spec.f976id == requestedSpec.f976id) {
                    MaxFragLenEnum mfle = MaxFragLenEnum.valueOf(spec.f976id);
                    if (mfle == null) {
                        throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "the requested maximum fragment length is other than the allowed values");
                    }
                    chc.maxFragmentLength = mfle.fragmentSize;
                    chc.handshakeExtensions.put(SSLExtension.EE_MAX_FRAGMENT_LENGTH, spec);
                    return;
                }
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "The maximum fragment length response is not requested");
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/MaxFragExtension$EEMaxFragmentLengthUpdate.class */
    private static final class EEMaxFragmentLengthUpdate implements HandshakeConsumer {
        private EEMaxFragmentLengthUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            MaxFragLenSpec spec = (MaxFragLenSpec) chc.handshakeExtensions.get(SSLExtension.EE_MAX_FRAGMENT_LENGTH);
            if (spec == null) {
                return;
            }
            if (chc.maxFragmentLength > 0 && chc.sslConfig.maximumPacketSize != 0) {
                int estimatedMaxFragSize = chc.negotiatedCipherSuite.calculatePacketSize(chc.maxFragmentLength, chc.negotiatedProtocol, chc.sslContext.isDTLS());
                if (estimatedMaxFragSize > chc.sslConfig.maximumPacketSize) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Abort the maximum fragment length negotiation, may overflow the maximum packet size limit.", new Object[0]);
                    }
                    chc.maxFragmentLength = -1;
                }
            }
            if (chc.maxFragmentLength > 0) {
                chc.handshakeSession.setNegotiatedMaxFragSize(chc.maxFragmentLength);
                chc.conContext.inputRecord.changeFragmentSize(chc.maxFragmentLength);
                chc.conContext.outputRecord.changeFragmentSize(chc.maxFragmentLength);
            }
        }
    }
}