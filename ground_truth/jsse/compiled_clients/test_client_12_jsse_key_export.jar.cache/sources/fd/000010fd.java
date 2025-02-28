package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Locale;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension.class */
final class PskKeyExchangeModesExtension {
    static final HandshakeProducer chNetworkProducer = new PskKeyExchangeModesProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new PskKeyExchangeModesConsumer();
    static final HandshakeAbsence chOnLoadAbsence = new PskKeyExchangeModesOnLoadAbsence();
    static final HandshakeAbsence chOnTradeAbsence = new PskKeyExchangeModesOnTradeAbsence();
    static final SSLStringizer pkemStringizer = new PskKeyExchangeModesStringizer();

    PskKeyExchangeModesExtension() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension$PskKeyExchangeMode.class */
    public enum PskKeyExchangeMode {
        PSK_KE((byte) 0, "psk_ke"),
        PSK_DHE_KE((byte) 1, "psk_dhe_ke");
        

        /* renamed from: id */
        final byte f979id;
        final String name;

        PskKeyExchangeMode(byte id, String name) {
            this.f979id = id;
            this.name = name;
        }

        static PskKeyExchangeMode valueOf(byte id) {
            PskKeyExchangeMode[] values;
            for (PskKeyExchangeMode pkem : values()) {
                if (pkem.f979id == id) {
                    return pkem;
                }
            }
            return null;
        }

        static String nameOf(byte id) {
            PskKeyExchangeMode[] values;
            for (PskKeyExchangeMode pkem : values()) {
                if (pkem.f979id == id) {
                    return pkem.name;
                }
            }
            return "<UNKNOWN PskKeyExchangeMode TYPE: " + (id & 255) + ">";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension$PskKeyExchangeModesSpec.class */
    static final class PskKeyExchangeModesSpec implements SSLExtension.SSLExtensionSpec {
        private static final PskKeyExchangeModesSpec DEFAULT = new PskKeyExchangeModesSpec(new byte[]{PskKeyExchangeMode.PSK_DHE_KE.f979id});
        final byte[] modes;

        PskKeyExchangeModesSpec(byte[] modes) {
            this.modes = modes;
        }

        PskKeyExchangeModesSpec(ByteBuffer m) throws IOException {
            if (m.remaining() < 2) {
                throw new SSLProtocolException("Invalid psk_key_exchange_modes extension: insufficient data");
            }
            this.modes = Record.getBytes8(m);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public boolean contains(PskKeyExchangeMode mode) {
            byte[] bArr;
            if (this.modes != null) {
                for (byte m : this.modes) {
                    if (mode.f979id == m) {
                        return true;
                    }
                }
                return false;
            }
            return false;
        }

        public String toString() {
            byte[] bArr;
            MessageFormat messageFormat = new MessageFormat("\"ke_modes\": '['{0}']'", Locale.ENGLISH);
            if (this.modes == null || this.modes.length == 0) {
                Object[] messageFields = {"<no PSK key exchange modes specified>"};
                return messageFormat.format(messageFields);
            }
            StringBuilder builder = new StringBuilder(64);
            boolean isFirst = true;
            for (byte mode : this.modes) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(", ");
                }
                builder.append(PskKeyExchangeMode.nameOf(mode));
            }
            Object[] messageFields2 = {builder.toString()};
            return messageFormat.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension$PskKeyExchangeModesStringizer.class */
    private static final class PskKeyExchangeModesStringizer implements SSLStringizer {
        private PskKeyExchangeModesStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new PskKeyExchangeModesSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension$PskKeyExchangeModesConsumer.class */
    private static final class PskKeyExchangeModesConsumer implements SSLExtension.ExtensionConsumer {
        private PskKeyExchangeModesConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.PSK_KEY_EXCHANGE_MODES)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable psk_key_exchange_modes extension", new Object[0]);
                }
                if (shc.isResumption && shc.resumingSession != null) {
                    shc.isResumption = false;
                    shc.resumingSession = null;
                    return;
                }
                return;
            }
            try {
                PskKeyExchangeModesSpec spec = new PskKeyExchangeModesSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.PSK_KEY_EXCHANGE_MODES, spec);
                if (shc.isResumption && !spec.contains(PskKeyExchangeMode.PSK_DHE_KE)) {
                    shc.isResumption = false;
                    shc.resumingSession = null;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("abort session resumption, no supported psk_dhe_ke PSK key exchange mode", new Object[0]);
                    }
                }
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension$PskKeyExchangeModesProducer.class */
    private static final class PskKeyExchangeModesProducer implements HandshakeProducer {
        private PskKeyExchangeModesProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.PSK_KEY_EXCHANGE_MODES)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Ignore unavailable psk_key_exchange_modes extension", new Object[0]);
                    return null;
                }
                return null;
            }
            byte[] extData = {1, 1};
            chc.handshakeExtensions.put(SSLExtension.PSK_KEY_EXCHANGE_MODES, PskKeyExchangeModesSpec.DEFAULT);
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension$PskKeyExchangeModesOnLoadAbsence.class */
    private static final class PskKeyExchangeModesOnLoadAbsence implements HandshakeAbsence {
        private PskKeyExchangeModesOnLoadAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.isResumption) {
                shc.isResumption = false;
                shc.resumingSession = null;
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("abort session resumption, no supported psk_dhe_ke PSK key exchange mode", new Object[0]);
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PskKeyExchangeModesExtension$PskKeyExchangeModesOnTradeAbsence.class */
    private static final class PskKeyExchangeModesOnTradeAbsence implements HandshakeAbsence {
        private PskKeyExchangeModesOnTradeAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            SSLExtension.SSLExtensionSpec spec = shc.handshakeExtensions.get(SSLExtension.CH_PRE_SHARED_KEY);
            if (spec != null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "pre_shared_key key extension is offered without a psk_key_exchange_modes extension");
            }
        }
    }
}