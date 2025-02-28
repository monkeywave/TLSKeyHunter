package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Locale;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Alert.class */
public enum Alert {
    CLOSE_NOTIFY((byte) 0, "close_notify", false),
    UNEXPECTED_MESSAGE((byte) 10, "unexpected_message", false),
    BAD_RECORD_MAC((byte) 20, "bad_record_mac", false),
    DECRYPTION_FAILED((byte) 21, "decryption_failed", false),
    RECORD_OVERFLOW((byte) 22, "record_overflow", false),
    DECOMPRESSION_FAILURE((byte) 30, "decompression_failure", false),
    HANDSHAKE_FAILURE((byte) 40, "handshake_failure", true),
    NO_CERTIFICATE((byte) 41, "no_certificate", true),
    BAD_CERTIFICATE((byte) 42, "bad_certificate", true),
    UNSUPPORTED_CERTIFICATE((byte) 43, "unsupported_certificate", true),
    CERTIFICATE_REVOKED((byte) 44, "certificate_revoked", true),
    CERTIFICATE_EXPIRED((byte) 45, "certificate_expired", true),
    CERTIFICATE_UNKNOWN((byte) 46, "certificate_unknown", true),
    ILLEGAL_PARAMETER((byte) 47, "illegal_parameter", true),
    UNKNOWN_CA((byte) 48, "unknown_ca", true),
    ACCESS_DENIED((byte) 49, "access_denied", true),
    DECODE_ERROR((byte) 50, "decode_error", true),
    DECRYPT_ERROR((byte) 51, "decrypt_error", true),
    EXPORT_RESTRICTION((byte) 60, "export_restriction", true),
    PROTOCOL_VERSION((byte) 70, "protocol_version", true),
    INSUFFICIENT_SECURITY((byte) 71, "insufficient_security", true),
    INTERNAL_ERROR((byte) 80, "internal_error", false),
    INAPPROPRIATE_FALLBACK((byte) 86, "inappropriate_fallback", false),
    USER_CANCELED((byte) 90, "user_canceled", false),
    NO_RENEGOTIATION((byte) 100, "no_renegotiation", true),
    MISSING_EXTENSION((byte) 109, "missing_extension", true),
    UNSUPPORTED_EXTENSION((byte) 110, "unsupported_extension", true),
    CERT_UNOBTAINABLE((byte) 111, "certificate_unobtainable", true),
    UNRECOGNIZED_NAME((byte) 112, "unrecognized_name", true),
    BAD_CERT_STATUS_RESPONSE((byte) 113, "bad_certificate_status_response", true),
    BAD_CERT_HASH_VALUE((byte) 114, "bad_certificate_hash_value", true),
    UNKNOWN_PSK_IDENTITY((byte) 115, "unknown_psk_identity", true),
    CERTIFICATE_REQUIRED((byte) 116, "certificate_required", true),
    NO_APPLICATION_PROTOCOL((byte) 120, "no_application_protocol", true);
    

    /* renamed from: id */
    final byte f960id;
    final String description;
    final boolean handshakeOnly;
    static final SSLConsumer alertConsumer = new AlertConsumer();

    Alert(byte id, String description, boolean handshakeOnly) {
        this.f960id = id;
        this.description = description;
        this.handshakeOnly = handshakeOnly;
    }

    static Alert valueOf(byte id) {
        Alert[] values;
        for (Alert al : values()) {
            if (al.f960id == id) {
                return al;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String nameOf(byte id) {
        Alert[] values;
        for (Alert al : values()) {
            if (al.f960id == id) {
                return al.description;
            }
        }
        return "UNKNOWN ALERT (" + (id & 255) + ")";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLException createSSLException(String reason) {
        return createSSLException(reason, null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLException createSSLException(String reason, Throwable cause) {
        SSLException ssle;
        if (reason == null) {
            reason = cause != null ? cause.getMessage() : "";
        }
        if (cause != null && (cause instanceof IOException)) {
            ssle = new SSLException(reason);
        } else if (this == UNEXPECTED_MESSAGE) {
            ssle = new SSLProtocolException(reason);
        } else if (this.handshakeOnly) {
            ssle = new SSLHandshakeException(reason);
        } else {
            ssle = new SSLException(reason);
        }
        if (cause != null) {
            ssle.initCause(cause);
        }
        return ssle;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Alert$Level.class */
    public enum Level {
        WARNING((byte) 1, "warning"),
        FATAL((byte) 2, "fatal");
        
        final byte level;
        final String description;

        Level(byte level, String description) {
            this.level = level;
            this.description = description;
        }

        static Level valueOf(byte level) {
            Level[] values;
            for (Level lv : values()) {
                if (lv.level == level) {
                    return lv;
                }
            }
            return null;
        }

        static String nameOf(byte level) {
            Level[] values;
            for (Level lv : values()) {
                if (lv.level == level) {
                    return lv.description;
                }
            }
            return "UNKNOWN ALERT LEVEL (" + (level & 255) + ")";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Alert$AlertMessage.class */
    private static final class AlertMessage {
        private final byte level;

        /* renamed from: id */
        private final byte f961id;

        AlertMessage(TransportContext context, ByteBuffer m) throws IOException {
            if (m.remaining() != 2) {
                throw context.fatal(Alert.ILLEGAL_PARAMETER, "Invalid Alert message: no sufficient data");
            }
            this.level = m.get();
            this.f961id = m.get();
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"Alert\": '{'\n  \"level\"      : \"{0}\",\n  \"description\": \"{1}\"\n'}'", Locale.ENGLISH);
            Object[] messageFields = {Level.nameOf(this.level), Alert.nameOf(this.f961id)};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Alert$AlertConsumer.class */
    private static final class AlertConsumer implements SSLConsumer {
        private AlertConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer m) throws IOException {
            String diagnostic;
            TransportContext tc = (TransportContext) context;
            AlertMessage am = new AlertMessage(tc, m);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("Received alert message", am);
            }
            Level level = Level.valueOf(am.level);
            Alert alert = Alert.valueOf(am.f961id);
            if (alert == Alert.CLOSE_NOTIFY) {
                tc.isInputCloseNotified = true;
                tc.closeInbound();
                if (tc.peerUserCanceled) {
                    tc.closeOutbound();
                } else if (tc.handshakeContext != null) {
                    throw tc.fatal(Alert.UNEXPECTED_MESSAGE, "Received close_notify during handshake");
                }
            } else if (alert == Alert.USER_CANCELED) {
                if (level == Level.WARNING) {
                    tc.peerUserCanceled = true;
                    return;
                }
                throw tc.fatal(alert, "Received fatal close_notify alert", true, null);
            } else if (level == Level.WARNING && alert != null) {
                if (alert.handshakeOnly && tc.handshakeContext != null) {
                    if (tc.sslConfig.isClientMode || alert != Alert.NO_CERTIFICATE || tc.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_REQUESTED) {
                        throw tc.fatal(Alert.HANDSHAKE_FAILURE, "received handshake warning: " + alert.description);
                    }
                    tc.handshakeContext.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id));
                    tc.handshakeContext.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id));
                }
            } else {
                if (alert == null) {
                    alert = Alert.UNEXPECTED_MESSAGE;
                    diagnostic = "Unknown alert description (" + ((int) am.f961id) + ")";
                } else {
                    diagnostic = "Received fatal alert: " + alert.description;
                }
                throw tc.fatal(alert, diagnostic, true, null);
            }
        }
    }
}