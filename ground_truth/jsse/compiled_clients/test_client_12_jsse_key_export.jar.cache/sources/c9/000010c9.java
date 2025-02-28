package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.openjsse.sun.security.ssl.SSLCipher;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyUpdate.class */
public final class KeyUpdate {
    static final SSLProducer kickstartProducer = new KeyUpdateKickstartProducer();
    static final SSLConsumer handshakeConsumer = new KeyUpdateConsumer();
    static final HandshakeProducer handshakeProducer = new KeyUpdateProducer();

    KeyUpdate() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyUpdate$KeyUpdateMessage.class */
    static final class KeyUpdateMessage extends SSLHandshake.HandshakeMessage {
        private final KeyUpdateRequest status;

        KeyUpdateMessage(PostHandshakeContext context, KeyUpdateRequest status) {
            super(context);
            this.status = status;
        }

        KeyUpdateMessage(PostHandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            if (m.remaining() != 1) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "KeyUpdate has an unexpected length of " + m.remaining());
            }
            byte request = m.get();
            this.status = KeyUpdateRequest.valueOf(request);
            if (this.status == null) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid KeyUpdate message value: " + KeyUpdateRequest.nameOf(request));
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.KEY_UPDATE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 1;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream s) throws IOException {
            s.putInt8(this.status.f974id);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"KeyUpdate\": '{'\n  \"request_update\": {0}\n'}'", Locale.ENGLISH);
            Object[] messageFields = {this.status.name};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyUpdate$KeyUpdateRequest.class */
    enum KeyUpdateRequest {
        NOTREQUESTED((byte) 0, "update_not_requested"),
        REQUESTED((byte) 1, "update_requested");
        

        /* renamed from: id */
        final byte f974id;
        final String name;

        KeyUpdateRequest(byte id, String name) {
            this.f974id = id;
            this.name = name;
        }

        static KeyUpdateRequest valueOf(byte id) {
            KeyUpdateRequest[] values;
            for (KeyUpdateRequest kur : values()) {
                if (kur.f974id == id) {
                    return kur;
                }
            }
            return null;
        }

        static String nameOf(byte id) {
            KeyUpdateRequest[] values;
            for (KeyUpdateRequest kur : values()) {
                if (kur.f974id == id) {
                    return kur.name;
                }
            }
            return "<UNKNOWN KeyUpdateRequest TYPE: " + (id & 255) + ">";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyUpdate$KeyUpdateKickstartProducer.class */
    private static final class KeyUpdateKickstartProducer implements SSLProducer {
        private KeyUpdateKickstartProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLProducer
        public byte[] produce(ConnectionContext context) throws IOException {
            PostHandshakeContext hc = (PostHandshakeContext) context;
            return KeyUpdate.handshakeProducer.produce(context, new KeyUpdateMessage(hc, KeyUpdateRequest.REQUESTED));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyUpdate$KeyUpdateConsumer.class */
    private static final class KeyUpdateConsumer implements SSLConsumer {
        private KeyUpdateConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            PostHandshakeContext hc = (PostHandshakeContext) context;
            KeyUpdateMessage km = new KeyUpdateMessage(hc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming KeyUpdate post-handshake message", km);
            }
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(hc.conContext.protocolVersion);
            if (kdg == null) {
                throw hc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + hc.conContext.protocolVersion);
            }
            SSLKeyDerivation skd = kdg.createKeyDerivation(hc, hc.conContext.inputRecord.readCipher.baseSecret);
            if (skd == null) {
                throw hc.conContext.fatal(Alert.INTERNAL_ERROR, "no key derivation");
            }
            SecretKey nplus1 = skd.deriveKey("TlsUpdateNplus1", null);
            SSLKeyDerivation kd = kdg.createKeyDerivation(hc, nplus1);
            SecretKey key = kd.deriveKey("TlsKey", null);
            IvParameterSpec ivSpec = new IvParameterSpec(kd.deriveKey("TlsIv", null).getEncoded());
            try {
                SSLCipher.SSLReadCipher rc = hc.negotiatedCipherSuite.bulkCipher.createReadCipher(Authenticator.valueOf(hc.conContext.protocolVersion), hc.conContext.protocolVersion, key, ivSpec, hc.sslContext.getSecureRandom());
                if (rc == null) {
                    throw hc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + hc.negotiatedCipherSuite + ") and protocol version (" + hc.negotiatedProtocol + ")");
                }
                rc.baseSecret = nplus1;
                hc.conContext.inputRecord.changeReadCiphers(rc);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("KeyUpdate: read key updated", new Object[0]);
                }
                if (km.status == KeyUpdateRequest.REQUESTED) {
                    KeyUpdate.handshakeProducer.produce(hc, new KeyUpdateMessage(hc, KeyUpdateRequest.NOTREQUESTED));
                } else {
                    hc.conContext.finishPostHandshake();
                }
            } catch (GeneralSecurityException gse) {
                throw hc.conContext.fatal(Alert.INTERNAL_ERROR, "Failure to derive read secrets", gse);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/KeyUpdate$KeyUpdateProducer.class */
    private static final class KeyUpdateProducer implements HandshakeProducer {
        private KeyUpdateProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            PostHandshakeContext hc = (PostHandshakeContext) context;
            KeyUpdateMessage km = (KeyUpdateMessage) message;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced KeyUpdate post-handshake message", km);
            }
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(hc.conContext.protocolVersion);
            if (kdg == null) {
                throw hc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + hc.conContext.protocolVersion);
            }
            SSLKeyDerivation skd = kdg.createKeyDerivation(hc, hc.conContext.outputRecord.writeCipher.baseSecret);
            if (skd == null) {
                throw hc.conContext.fatal(Alert.INTERNAL_ERROR, "no key derivation");
            }
            SecretKey nplus1 = skd.deriveKey("TlsUpdateNplus1", null);
            SSLKeyDerivation kd = kdg.createKeyDerivation(hc, nplus1);
            SecretKey key = kd.deriveKey("TlsKey", null);
            IvParameterSpec ivSpec = new IvParameterSpec(kd.deriveKey("TlsIv", null).getEncoded());
            try {
                SSLCipher.SSLWriteCipher wc = hc.negotiatedCipherSuite.bulkCipher.createWriteCipher(Authenticator.valueOf(hc.conContext.protocolVersion), hc.conContext.protocolVersion, key, ivSpec, hc.sslContext.getSecureRandom());
                if (wc == null) {
                    throw hc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + hc.negotiatedCipherSuite + ") and protocol version (" + hc.negotiatedProtocol + ")");
                }
                wc.baseSecret = nplus1;
                hc.conContext.outputRecord.changeWriteCiphers(wc, km.status.f974id);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("KeyUpdate: write key updated", new Object[0]);
                }
                hc.conContext.finishPostHandshake();
                return null;
            } catch (GeneralSecurityException gse) {
                throw hc.conContext.fatal(Alert.INTERNAL_ERROR, "Failure to derive write secrets", gse);
            }
        }
    }
}