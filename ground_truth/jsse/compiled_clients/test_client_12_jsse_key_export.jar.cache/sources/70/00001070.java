package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Locale;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/EncryptedExtensions.class */
final class EncryptedExtensions {
    static final HandshakeProducer handshakeProducer = new EncryptedExtensionsProducer();
    static final SSLConsumer handshakeConsumer = new EncryptedExtensionsConsumer();

    EncryptedExtensions() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/EncryptedExtensions$EncryptedExtensionsMessage.class */
    static final class EncryptedExtensionsMessage extends SSLHandshake.HandshakeMessage {
        private final SSLExtensions extensions;

        EncryptedExtensionsMessage(HandshakeContext handshakeContext) throws IOException {
            super(handshakeContext);
            this.extensions = new SSLExtensions(this);
        }

        EncryptedExtensionsMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.remaining() < 2) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid EncryptedExtensions handshake message: no sufficient data");
            }
            SSLExtension[] encryptedExtensions = handshakeContext.sslConfig.getEnabledExtensions(SSLHandshake.ENCRYPTED_EXTENSIONS);
            this.extensions = new SSLExtensions(this, m, encryptedExtensions);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.ENCRYPTED_EXTENSIONS;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        int messageLength() {
            int extLen = this.extensions.length();
            if (extLen == 0) {
                extLen = 2;
            }
            return extLen;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        void send(HandshakeOutStream hos) throws IOException {
            if (this.extensions.length() == 0) {
                hos.putInt16(0);
            } else {
                this.extensions.send(hos);
            }
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"EncryptedExtensions\": [\n{0}\n]", Locale.ENGLISH);
            Object[] messageFields = {Utilities.indent(this.extensions.toString())};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/EncryptedExtensions$EncryptedExtensionsProducer.class */
    private static final class EncryptedExtensionsProducer implements HandshakeProducer {
        private EncryptedExtensionsProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            EncryptedExtensionsMessage eem = new EncryptedExtensionsMessage(shc);
            SSLExtension[] extTypes = shc.sslConfig.getEnabledExtensions(SSLHandshake.ENCRYPTED_EXTENSIONS, shc.negotiatedProtocol);
            eem.extensions.produce(shc, extTypes);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced EncryptedExtensions message", eem);
            }
            eem.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/EncryptedExtensions$EncryptedExtensionsConsumer.class */
    private static final class EncryptedExtensionsConsumer implements SSLConsumer {
        private EncryptedExtensionsConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.ENCRYPTED_EXTENSIONS.f987id));
            EncryptedExtensionsMessage eem = new EncryptedExtensionsMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming EncryptedExtensions handshake message", eem);
            }
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(SSLHandshake.ENCRYPTED_EXTENSIONS);
            eem.extensions.consumeOnLoad(chc, extTypes);
            eem.extensions.consumeOnTrade(chc, extTypes);
        }
    }
}