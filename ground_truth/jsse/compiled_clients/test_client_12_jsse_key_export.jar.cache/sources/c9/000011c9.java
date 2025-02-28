package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHelloDone.class */
final class ServerHelloDone {
    static final SSLConsumer handshakeConsumer = new ServerHelloDoneConsumer();
    static final HandshakeProducer handshakeProducer = new ServerHelloDoneProducer();

    ServerHelloDone() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHelloDone$ServerHelloDoneMessage.class */
    static final class ServerHelloDoneMessage extends SSLHandshake.HandshakeMessage {
        ServerHelloDoneMessage(HandshakeContext handshakeContext) {
            super(handshakeContext);
        }

        ServerHelloDoneMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.hasRemaining()) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Error parsing ServerHelloDone message: not empty");
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.SERVER_HELLO_DONE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 0;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream s) throws IOException {
        }

        public String toString() {
            return "<empty>";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHelloDone$ServerHelloDoneProducer.class */
    private static final class ServerHelloDoneProducer implements HandshakeProducer {
        private ServerHelloDoneProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ServerHelloDoneMessage shdm = new ServerHelloDoneMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ServerHelloDone handshake message", shdm);
            }
            shdm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), SSLHandshake.CLIENT_KEY_EXCHANGE);
            shc.conContext.consumers.put(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id), ChangeCipherSpec.t10Consumer);
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerHelloDone$ServerHelloDoneConsumer.class */
    private static final class ServerHelloDoneConsumer implements SSLConsumer {
        private ServerHelloDoneConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            SSLConsumer certStatCons = chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id));
            if (certStatCons != null) {
                CertificateStatus.handshakeAbsence.absent(context, null);
            }
            chc.handshakeConsumers.clear();
            ServerHelloDoneMessage shdm = new ServerHelloDoneMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ServerHelloDone handshake message", shdm);
            }
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), SSLHandshake.CLIENT_KEY_EXCHANGE);
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
            SSLHandshake[] probableHandshakeMessages = {SSLHandshake.CERTIFICATE, SSLHandshake.CLIENT_KEY_EXCHANGE, SSLHandshake.CERTIFICATE_VERIFY, SSLHandshake.FINISHED};
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer = chc.handshakeProducers.remove(Byte.valueOf(hs.f987id));
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, null);
                }
            }
        }
    }
}