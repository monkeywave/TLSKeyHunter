package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloRequest.class */
public final class HelloRequest {
    static final SSLProducer kickstartProducer = new HelloRequestKickstartProducer();
    static final SSLConsumer handshakeConsumer = new HelloRequestConsumer();
    static final HandshakeProducer handshakeProducer = new HelloRequestProducer();

    HelloRequest() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloRequest$HelloRequestMessage.class */
    static final class HelloRequestMessage extends SSLHandshake.HandshakeMessage {
        HelloRequestMessage(HandshakeContext handshakeContext) {
            super(handshakeContext);
        }

        HelloRequestMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.hasRemaining()) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Error parsing HelloRequest message: not empty");
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.HELLO_REQUEST;
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

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloRequest$HelloRequestKickstartProducer.class */
    private static final class HelloRequestKickstartProducer implements SSLProducer {
        private HelloRequestKickstartProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLProducer
        public byte[] produce(ConnectionContext context) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            HelloRequestMessage hrm = new HelloRequestMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced HelloRequest handshake message", hrm);
            }
            hrm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id), SSLHandshake.CLIENT_HELLO);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloRequest$HelloRequestProducer.class */
    private static final class HelloRequestProducer implements HandshakeProducer {
        private HelloRequestProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            HelloRequestMessage hrm = new HelloRequestMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced HelloRequest handshake message", hrm);
            }
            hrm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id), SSLHandshake.CLIENT_HELLO);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloRequest$HelloRequestConsumer.class */
    private static final class HelloRequestConsumer implements SSLConsumer {
        private HelloRequestConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            HelloRequestMessage hrm = new HelloRequestMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming HelloRequest handshake message", hrm);
            }
            if (!chc.kickstartMessageDelivered) {
                if (!chc.conContext.secureRenegotiation && !HandshakeContext.allowUnsafeRenegotiation) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsafe renegotiation is not allowed");
                }
                if (!chc.conContext.secureRenegotiation && SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("Continue with insecure renegotiation", new Object[0]);
                }
                chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id), SSLHandshake.CLIENT_HELLO);
                SSLHandshake.CLIENT_HELLO.produce(context, hrm);
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Ingore HelloRequest, handshaking is in progress", new Object[0]);
            }
        }
    }
}