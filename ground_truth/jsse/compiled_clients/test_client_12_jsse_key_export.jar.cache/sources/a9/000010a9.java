package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Locale;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.ClientHello;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloVerifyRequest.class */
final class HelloVerifyRequest {
    static final SSLConsumer handshakeConsumer = new HelloVerifyRequestConsumer();
    static final HandshakeProducer handshakeProducer = new HelloVerifyRequestProducer();

    HelloVerifyRequest() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloVerifyRequest$HelloVerifyRequestMessage.class */
    static final class HelloVerifyRequestMessage extends SSLHandshake.HandshakeMessage {
        final int serverVersion;
        final byte[] cookie;

        HelloVerifyRequestMessage(HandshakeContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            super(context);
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            HelloCookieManager hcMgr = shc.sslContext.getHelloCookieManager(ProtocolVersion.DTLS10);
            this.serverVersion = shc.clientHelloVersion;
            this.cookie = hcMgr.createCookie(shc, clientHello);
        }

        HelloVerifyRequestMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (m.remaining() < 3) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid HelloVerifyRequest: no sufficient data");
            }
            byte major = m.get();
            byte minor = m.get();
            this.serverVersion = ((major & 255) << 8) | (minor & 255);
            this.cookie = Record.getBytes8(m);
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.HELLO_VERIFY_REQUEST;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return 3 + this.cookie.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8((byte) ((this.serverVersion >>> 8) & GF2Field.MASK));
            hos.putInt8((byte) (this.serverVersion & GF2Field.MASK));
            hos.putBytes8(this.cookie);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"HelloVerifyRequest\": '{'\n  \"server version\"      : \"{0}\",\n  \"cookie\"              : \"{1}\",\n'}'", Locale.ENGLISH);
            Object[] messageFields = {ProtocolVersion.nameOf(this.serverVersion), Utilities.toHexString(this.cookie)};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloVerifyRequest$HelloVerifyRequestProducer.class */
    private static final class HelloVerifyRequestProducer implements HandshakeProducer {
        private HelloVerifyRequestProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.handshakeProducers.remove(Byte.valueOf(SSLHandshake.HELLO_VERIFY_REQUEST.f987id));
            HelloVerifyRequestMessage hvrm = new HelloVerifyRequestMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced HelloVerifyRequest handshake message", hvrm);
            }
            hvrm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeHash.finish();
            shc.handshakeExtensions.clear();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CLIENT_HELLO.f987id), SSLHandshake.CLIENT_HELLO);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloVerifyRequest$HelloVerifyRequestConsumer.class */
    private static final class HelloVerifyRequestConsumer implements SSLConsumer {
        private HelloVerifyRequestConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.HELLO_VERIFY_REQUEST.f987id));
            if (!chc.handshakeConsumers.isEmpty()) {
                chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.SERVER_HELLO.f987id));
            }
            if (!chc.handshakeConsumers.isEmpty()) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "No more message expected before HelloVerifyRequest is processed");
            }
            chc.handshakeHash.finish();
            HelloVerifyRequestMessage hvrm = new HelloVerifyRequestMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming HelloVerifyRequest handshake message", hvrm);
            }
            chc.initialClientHelloMsg.setHelloCookie(hvrm.cookie);
            SSLHandshake.CLIENT_HELLO.produce(context, hvrm);
        }
    }
}