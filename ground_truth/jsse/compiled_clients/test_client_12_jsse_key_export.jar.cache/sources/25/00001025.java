package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientKeyExchange.class */
final class ClientKeyExchange {
    static final SSLConsumer handshakeConsumer = new ClientKeyExchangeConsumer();
    static final HandshakeProducer handshakeProducer = new ClientKeyExchangeProducer();

    ClientKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientKeyExchange$ClientKeyExchangeProducer.class */
    private static final class ClientKeyExchangeProducer implements HandshakeProducer {
        private ClientKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            Map.Entry<Byte, HandshakeProducer>[] handshakeProducers;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            SSLKeyExchange ke = SSLKeyExchange.valueOf(chc.negotiatedCipherSuite.keyExchange, chc.negotiatedProtocol);
            if (ke != null) {
                for (Map.Entry<Byte, HandshakeProducer> hp : ke.getHandshakeProducers(chc)) {
                    if (hp.getKey().byteValue() == SSLHandshake.CLIENT_KEY_EXCHANGE.f987id) {
                        return hp.getValue().produce(context, message);
                    }
                }
            }
            throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected ClientKeyExchange handshake message.");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ClientKeyExchange$ClientKeyExchangeConsumer.class */
    private static final class ClientKeyExchangeConsumer implements SSLConsumer {
        private ClientKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            Map.Entry<Byte, SSLConsumer>[] handshakeConsumers;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            shc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id));
            if (shc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id))) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected ClientKeyExchange handshake message.");
            }
            SSLKeyExchange ke = SSLKeyExchange.valueOf(shc.negotiatedCipherSuite.keyExchange, shc.negotiatedProtocol);
            if (ke != null) {
                for (Map.Entry<Byte, SSLConsumer> hc : ke.getHandshakeConsumers(shc)) {
                    if (hc.getKey().byteValue() == SSLHandshake.CLIENT_KEY_EXCHANGE.f987id) {
                        hc.getValue().consume(context, message);
                        return;
                    }
                }
            }
            throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected ClientKeyExchange handshake message.");
        }
    }
}