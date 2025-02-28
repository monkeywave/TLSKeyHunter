package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerKeyExchange.class */
final class ServerKeyExchange {
    static final SSLConsumer handshakeConsumer = new ServerKeyExchangeConsumer();
    static final HandshakeProducer handshakeProducer = new ServerKeyExchangeProducer();

    ServerKeyExchange() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerKeyExchange$ServerKeyExchangeProducer.class */
    private static final class ServerKeyExchangeProducer implements HandshakeProducer {
        private ServerKeyExchangeProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            Map.Entry<Byte, HandshakeProducer>[] handshakeProducers;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            SSLKeyExchange ke = SSLKeyExchange.valueOf(shc.negotiatedCipherSuite.keyExchange, shc.negotiatedProtocol);
            if (ke != null) {
                for (Map.Entry<Byte, HandshakeProducer> hc : ke.getHandshakeProducers(shc)) {
                    if (hc.getKey().byteValue() == SSLHandshake.SERVER_KEY_EXCHANGE.f987id) {
                        return hc.getValue().produce(context, message);
                    }
                }
            }
            throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No ServerKeyExchange handshake message can be produced.");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ServerKeyExchange$ServerKeyExchangeConsumer.class */
    private static final class ServerKeyExchangeConsumer implements SSLConsumer {
        private ServerKeyExchangeConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            Map.Entry<Byte, SSLConsumer>[] handshakeConsumers;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.SERVER_KEY_EXCHANGE.f987id));
            SSLConsumer certStatCons = chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id));
            if (certStatCons != null) {
                CertificateStatus.handshakeAbsence.absent(context, null);
            }
            SSLKeyExchange ke = SSLKeyExchange.valueOf(chc.negotiatedCipherSuite.keyExchange, chc.negotiatedProtocol);
            if (ke != null) {
                for (Map.Entry<Byte, SSLConsumer> hc : ke.getHandshakeConsumers(chc)) {
                    if (hc.getKey().byteValue() == SSLHandshake.SERVER_KEY_EXCHANGE.f987id) {
                        hc.getValue().consume(context, message);
                        return;
                    }
                }
            }
            throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected ServerKeyExchange handshake message.");
        }
    }
}