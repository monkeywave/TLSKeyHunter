package org.openjsse.sun.security.ssl;

import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLHandshakeBinding.class */
interface SSLHandshakeBinding {
    default SSLHandshake[] getRelatedHandshakers(HandshakeContext handshakeContext) {
        return new SSLHandshake[0];
    }

    default Map.Entry<Byte, HandshakeProducer>[] getHandshakeProducers(HandshakeContext handshakeContext) {
        return new Map.Entry[0];
    }

    default Map.Entry<Byte, SSLConsumer>[] getHandshakeConsumers(HandshakeContext handshakeContext) {
        return new Map.Entry[0];
    }
}