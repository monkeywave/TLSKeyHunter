package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.AbstractMap;
import java.util.Map;
import javax.net.ssl.SSLException;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLHandshake.class */
public enum SSLHandshake implements SSLConsumer, HandshakeProducer {
    HELLO_REQUEST((byte) 0, "hello_request", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(HelloRequest.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(HelloRequest.handshakeProducer, ProtocolVersion.PROTOCOLS_TO_12)}),
    CLIENT_HELLO((byte) 1, "client_hello", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ClientHello.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ClientHello.handshakeProducer, ProtocolVersion.PROTOCOLS_TO_13)}),
    SERVER_HELLO((byte) 2, "server_hello", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerHello.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerHello.t12HandshakeProducer, ProtocolVersion.PROTOCOLS_TO_12), new AbstractMap.SimpleImmutableEntry(ServerHello.t13HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    HELLO_RETRY_REQUEST((byte) 2, "hello_retry_request", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerHello.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerHello.hrrHandshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    HELLO_VERIFY_REQUEST((byte) 3, "hello_verify_request", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(HelloVerifyRequest.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(HelloVerifyRequest.handshakeProducer, ProtocolVersion.PROTOCOLS_TO_12)}),
    NEW_SESSION_TICKET((byte) 4, "new_session_ticket", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(NewSessionTicket.handshakeConsumer, ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(NewSessionTicket.handshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    END_OF_EARLY_DATA((byte) 5, "end_of_early_data"),
    ENCRYPTED_EXTENSIONS((byte) 8, "encrypted_extensions", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(EncryptedExtensions.handshakeConsumer, ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(EncryptedExtensions.handshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    CERTIFICATE((byte) 11, "certificate", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateMessage.t12HandshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12), new AbstractMap.SimpleImmutableEntry(CertificateMessage.t13HandshakeConsumer, ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateMessage.t12HandshakeProducer, ProtocolVersion.PROTOCOLS_TO_12), new AbstractMap.SimpleImmutableEntry(CertificateMessage.t13HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    SERVER_KEY_EXCHANGE((byte) 12, "server_key_exchange", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerKeyExchange.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerKeyExchange.handshakeProducer, ProtocolVersion.PROTOCOLS_TO_12)}),
    CERTIFICATE_REQUEST((byte) 13, "certificate_request", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateRequest.t10HandshakeConsumer, ProtocolVersion.PROTOCOLS_TO_11), new AbstractMap.SimpleImmutableEntry(CertificateRequest.t12HandshakeConsumer, ProtocolVersion.PROTOCOLS_OF_12), new AbstractMap.SimpleImmutableEntry(CertificateRequest.t13HandshakeConsumer, ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateRequest.t10HandshakeProducer, ProtocolVersion.PROTOCOLS_TO_11), new AbstractMap.SimpleImmutableEntry(CertificateRequest.t12HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_12), new AbstractMap.SimpleImmutableEntry(CertificateRequest.t13HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    SERVER_HELLO_DONE((byte) 14, "server_hello_done", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerHelloDone.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ServerHelloDone.handshakeProducer, ProtocolVersion.PROTOCOLS_TO_12)}),
    CERTIFICATE_VERIFY((byte) 15, "certificate_verify", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateVerify.s30HandshakeConsumer, ProtocolVersion.PROTOCOLS_OF_30), new AbstractMap.SimpleImmutableEntry(CertificateVerify.t10HandshakeConsumer, ProtocolVersion.PROTOCOLS_10_11), new AbstractMap.SimpleImmutableEntry(CertificateVerify.t12HandshakeConsumer, ProtocolVersion.PROTOCOLS_OF_12), new AbstractMap.SimpleImmutableEntry(CertificateVerify.t13HandshakeConsumer, ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateVerify.s30HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_30), new AbstractMap.SimpleImmutableEntry(CertificateVerify.t10HandshakeProducer, ProtocolVersion.PROTOCOLS_10_11), new AbstractMap.SimpleImmutableEntry(CertificateVerify.t12HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_12), new AbstractMap.SimpleImmutableEntry(CertificateVerify.t13HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    CLIENT_KEY_EXCHANGE((byte) 16, "client_key_exchange", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ClientKeyExchange.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(ClientKeyExchange.handshakeProducer, ProtocolVersion.PROTOCOLS_TO_12)}),
    FINISHED((byte) 20, "finished", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Finished.t12HandshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12), new AbstractMap.SimpleImmutableEntry(Finished.t13HandshakeConsumer, ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Finished.t12HandshakeProducer, ProtocolVersion.PROTOCOLS_TO_12), new AbstractMap.SimpleImmutableEntry(Finished.t13HandshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    CERTIFICATE_URL((byte) 21, "certificate_url"),
    CERTIFICATE_STATUS((byte) 22, "certificate_status", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateStatus.handshakeConsumer, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateStatus.handshakeProducer, ProtocolVersion.PROTOCOLS_TO_12)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(CertificateStatus.handshakeAbsence, ProtocolVersion.PROTOCOLS_TO_12)}),
    SUPPLEMENTAL_DATA((byte) 23, "supplemental_data"),
    KEY_UPDATE((byte) 24, "key_update", new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(KeyUpdate.handshakeConsumer, ProtocolVersion.PROTOCOLS_OF_13)}, new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(KeyUpdate.handshakeProducer, ProtocolVersion.PROTOCOLS_OF_13)}),
    MESSAGE_HASH((byte) -2, "message_hash"),
    NOT_APPLICABLE((byte) -1, "not_applicable");
    

    /* renamed from: id */
    final byte f987id;
    final String name;
    final Map.Entry<SSLConsumer, ProtocolVersion[]>[] handshakeConsumers;
    final Map.Entry<HandshakeProducer, ProtocolVersion[]>[] handshakeProducers;
    final Map.Entry<HandshakeAbsence, ProtocolVersion[]>[] handshakeAbsences;

    SSLHandshake(byte id, String name) {
        this(id, name, new Map.Entry[0], new Map.Entry[0], new Map.Entry[0]);
    }

    SSLHandshake(byte id, String name, Map.Entry[] entryArr, Map.Entry[] entryArr2) {
        this(id, name, entryArr, entryArr2, new Map.Entry[0]);
    }

    SSLHandshake(byte id, String name, Map.Entry[] entryArr, Map.Entry[] entryArr2, Map.Entry[] entryArr3) {
        this.f987id = id;
        this.name = name;
        this.handshakeConsumers = entryArr;
        this.handshakeProducers = entryArr2;
        this.handshakeAbsences = entryArr3;
    }

    @Override // org.openjsse.sun.security.ssl.SSLConsumer
    public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
        SSLConsumer hc = getHandshakeConsumer(context);
        if (hc != null) {
            hc.consume(context, message);
            return;
        }
        throw new UnsupportedOperationException("Unsupported handshake consumer: " + this.name);
    }

    private SSLConsumer getHandshakeConsumer(ConnectionContext context) {
        ProtocolVersion protocolVersion;
        Map.Entry<SSLConsumer, ProtocolVersion[]>[] entryArr;
        ProtocolVersion[] value;
        if (this.handshakeConsumers.length == 0) {
            return null;
        }
        HandshakeContext hc = (HandshakeContext) context;
        if (hc.negotiatedProtocol == null || hc.negotiatedProtocol == ProtocolVersion.NONE) {
            if (hc.conContext.isNegotiated && hc.conContext.protocolVersion != ProtocolVersion.NONE) {
                protocolVersion = hc.conContext.protocolVersion;
            } else {
                protocolVersion = hc.maximumActiveProtocol;
            }
        } else {
            protocolVersion = hc.negotiatedProtocol;
        }
        for (Map.Entry<SSLConsumer, ProtocolVersion[]> phe : this.handshakeConsumers) {
            for (ProtocolVersion pv : phe.getValue()) {
                if (protocolVersion == pv) {
                    return phe.getKey();
                }
            }
        }
        return null;
    }

    @Override // org.openjsse.sun.security.ssl.HandshakeProducer
    public byte[] produce(ConnectionContext context, HandshakeMessage message) throws IOException {
        HandshakeProducer hp = getHandshakeProducer(context);
        if (hp != null) {
            return hp.produce(context, message);
        }
        throw new UnsupportedOperationException("Unsupported handshake producer: " + this.name);
    }

    private HandshakeProducer getHandshakeProducer(ConnectionContext context) {
        ProtocolVersion protocolVersion;
        Map.Entry<HandshakeProducer, ProtocolVersion[]>[] entryArr;
        ProtocolVersion[] value;
        if (this.handshakeConsumers.length == 0) {
            return null;
        }
        HandshakeContext hc = (HandshakeContext) context;
        if (hc.negotiatedProtocol == null || hc.negotiatedProtocol == ProtocolVersion.NONE) {
            if (hc.conContext.isNegotiated && hc.conContext.protocolVersion != ProtocolVersion.NONE) {
                protocolVersion = hc.conContext.protocolVersion;
            } else {
                protocolVersion = hc.maximumActiveProtocol;
            }
        } else {
            protocolVersion = hc.negotiatedProtocol;
        }
        for (Map.Entry<HandshakeProducer, ProtocolVersion[]> phe : this.handshakeProducers) {
            for (ProtocolVersion pv : phe.getValue()) {
                if (protocolVersion == pv) {
                    return phe.getKey();
                }
            }
        }
        return null;
    }

    @Override // java.lang.Enum
    public String toString() {
        return this.name;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String nameOf(byte id) {
        SSLHandshake[] values;
        for (SSLHandshake hs : values()) {
            if (hs.f987id == id) {
                return hs.name;
            }
        }
        return "UNKNOWN-HANDSHAKE-MESSAGE(" + ((int) id) + ")";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isKnown(byte id) {
        SSLHandshake[] values;
        for (SSLHandshake hs : values()) {
            if (hs.f987id == id && id != NOT_APPLICABLE.f987id) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static final void kickstart(HandshakeContext context) throws IOException {
        if (context instanceof ClientHandshakeContext) {
            if (context.conContext.isNegotiated && context.conContext.protocolVersion.useTLS13PlusSpec()) {
                KeyUpdate.kickstartProducer.produce(context);
            } else {
                ClientHello.kickstartProducer.produce(context);
            }
        } else if (context.conContext.protocolVersion.useTLS13PlusSpec()) {
            KeyUpdate.kickstartProducer.produce(context);
        } else {
            HelloRequest.kickstartProducer.produce(context);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLHandshake$HandshakeMessage.class */
    static abstract class HandshakeMessage {
        final HandshakeContext handshakeContext;

        /* JADX INFO: Access modifiers changed from: package-private */
        public abstract SSLHandshake handshakeType();

        abstract int messageLength();

        abstract void send(HandshakeOutStream handshakeOutStream) throws IOException;

        /* JADX INFO: Access modifiers changed from: package-private */
        public HandshakeMessage(HandshakeContext handshakeContext) {
            this.handshakeContext = handshakeContext;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public void write(HandshakeOutStream hos) throws IOException {
            int len = messageLength();
            if (len >= 16777216) {
                throw new SSLException("Handshake message is overflow, type = " + handshakeType() + ", len = " + len);
            }
            hos.write(handshakeType().f987id);
            hos.putInt24(len);
            send(hos);
            hos.complete();
        }
    }
}