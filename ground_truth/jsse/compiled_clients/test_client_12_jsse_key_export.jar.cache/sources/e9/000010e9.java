package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/PostHandshakeContext.class */
public final class PostHandshakeContext extends HandshakeContext {
    /* JADX INFO: Access modifiers changed from: package-private */
    public PostHandshakeContext(TransportContext context) throws IOException {
        super(context);
        if (!this.negotiatedProtocol.useTLS13PlusSpec()) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Post-handshake not supported in " + this.negotiatedProtocol.name);
        }
        this.localSupportedSignAlgs = new ArrayList(context.conSession.getLocalSupportedSignatureSchemes());
        this.handshakeConsumers = new LinkedHashMap<>();
        if (context.sslConfig.isClientMode) {
            this.handshakeConsumers.putIfAbsent(Byte.valueOf(SSLHandshake.KEY_UPDATE.f987id), SSLHandshake.KEY_UPDATE);
            this.handshakeConsumers.putIfAbsent(Byte.valueOf(SSLHandshake.NEW_SESSION_TICKET.f987id), SSLHandshake.NEW_SESSION_TICKET);
        } else {
            this.handshakeConsumers.putIfAbsent(Byte.valueOf(SSLHandshake.KEY_UPDATE.f987id), SSLHandshake.KEY_UPDATE);
        }
        this.handshakeFinished = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.HandshakeContext
    public void kickstart() throws IOException {
        SSLHandshake.kickstart(this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.HandshakeContext
    public void dispatch(byte handshakeType, ByteBuffer fragment) throws IOException {
        SSLConsumer consumer = this.handshakeConsumers.get(Byte.valueOf(handshakeType));
        if (consumer == null) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected post-handshake message: " + SSLHandshake.nameOf(handshakeType));
        }
        try {
            consumer.consume(this, fragment);
        } catch (UnsupportedOperationException unsoe) {
            throw this.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unsupported post-handshake message: " + SSLHandshake.nameOf(handshakeType), unsoe);
        } catch (BufferOverflowException | BufferUnderflowException be) {
            throw this.conContext.fatal(Alert.DECODE_ERROR, "Illegal handshake message: " + SSLHandshake.nameOf(handshakeType), be);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isConsumable(TransportContext context, byte handshakeType) {
        if (handshakeType == SSLHandshake.KEY_UPDATE.f987id) {
            return context.protocolVersion.useTLS13PlusSpec();
        }
        if (handshakeType == SSLHandshake.NEW_SESSION_TICKET.f987id) {
            return context.sslConfig.isClientMode;
        }
        return false;
    }
}