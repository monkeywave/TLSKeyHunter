package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLConsumer.class */
interface SSLConsumer {
    void consume(ConnectionContext connectionContext, ByteBuffer byteBuffer) throws IOException;
}