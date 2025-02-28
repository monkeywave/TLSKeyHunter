package org.openjsse.sun.security.ssl;

import java.io.IOException;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeAbsence.class */
public interface HandshakeAbsence {
    void absent(ConnectionContext connectionContext, SSLHandshake.HandshakeMessage handshakeMessage) throws IOException;
}