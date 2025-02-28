package org.openjsse.sun.security.ssl;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyAgreementGenerator.class */
interface SSLKeyAgreementGenerator {
    SSLKeyDerivation createKeyDerivation(HandshakeContext handshakeContext) throws IOException;
}