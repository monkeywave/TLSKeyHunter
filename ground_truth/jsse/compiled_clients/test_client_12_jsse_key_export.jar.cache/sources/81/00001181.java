package org.openjsse.sun.security.ssl;

import java.io.IOException;
import javax.crypto.SecretKey;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyDerivationGenerator.class */
public interface SSLKeyDerivationGenerator {
    SSLKeyDerivation createKeyDerivation(HandshakeContext handshakeContext, SecretKey secretKey) throws IOException;
}