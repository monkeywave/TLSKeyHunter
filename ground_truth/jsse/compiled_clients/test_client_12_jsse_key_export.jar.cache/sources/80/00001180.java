package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyDerivation.class */
interface SSLKeyDerivation {
    SecretKey deriveKey(String str, AlgorithmParameterSpec algorithmParameterSpec) throws IOException;
}