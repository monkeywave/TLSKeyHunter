package org.openjsse.util;

import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/util/RSAKeyUtil.class */
public class RSAKeyUtil {
    public static AlgorithmParameterSpec getParams(RSAKey rsaKey) {
        return rsaKey.getParams();
    }

    private RSAKeyUtil() {
    }
}