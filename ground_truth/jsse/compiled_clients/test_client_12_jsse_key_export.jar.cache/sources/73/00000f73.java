package org.openjsse.java.security.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/java/security/spec/RSAKeyGenParameterSpec.class */
public class RSAKeyGenParameterSpec extends java.security.spec.RSAKeyGenParameterSpec {
    public RSAKeyGenParameterSpec(int keysize, BigInteger publicExponent) {
        super(keysize, publicExponent);
    }

    public RSAKeyGenParameterSpec(int keysize, BigInteger publicExponent, AlgorithmParameterSpec keyParams) {
        super(keysize, publicExponent, keyParams);
    }
}