package org.openjsse.java.security.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/java/security/spec/RSAPublicKeySpec.class */
public class RSAPublicKeySpec extends java.security.spec.RSAPublicKeySpec {
    public RSAPublicKeySpec(BigInteger modulus, BigInteger publicExponent) {
        super(modulus, publicExponent);
    }

    public RSAPublicKeySpec(BigInteger modulus, BigInteger publicExponent, AlgorithmParameterSpec params) {
        super(modulus, publicExponent, params);
    }
}