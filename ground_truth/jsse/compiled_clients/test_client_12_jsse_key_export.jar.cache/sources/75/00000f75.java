package org.openjsse.java.security.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/java/security/spec/RSAPrivateKeySpec.class */
public class RSAPrivateKeySpec extends java.security.spec.RSAPrivateKeySpec {
    public RSAPrivateKeySpec(BigInteger modulus, BigInteger privateExponent) {
        super(modulus, privateExponent);
    }

    public RSAPrivateKeySpec(BigInteger modulus, BigInteger privateExponent, AlgorithmParameterSpec params) {
        super(modulus, privateExponent, params);
    }
}