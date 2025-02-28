package org.openjsse.javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/javax/crypto/spec/ChaCha20ParameterSpec.class */
public final class ChaCha20ParameterSpec implements AlgorithmParameterSpec {
    private static final int NONCE_LENGTH = 12;
    private final byte[] nonce;
    private final int counter;

    public ChaCha20ParameterSpec(byte[] nonce, int counter) {
        this.counter = counter;
        Objects.requireNonNull(nonce, "Nonce must be non-null");
        this.nonce = (byte[]) nonce.clone();
        if (this.nonce.length != 12) {
            throw new IllegalArgumentException("Nonce must be 12-bytes in length");
        }
    }

    public byte[] getNonce() {
        return (byte[]) this.nonce.clone();
    }

    public int getCounter() {
        return this.counter;
    }
}