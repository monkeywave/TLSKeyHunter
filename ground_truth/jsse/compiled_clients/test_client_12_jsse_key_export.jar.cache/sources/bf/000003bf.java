package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/Xof.class */
public interface Xof extends ExtendedDigest {
    int doFinal(byte[] bArr, int i, int i2);

    int doOutput(byte[] bArr, int i, int i2);
}