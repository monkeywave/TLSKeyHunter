package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/CharToByteConverter.class */
public interface CharToByteConverter {
    String getType();

    byte[] convert(char[] cArr);
}