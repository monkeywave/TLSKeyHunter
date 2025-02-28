package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/AlphabetMapper.class */
public interface AlphabetMapper {
    int getRadix();

    byte[] convertToIndexes(char[] cArr);

    char[] convertToChars(byte[] bArr);
}