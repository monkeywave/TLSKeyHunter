package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public interface AlphabetMapper {
    char[] convertToChars(byte[] bArr);

    byte[] convertToIndexes(char[] cArr);

    int getRadix();
}