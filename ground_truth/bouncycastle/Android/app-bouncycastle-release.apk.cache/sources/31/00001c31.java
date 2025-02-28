package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public interface CharToByteConverter {
    byte[] convert(char[] cArr);

    String getType();
}