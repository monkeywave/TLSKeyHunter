package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

/* loaded from: classes2.dex */
public interface TlsBlockCipherImpl {
    int doFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws IOException;

    int getBlockSize();

    void init(byte[] bArr, int i, int i2) throws IOException;

    void setKey(byte[] bArr, int i, int i2) throws IOException;
}