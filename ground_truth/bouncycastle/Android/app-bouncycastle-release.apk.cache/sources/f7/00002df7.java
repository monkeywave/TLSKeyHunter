package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

/* loaded from: classes2.dex */
public interface TlsAEADCipherImpl {
    int doFinal(byte[] bArr, byte[] bArr2, int i, int i2, byte[] bArr3, int i3) throws IOException;

    int getOutputSize(int i);

    void init(byte[] bArr, int i) throws IOException;

    void setKey(byte[] bArr, int i, int i2) throws IOException;
}