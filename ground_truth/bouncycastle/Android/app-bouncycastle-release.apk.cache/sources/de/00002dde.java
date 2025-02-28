package org.bouncycastle.tls.crypto;

import java.io.IOException;

/* loaded from: classes2.dex */
public interface TlsEncryptor {
    byte[] encrypt(byte[] bArr, int i, int i2) throws IOException;
}