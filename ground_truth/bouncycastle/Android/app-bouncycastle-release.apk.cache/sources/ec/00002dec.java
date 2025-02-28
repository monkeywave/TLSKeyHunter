package org.bouncycastle.tls.crypto;

import java.io.IOException;

/* loaded from: classes2.dex */
public interface TlsSecret {
    byte[] calculateHMAC(int i, byte[] bArr, int i2, int i3);

    TlsSecret deriveUsingPRF(int i, String str, byte[] bArr, int i2);

    void destroy();

    byte[] encrypt(TlsEncryptor tlsEncryptor) throws IOException;

    byte[] extract();

    TlsSecret hkdfExpand(int i, byte[] bArr, int i2);

    TlsSecret hkdfExtract(int i, TlsSecret tlsSecret);

    boolean isAlive();
}