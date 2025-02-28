package org.bouncycastle.tls.crypto;

/* loaded from: classes2.dex */
public interface TlsHash {
    byte[] calculateHash();

    TlsHash cloneHash();

    void reset();

    void update(byte[] bArr, int i, int i2);
}