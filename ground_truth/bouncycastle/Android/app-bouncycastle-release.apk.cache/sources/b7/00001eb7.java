package org.bouncycastle.crypto.prng.drbg;

/* loaded from: classes2.dex */
public interface SP80090DRBG {
    int generate(byte[] bArr, byte[] bArr2, boolean z);

    int getBlockSize();

    void reseed(byte[] bArr);
}