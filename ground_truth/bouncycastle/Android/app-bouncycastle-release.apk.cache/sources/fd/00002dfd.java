package org.bouncycastle.tls.crypto.impl;

/* loaded from: classes2.dex */
public interface TlsSuiteMac {
    byte[] calculateMac(long j, short s, byte[] bArr, byte[] bArr2, int i, int i2);

    byte[] calculateMacConstantTime(long j, short s, byte[] bArr, byte[] bArr2, int i, int i2, int i3, byte[] bArr3);

    int getSize();
}