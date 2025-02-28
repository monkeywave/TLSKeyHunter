package org.bouncycastle.tls.crypto;

/* loaded from: classes2.dex */
public final class TlsEncodeResult {
    public final byte[] buf;
    public final int len;
    public final int off;
    public final short recordType;

    public TlsEncodeResult(byte[] bArr, int i, int i2, short s) {
        this.buf = bArr;
        this.off = i;
        this.len = i2;
        this.recordType = s;
    }
}