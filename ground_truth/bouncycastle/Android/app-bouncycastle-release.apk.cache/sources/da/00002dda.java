package org.bouncycastle.tls.crypto;

/* loaded from: classes2.dex */
public final class TlsDecodeResult {
    public final byte[] buf;
    public final short contentType;
    public final int len;
    public final int off;

    public TlsDecodeResult(byte[] bArr, int i, int i2, short s) {
        this.buf = bArr;
        this.off = i;
        this.len = i2;
        this.contentType = s;
    }
}