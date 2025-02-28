package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public final class CertificateVerify {
    private final int algorithm;
    private final byte[] signature;

    public CertificateVerify(int i, byte[] bArr) {
        if (!TlsUtils.isValidUint16(i)) {
            throw new IllegalArgumentException("'algorithm'");
        }
        if (bArr == null) {
            throw new NullPointerException("'signature' cannot be null");
        }
        this.algorithm = i;
        this.signature = bArr;
    }

    public static CertificateVerify parse(TlsContext tlsContext, InputStream inputStream) throws IOException {
        if (TlsUtils.isTLSv13(tlsContext)) {
            return new CertificateVerify(TlsUtils.readUint16(inputStream), TlsUtils.readOpaque16(inputStream));
        }
        throw new IllegalStateException();
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeUint16(this.algorithm, outputStream);
        TlsUtils.writeOpaque16(this.signature, outputStream);
    }

    public int getAlgorithm() {
        return this.algorithm;
    }

    public byte[] getSignature() {
        return this.signature;
    }
}