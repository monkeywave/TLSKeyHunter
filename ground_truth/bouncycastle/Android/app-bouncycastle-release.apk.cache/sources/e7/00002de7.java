package org.bouncycastle.tls.crypto;

import java.io.IOException;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsFatalAlert;

/* loaded from: classes2.dex */
public class TlsNullNullCipher implements TlsCipher {
    public static final TlsNullNullCipher INSTANCE = new TlsNullNullCipher();

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsDecodeResult decodeCiphertext(long j, short s, ProtocolVersion protocolVersion, byte[] bArr, int i, int i2) throws IOException {
        return new TlsDecodeResult(bArr, i, i2, s);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public TlsEncodeResult encodePlaintext(long j, short s, ProtocolVersion protocolVersion, int i, byte[] bArr, int i2, int i3) throws IOException {
        int i4 = i + i3;
        byte[] bArr2 = new byte[i4];
        System.arraycopy(bArr, i2, bArr2, i, i3);
        return new TlsEncodeResult(bArr2, 0, i4, s);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextDecodeLimit(int i) {
        return i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getCiphertextEncodeLimit(int i) {
        return i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextDecodeLimit(int i) {
        return i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public int getPlaintextEncodeLimit(int i) {
        return i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public void rekeyDecoder() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public void rekeyEncoder() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public boolean usesOpaqueRecordTypeDecode() {
        return false;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCipher
    public boolean usesOpaqueRecordTypeEncode() {
        return false;
    }
}