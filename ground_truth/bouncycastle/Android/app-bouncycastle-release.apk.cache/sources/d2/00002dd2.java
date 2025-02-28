package org.bouncycastle.tls.crypto;

import java.io.IOException;
import org.bouncycastle.tls.ProtocolVersion;

/* loaded from: classes2.dex */
public interface TlsCipher {
    TlsDecodeResult decodeCiphertext(long j, short s, ProtocolVersion protocolVersion, byte[] bArr, int i, int i2) throws IOException;

    TlsEncodeResult encodePlaintext(long j, short s, ProtocolVersion protocolVersion, int i, byte[] bArr, int i2, int i3) throws IOException;

    int getCiphertextDecodeLimit(int i);

    int getCiphertextEncodeLimit(int i);

    int getPlaintextDecodeLimit(int i);

    int getPlaintextEncodeLimit(int i);

    void rekeyDecoder() throws IOException;

    void rekeyEncoder() throws IOException;

    boolean usesOpaqueRecordTypeDecode();

    boolean usesOpaqueRecordTypeEncode();
}