package org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/encoders/Encoder.class */
public interface Encoder {
    int getEncodedLength(int i);

    int getMaxDecodedLength(int i);

    int encode(byte[] bArr, int i, int i2, OutputStream outputStream) throws IOException;

    int decode(byte[] bArr, int i, int i2, OutputStream outputStream) throws IOException;

    int decode(String str, OutputStream outputStream) throws IOException;
}