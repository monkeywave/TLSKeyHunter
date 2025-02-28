package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/Ed448PublicKeyParameters.class */
public final class Ed448PublicKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 57;
    private final byte[] data;

    public Ed448PublicKeyParameters(byte[] bArr) {
        this(validate(bArr), 0);
    }

    public Ed448PublicKeyParameters(byte[] bArr, int i) {
        super(false);
        this.data = new byte[57];
        System.arraycopy(bArr, i, this.data, 0, 57);
    }

    public Ed448PublicKeyParameters(InputStream inputStream) throws IOException {
        super(false);
        this.data = new byte[57];
        if (57 != Streams.readFully(inputStream, this.data)) {
            throw new EOFException("EOF encountered in middle of Ed448 public key");
        }
    }

    public void encode(byte[] bArr, int i) {
        System.arraycopy(this.data, 0, bArr, i, 57);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    private static byte[] validate(byte[] bArr) {
        if (bArr.length != 57) {
            throw new IllegalArgumentException("'buf' must have length 57");
        }
        return bArr;
    }
}