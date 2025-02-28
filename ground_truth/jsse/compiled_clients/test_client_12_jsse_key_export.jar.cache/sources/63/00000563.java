package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/Ed25519PublicKeyParameters.class */
public final class Ed25519PublicKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 32;
    private final byte[] data;

    public Ed25519PublicKeyParameters(byte[] bArr) {
        this(validate(bArr), 0);
    }

    public Ed25519PublicKeyParameters(byte[] bArr, int i) {
        super(false);
        this.data = new byte[32];
        System.arraycopy(bArr, i, this.data, 0, 32);
    }

    public Ed25519PublicKeyParameters(InputStream inputStream) throws IOException {
        super(false);
        this.data = new byte[32];
        if (32 != Streams.readFully(inputStream, this.data)) {
            throw new EOFException("EOF encountered in middle of Ed25519 public key");
        }
    }

    public void encode(byte[] bArr, int i) {
        System.arraycopy(this.data, 0, bArr, i, 32);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    private static byte[] validate(byte[] bArr) {
        if (bArr.length != 32) {
            throw new IllegalArgumentException("'buf' must have length 32");
        }
        return bArr;
    }
}