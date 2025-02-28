package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import org.bouncycastle.math.p010ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/Ed448PrivateKeyParameters.class */
public final class Ed448PrivateKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = 114;
    private final byte[] data;
    private Ed448PublicKeyParameters cachedPublicKey;

    public Ed448PrivateKeyParameters(SecureRandom secureRandom) {
        super(true);
        this.data = new byte[57];
        Ed448.generatePrivateKey(secureRandom, this.data);
    }

    public Ed448PrivateKeyParameters(byte[] bArr) {
        this(validate(bArr), 0);
    }

    public Ed448PrivateKeyParameters(byte[] bArr, int i) {
        super(true);
        this.data = new byte[57];
        System.arraycopy(bArr, i, this.data, 0, 57);
    }

    public Ed448PrivateKeyParameters(InputStream inputStream) throws IOException {
        super(true);
        this.data = new byte[57];
        if (57 != Streams.readFully(inputStream, this.data)) {
            throw new EOFException("EOF encountered in middle of Ed448 private key");
        }
    }

    public void encode(byte[] bArr, int i) {
        System.arraycopy(this.data, 0, bArr, i, 57);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    public Ed448PublicKeyParameters generatePublicKey() {
        Ed448PublicKeyParameters ed448PublicKeyParameters;
        synchronized (this.data) {
            if (null == this.cachedPublicKey) {
                byte[] bArr = new byte[57];
                Ed448.generatePublicKey(this.data, 0, bArr, 0);
                this.cachedPublicKey = new Ed448PublicKeyParameters(bArr, 0);
            }
            ed448PublicKeyParameters = this.cachedPublicKey;
        }
        return ed448PublicKeyParameters;
    }

    public void sign(int i, Ed448PublicKeyParameters ed448PublicKeyParameters, byte[] bArr, byte[] bArr2, int i2, int i3, byte[] bArr3, int i4) {
        sign(i, bArr, bArr2, i2, i3, bArr3, i4);
    }

    public void sign(int i, byte[] bArr, byte[] bArr2, int i2, int i3, byte[] bArr3, int i4) {
        byte[] bArr4 = new byte[57];
        generatePublicKey().encode(bArr4, 0);
        switch (i) {
            case 0:
                Ed448.sign(this.data, 0, bArr4, 0, bArr, bArr2, i2, i3, bArr3, i4);
                return;
            case 1:
                if (64 != i3) {
                    throw new IllegalArgumentException("msgLen");
                }
                Ed448.signPrehash(this.data, 0, bArr4, 0, bArr, bArr2, i2, bArr3, i4);
                return;
            default:
                throw new IllegalArgumentException("algorithm");
        }
    }

    private static byte[] validate(byte[] bArr) {
        if (bArr.length != 57) {
            throw new IllegalArgumentException("'buf' must have length 57");
        }
        return bArr;
    }
}