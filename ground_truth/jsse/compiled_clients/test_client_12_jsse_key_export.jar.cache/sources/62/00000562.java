package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import org.bouncycastle.math.p010ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.p012io.Streams;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/Ed25519PrivateKeyParameters.class */
public final class Ed25519PrivateKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 32;
    public static final int SIGNATURE_SIZE = 64;
    private final byte[] data;
    private Ed25519PublicKeyParameters cachedPublicKey;

    public Ed25519PrivateKeyParameters(SecureRandom secureRandom) {
        super(true);
        this.data = new byte[32];
        Ed25519.generatePrivateKey(secureRandom, this.data);
    }

    public Ed25519PrivateKeyParameters(byte[] bArr) {
        this(validate(bArr), 0);
    }

    public Ed25519PrivateKeyParameters(byte[] bArr, int i) {
        super(true);
        this.data = new byte[32];
        System.arraycopy(bArr, i, this.data, 0, 32);
    }

    public Ed25519PrivateKeyParameters(InputStream inputStream) throws IOException {
        super(true);
        this.data = new byte[32];
        if (32 != Streams.readFully(inputStream, this.data)) {
            throw new EOFException("EOF encountered in middle of Ed25519 private key");
        }
    }

    public void encode(byte[] bArr, int i) {
        System.arraycopy(this.data, 0, bArr, i, 32);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    public Ed25519PublicKeyParameters generatePublicKey() {
        Ed25519PublicKeyParameters ed25519PublicKeyParameters;
        synchronized (this.data) {
            if (null == this.cachedPublicKey) {
                byte[] bArr = new byte[32];
                Ed25519.generatePublicKey(this.data, 0, bArr, 0);
                this.cachedPublicKey = new Ed25519PublicKeyParameters(bArr, 0);
            }
            ed25519PublicKeyParameters = this.cachedPublicKey;
        }
        return ed25519PublicKeyParameters;
    }

    public void sign(int i, Ed25519PublicKeyParameters ed25519PublicKeyParameters, byte[] bArr, byte[] bArr2, int i2, int i3, byte[] bArr3, int i4) {
        sign(i, bArr, bArr2, i2, i3, bArr3, i4);
    }

    public void sign(int i, byte[] bArr, byte[] bArr2, int i2, int i3, byte[] bArr3, int i4) {
        byte[] bArr4 = new byte[32];
        generatePublicKey().encode(bArr4, 0);
        switch (i) {
            case 0:
                if (null != bArr) {
                    throw new IllegalArgumentException("ctx");
                }
                Ed25519.sign(this.data, 0, bArr4, 0, bArr2, i2, i3, bArr3, i4);
                return;
            case 1:
                Ed25519.sign(this.data, 0, bArr4, 0, bArr, bArr2, i2, i3, bArr3, i4);
                return;
            case 2:
                if (64 != i3) {
                    throw new IllegalArgumentException("msgLen");
                }
                Ed25519.signPrehash(this.data, 0, bArr4, 0, bArr, bArr2, i2, bArr3, i4);
                return;
            default:
                throw new IllegalArgumentException("algorithm");
        }
    }

    private static byte[] validate(byte[] bArr) {
        if (bArr.length != 32) {
            throw new IllegalArgumentException("'buf' must have length 32");
        }
        return bArr;
    }
}