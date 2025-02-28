package org.bouncycastle.crypto.params;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.math.p016ec.rfc8032.Ed25519;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
public final class Ed25519PublicKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 32;
    private final Ed25519.PublicPoint publicPoint;

    public Ed25519PublicKeyParameters(InputStream inputStream) throws IOException {
        super(false);
        byte[] bArr = new byte[32];
        if (32 != Streams.readFully(inputStream, bArr)) {
            throw new EOFException("EOF encountered in middle of Ed25519 public key");
        }
        this.publicPoint = parse(bArr, 0);
    }

    public Ed25519PublicKeyParameters(Ed25519.PublicPoint publicPoint) {
        super(false);
        if (publicPoint == null) {
            throw new NullPointerException("'publicPoint' cannot be null");
        }
        this.publicPoint = publicPoint;
    }

    public Ed25519PublicKeyParameters(byte[] bArr) {
        this(validate(bArr), 0);
    }

    public Ed25519PublicKeyParameters(byte[] bArr, int i) {
        super(false);
        this.publicPoint = parse(bArr, i);
    }

    private static Ed25519.PublicPoint parse(byte[] bArr, int i) {
        Ed25519.PublicPoint validatePublicKeyPartialExport = Ed25519.validatePublicKeyPartialExport(bArr, i);
        if (validatePublicKeyPartialExport != null) {
            return validatePublicKeyPartialExport;
        }
        throw new IllegalArgumentException("invalid public key");
    }

    private static byte[] validate(byte[] bArr) {
        if (bArr.length == 32) {
            return bArr;
        }
        throw new IllegalArgumentException("'buf' must have length 32");
    }

    public void encode(byte[] bArr, int i) {
        Ed25519.encodePublicPoint(this.publicPoint, bArr, i);
    }

    public byte[] getEncoded() {
        byte[] bArr = new byte[32];
        encode(bArr, 0);
        return bArr;
    }

    public boolean verify(int i, byte[] bArr, byte[] bArr2, int i2, int i3, byte[] bArr3, int i4) {
        if (i == 0) {
            if (bArr == null) {
                return Ed25519.verify(bArr3, i4, this.publicPoint, bArr2, i2, i3);
            }
            throw new IllegalArgumentException("ctx");
        } else if (i == 1) {
            if (bArr != null) {
                if (bArr.length <= 255) {
                    return Ed25519.verify(bArr3, i4, this.publicPoint, bArr, bArr2, i2, i3);
                }
                throw new IllegalArgumentException("ctx");
            }
            throw new NullPointerException("'ctx' cannot be null");
        } else if (i == 2) {
            if (bArr != null) {
                if (bArr.length <= 255) {
                    if (64 == i3) {
                        return Ed25519.verifyPrehash(bArr3, i4, this.publicPoint, bArr, bArr2, i2);
                    }
                    throw new IllegalArgumentException("msgLen");
                }
                throw new IllegalArgumentException("ctx");
            }
            throw new NullPointerException("'ctx' cannot be null");
        } else {
            throw new IllegalArgumentException("algorithm");
        }
    }
}