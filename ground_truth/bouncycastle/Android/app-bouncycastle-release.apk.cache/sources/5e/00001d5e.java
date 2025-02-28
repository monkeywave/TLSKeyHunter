package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class RFC3394WrapEngine implements Wrapper {
    private static final byte[] DEFAULT_IV = {-90, -90, -90, -90, -90, -90, -90, -90};
    private final BlockCipher engine;
    private boolean forWrapping;

    /* renamed from: iv */
    private final byte[] f674iv;
    private KeyParameter param;
    private final boolean wrapCipherMode;

    public RFC3394WrapEngine(BlockCipher blockCipher) {
        this(blockCipher, false);
    }

    public RFC3394WrapEngine(BlockCipher blockCipher, boolean z) {
        this.f674iv = new byte[8];
        this.param = null;
        this.forWrapping = true;
        this.engine = blockCipher;
        this.wrapCipherMode = !z;
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public String getAlgorithmName() {
        return this.engine.getAlgorithmName();
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forWrapping = z;
        if (cipherParameters instanceof ParametersWithRandom) {
            cipherParameters = ((ParametersWithRandom) cipherParameters).getParameters();
        }
        if (cipherParameters instanceof KeyParameter) {
            this.param = (KeyParameter) cipherParameters;
            System.arraycopy(DEFAULT_IV, 0, this.f674iv, 0, 8);
        } else if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            byte[] iv = parametersWithIV.getIV();
            if (iv.length != 8) {
                throw new IllegalArgumentException("IV not equal to 8");
            }
            this.param = (KeyParameter) parametersWithIV.getParameters();
            System.arraycopy(iv, 0, this.f674iv, 0, 8);
        }
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] unwrap(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] bArr2;
        if (this.forWrapping) {
            throw new IllegalStateException("not set for unwrapping");
        }
        if (i2 >= 16) {
            int i3 = i2 / 8;
            if (i3 * 8 == i2) {
                this.engine.init(!this.wrapCipherMode, this.param);
                byte[] bArr3 = this.f674iv;
                byte[] bArr4 = new byte[i2 - bArr3.length];
                byte[] bArr5 = new byte[bArr3.length];
                int i4 = 8;
                byte[] bArr6 = new byte[bArr3.length + 8];
                int i5 = i3 - 1;
                if (i5 == 1) {
                    this.engine.processBlock(bArr, i, bArr6, 0);
                    System.arraycopy(bArr6, 0, bArr5, 0, this.f674iv.length);
                    System.arraycopy(bArr6, this.f674iv.length, bArr4, 0, 8);
                } else {
                    System.arraycopy(bArr, i, bArr5, 0, bArr3.length);
                    byte[] bArr7 = this.f674iv;
                    System.arraycopy(bArr, bArr7.length + i, bArr4, 0, i2 - bArr7.length);
                    int i6 = 5;
                    while (i6 >= 0) {
                        int i7 = i5;
                        while (i7 >= 1) {
                            System.arraycopy(bArr5, 0, bArr6, 0, this.f674iv.length);
                            int i8 = (i7 - 1) * i4;
                            System.arraycopy(bArr4, i8, bArr6, this.f674iv.length, i4);
                            int i9 = (i5 * i6) + i7;
                            int i10 = 1;
                            while (i9 != 0) {
                                int length = this.f674iv.length - i10;
                                bArr6[length] = (byte) (bArr6[length] ^ ((byte) i9));
                                i9 >>>= 8;
                                i10++;
                            }
                            this.engine.processBlock(bArr6, 0, bArr6, 0);
                            System.arraycopy(bArr6, 0, bArr5, 0, 8);
                            System.arraycopy(bArr6, 8, bArr4, i8, 8);
                            i7--;
                            i4 = 8;
                        }
                        i6--;
                        i4 = 8;
                    }
                }
                if (i5 != 1) {
                    if (!Arrays.constantTimeAreEqual(bArr5, this.f674iv)) {
                        throw new InvalidCipherTextException("checksum failed");
                    }
                } else if (!Arrays.constantTimeAreEqual(bArr5, this.f674iv)) {
                    System.arraycopy(bArr, i, bArr5, 0, this.f674iv.length);
                    byte[] bArr8 = this.f674iv;
                    System.arraycopy(bArr, i + bArr8.length, bArr4, 0, i2 - bArr8.length);
                    int i11 = 5;
                    while (true) {
                        bArr2 = this.f674iv;
                        if (i11 < 0) {
                            break;
                        }
                        System.arraycopy(bArr5, 0, bArr6, 0, bArr2.length);
                        System.arraycopy(bArr4, 0, bArr6, this.f674iv.length, 8);
                        int i12 = (i5 * i11) + 1;
                        int i13 = 1;
                        while (i12 != 0) {
                            int length2 = this.f674iv.length - i13;
                            bArr6[length2] = (byte) (((byte) i12) ^ bArr6[length2]);
                            i12 >>>= 8;
                            i13++;
                        }
                        this.engine.processBlock(bArr6, 0, bArr6, 0);
                        System.arraycopy(bArr6, 0, bArr5, 0, 8);
                        System.arraycopy(bArr6, 8, bArr4, 0, 8);
                        i11--;
                    }
                    if (!Arrays.constantTimeAreEqual(bArr5, bArr2)) {
                        throw new InvalidCipherTextException("checksum failed");
                    }
                }
                return bArr4;
            }
            throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
        }
        throw new InvalidCipherTextException("unwrap data too short");
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] wrap(byte[] bArr, int i, int i2) {
        if (this.forWrapping) {
            if (i2 >= 8) {
                int i3 = i2 / 8;
                if (i3 * 8 == i2) {
                    this.engine.init(this.wrapCipherMode, this.param);
                    byte[] bArr2 = this.f674iv;
                    byte[] bArr3 = new byte[bArr2.length + i2];
                    System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length);
                    System.arraycopy(bArr, i, bArr3, this.f674iv.length, i2);
                    if (i3 == 1) {
                        this.engine.processBlock(bArr3, 0, bArr3, 0);
                    } else {
                        byte[] bArr4 = new byte[this.f674iv.length + 8];
                        for (int i4 = 0; i4 != 6; i4++) {
                            for (int i5 = 1; i5 <= i3; i5++) {
                                System.arraycopy(bArr3, 0, bArr4, 0, this.f674iv.length);
                                int i6 = i5 * 8;
                                System.arraycopy(bArr3, i6, bArr4, this.f674iv.length, 8);
                                this.engine.processBlock(bArr4, 0, bArr4, 0);
                                int i7 = (i3 * i4) + i5;
                                int i8 = 1;
                                while (i7 != 0) {
                                    int length = this.f674iv.length - i8;
                                    bArr4[length] = (byte) (((byte) i7) ^ bArr4[length]);
                                    i7 >>>= 8;
                                    i8++;
                                }
                                System.arraycopy(bArr4, 0, bArr3, 0, 8);
                                System.arraycopy(bArr4, 8, bArr3, i6, 8);
                            }
                        }
                    }
                    return bArr3;
                }
                throw new DataLengthException("wrap data must be a multiple of 8 bytes");
            }
            throw new DataLengthException("wrap data must be at least 8 bytes");
        }
        throw new IllegalStateException("not set for wrapping");
    }
}