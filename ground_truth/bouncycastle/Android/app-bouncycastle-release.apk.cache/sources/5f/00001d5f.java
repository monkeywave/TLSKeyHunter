package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class RFC5649WrapEngine implements Wrapper {
    private static final byte[] DEFAULT_IV = {-90, 89, 89, -90};
    private final BlockCipher engine;
    private final byte[] preIV = new byte[4];
    private KeyParameter param = null;
    private boolean forWrapping = true;

    public RFC5649WrapEngine(BlockCipher blockCipher) {
        this.engine = blockCipher;
    }

    private byte[] padPlaintext(byte[] bArr) {
        int length = bArr.length;
        int i = (8 - (length % 8)) % 8;
        byte[] bArr2 = new byte[length + i];
        System.arraycopy(bArr, 0, bArr2, 0, length);
        if (i != 0) {
            System.arraycopy(new byte[i], 0, bArr2, length, i);
        }
        return bArr2;
    }

    private byte[] rfc3394UnwrapNoIvCheck(byte[] bArr, int i, int i2, byte[] bArr2) {
        int i3 = i2 - 8;
        byte[] bArr3 = new byte[i3];
        byte[] bArr4 = new byte[16];
        System.arraycopy(bArr, i, bArr4, 0, 8);
        System.arraycopy(bArr, i + 8, bArr3, 0, i3);
        this.engine.init(false, this.param);
        int i4 = (i2 / 8) - 1;
        for (int i5 = 5; i5 >= 0; i5--) {
            for (int i6 = i4; i6 >= 1; i6--) {
                int i7 = (i6 - 1) * 8;
                System.arraycopy(bArr3, i7, bArr4, 8, 8);
                int i8 = (i4 * i5) + i6;
                int i9 = 1;
                while (i8 != 0) {
                    int i10 = 8 - i9;
                    bArr4[i10] = (byte) (bArr4[i10] ^ ((byte) i8));
                    i8 >>>= 8;
                    i9++;
                }
                this.engine.processBlock(bArr4, 0, bArr4, 0);
                System.arraycopy(bArr4, 8, bArr3, i7, 8);
            }
        }
        System.arraycopy(bArr4, 0, bArr2, 0, 8);
        return bArr3;
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
            System.arraycopy(DEFAULT_IV, 0, this.preIV, 0, 4);
        } else if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            byte[] iv = parametersWithIV.getIV();
            if (iv.length != 4) {
                throw new IllegalArgumentException("IV length not equal to 4");
            }
            this.param = (KeyParameter) parametersWithIV.getParameters();
            System.arraycopy(iv, 0, this.preIV, 0, 4);
        }
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] unwrap(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] rfc3394UnwrapNoIvCheck;
        if (this.forWrapping) {
            throw new IllegalStateException("not set for unwrapping");
        }
        int i3 = i2 / 8;
        if (i3 * 8 == i2) {
            if (i3 > 1) {
                byte[] bArr2 = new byte[i2];
                System.arraycopy(bArr, i, bArr2, 0, i2);
                byte[] bArr3 = new byte[i2];
                byte[] bArr4 = new byte[8];
                if (i3 == 2) {
                    this.engine.init(false, this.param);
                    int blockSize = this.engine.getBlockSize();
                    for (int i4 = 0; i4 < i2; i4 += blockSize) {
                        this.engine.processBlock(bArr2, i4, bArr3, i4);
                    }
                    System.arraycopy(bArr3, 0, bArr4, 0, 8);
                    int i5 = i2 - 8;
                    rfc3394UnwrapNoIvCheck = new byte[i5];
                    System.arraycopy(bArr3, 8, rfc3394UnwrapNoIvCheck, 0, i5);
                } else {
                    rfc3394UnwrapNoIvCheck = rfc3394UnwrapNoIvCheck(bArr, i, i2, bArr4);
                }
                int i6 = 4;
                byte[] bArr5 = new byte[4];
                System.arraycopy(bArr4, 0, bArr5, 0, 4);
                int bigEndianToInt = Pack.bigEndianToInt(bArr4, 4);
                boolean constantTimeAreEqual = Arrays.constantTimeAreEqual(bArr5, this.preIV);
                int length = rfc3394UnwrapNoIvCheck.length;
                if (bigEndianToInt <= length - 8) {
                    constantTimeAreEqual = false;
                }
                if (bigEndianToInt > length) {
                    constantTimeAreEqual = false;
                }
                int i7 = length - bigEndianToInt;
                if (i7 >= 8 || i7 < 0) {
                    constantTimeAreEqual = false;
                } else {
                    i6 = i7;
                }
                byte[] bArr6 = new byte[i6];
                System.arraycopy(rfc3394UnwrapNoIvCheck, rfc3394UnwrapNoIvCheck.length - i6, bArr6, 0, i6);
                if (!Arrays.constantTimeAreEqual(bArr6, new byte[i6])) {
                    constantTimeAreEqual = false;
                }
                if (constantTimeAreEqual) {
                    byte[] bArr7 = new byte[bigEndianToInt];
                    System.arraycopy(rfc3394UnwrapNoIvCheck, 0, bArr7, 0, bigEndianToInt);
                    return bArr7;
                }
                throw new InvalidCipherTextException("checksum failed");
            }
            throw new InvalidCipherTextException("unwrap data must be at least 16 bytes");
        }
        throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] wrap(byte[] bArr, int i, int i2) {
        if (this.forWrapping) {
            byte[] bArr2 = new byte[8];
            System.arraycopy(this.preIV, 0, bArr2, 0, 4);
            Pack.intToBigEndian(i2, bArr2, 4);
            byte[] bArr3 = new byte[i2];
            System.arraycopy(bArr, i, bArr3, 0, i2);
            byte[] padPlaintext = padPlaintext(bArr3);
            if (padPlaintext.length != 8) {
                RFC3394WrapEngine rFC3394WrapEngine = new RFC3394WrapEngine(this.engine);
                rFC3394WrapEngine.init(true, new ParametersWithIV(this.param, bArr2));
                return rFC3394WrapEngine.wrap(padPlaintext, 0, padPlaintext.length);
            }
            int length = padPlaintext.length + 8;
            byte[] bArr4 = new byte[length];
            System.arraycopy(bArr2, 0, bArr4, 0, 8);
            System.arraycopy(padPlaintext, 0, bArr4, 8, padPlaintext.length);
            this.engine.init(true, this.param);
            int blockSize = this.engine.getBlockSize();
            for (int i3 = 0; i3 < length; i3 += blockSize) {
                this.engine.processBlock(bArr4, i3, bArr4, i3);
            }
            return bArr4;
        }
        throw new IllegalStateException("not set for wrapping");
    }
}