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

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RFC5649WrapEngine.class */
public class RFC5649WrapEngine implements Wrapper {
    private BlockCipher engine;
    private KeyParameter param;
    private boolean forWrapping;
    private byte[] highOrderIV = {-90, 89, 89, -90};
    private byte[] preIV = this.highOrderIV;
    private byte[] extractedAIV = null;

    public RFC5649WrapEngine(BlockCipher blockCipher) {
        this.engine = blockCipher;
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forWrapping = z;
        if (cipherParameters instanceof ParametersWithRandom) {
            cipherParameters = ((ParametersWithRandom) cipherParameters).getParameters();
        }
        if (cipherParameters instanceof KeyParameter) {
            this.param = (KeyParameter) cipherParameters;
            this.preIV = this.highOrderIV;
        } else if (cipherParameters instanceof ParametersWithIV) {
            this.preIV = ((ParametersWithIV) cipherParameters).getIV();
            this.param = (KeyParameter) ((ParametersWithIV) cipherParameters).getParameters();
            if (this.preIV.length != 4) {
                throw new IllegalArgumentException("IV length not equal to 4");
            }
        }
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public String getAlgorithmName() {
        return this.engine.getAlgorithmName();
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

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] wrap(byte[] bArr, int i, int i2) {
        if (!this.forWrapping) {
            throw new IllegalStateException("not set for wrapping");
        }
        byte[] bArr2 = new byte[8];
        byte[] intToBigEndian = Pack.intToBigEndian(i2);
        System.arraycopy(this.preIV, 0, bArr2, 0, this.preIV.length);
        System.arraycopy(intToBigEndian, 0, bArr2, this.preIV.length, intToBigEndian.length);
        byte[] bArr3 = new byte[i2];
        System.arraycopy(bArr, i, bArr3, 0, i2);
        byte[] padPlaintext = padPlaintext(bArr3);
        if (padPlaintext.length != 8) {
            RFC3394WrapEngine rFC3394WrapEngine = new RFC3394WrapEngine(this.engine);
            rFC3394WrapEngine.init(true, new ParametersWithIV(this.param, bArr2));
            return rFC3394WrapEngine.wrap(padPlaintext, 0, padPlaintext.length);
        }
        byte[] bArr4 = new byte[padPlaintext.length + bArr2.length];
        System.arraycopy(bArr2, 0, bArr4, 0, bArr2.length);
        System.arraycopy(padPlaintext, 0, bArr4, bArr2.length, padPlaintext.length);
        this.engine.init(true, this.param);
        int i3 = 0;
        while (true) {
            int i4 = i3;
            if (i4 >= bArr4.length) {
                return bArr4;
            }
            this.engine.processBlock(bArr4, i4, bArr4, i4);
            i3 = i4 + this.engine.getBlockSize();
        }
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] unwrap(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] rfc3394UnwrapNoIvCheck;
        if (this.forWrapping) {
            throw new IllegalStateException("not set for unwrapping");
        }
        int i3 = i2 / 8;
        if (i3 * 8 != i2) {
            throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
        }
        if (i3 <= 1) {
            throw new InvalidCipherTextException("unwrap data must be at least 16 bytes");
        }
        byte[] bArr2 = new byte[i2];
        System.arraycopy(bArr, i, bArr2, 0, i2);
        byte[] bArr3 = new byte[i2];
        if (i3 == 2) {
            this.engine.init(false, this.param);
            int i4 = 0;
            while (true) {
                int i5 = i4;
                if (i5 >= bArr2.length) {
                    break;
                }
                this.engine.processBlock(bArr2, i5, bArr3, i5);
                i4 = i5 + this.engine.getBlockSize();
            }
            this.extractedAIV = new byte[8];
            System.arraycopy(bArr3, 0, this.extractedAIV, 0, this.extractedAIV.length);
            rfc3394UnwrapNoIvCheck = new byte[bArr3.length - this.extractedAIV.length];
            System.arraycopy(bArr3, this.extractedAIV.length, rfc3394UnwrapNoIvCheck, 0, rfc3394UnwrapNoIvCheck.length);
        } else {
            rfc3394UnwrapNoIvCheck = rfc3394UnwrapNoIvCheck(bArr, i, i2);
        }
        byte[] bArr4 = new byte[4];
        byte[] bArr5 = new byte[4];
        System.arraycopy(this.extractedAIV, 0, bArr4, 0, bArr4.length);
        System.arraycopy(this.extractedAIV, bArr4.length, bArr5, 0, bArr5.length);
        int bigEndianToInt = Pack.bigEndianToInt(bArr5, 0);
        boolean z = true;
        if (!Arrays.constantTimeAreEqual(bArr4, this.preIV)) {
            z = false;
        }
        int length = rfc3394UnwrapNoIvCheck.length;
        if (bigEndianToInt <= length - 8) {
            z = false;
        }
        if (bigEndianToInt > length) {
            z = false;
        }
        int i6 = length - bigEndianToInt;
        if (i6 >= 8 || i6 < 0) {
            z = false;
            i6 = 4;
        }
        byte[] bArr6 = new byte[i6];
        byte[] bArr7 = new byte[i6];
        System.arraycopy(rfc3394UnwrapNoIvCheck, rfc3394UnwrapNoIvCheck.length - i6, bArr7, 0, i6);
        if (!Arrays.constantTimeAreEqual(bArr7, bArr6)) {
            z = false;
        }
        if (z) {
            byte[] bArr8 = new byte[bigEndianToInt];
            System.arraycopy(rfc3394UnwrapNoIvCheck, 0, bArr8, 0, bArr8.length);
            return bArr8;
        }
        throw new InvalidCipherTextException("checksum failed");
    }

    private byte[] rfc3394UnwrapNoIvCheck(byte[] bArr, int i, int i2) {
        byte[] bArr2 = new byte[8];
        byte[] bArr3 = new byte[i2 - bArr2.length];
        byte[] bArr4 = new byte[bArr2.length];
        byte[] bArr5 = new byte[8 + bArr2.length];
        System.arraycopy(bArr, i, bArr4, 0, bArr2.length);
        System.arraycopy(bArr, i + bArr2.length, bArr3, 0, i2 - bArr2.length);
        this.engine.init(false, this.param);
        int i3 = (i2 / 8) - 1;
        for (int i4 = 5; i4 >= 0; i4--) {
            for (int i5 = i3; i5 >= 1; i5--) {
                System.arraycopy(bArr4, 0, bArr5, 0, bArr2.length);
                System.arraycopy(bArr3, 8 * (i5 - 1), bArr5, bArr2.length, 8);
                int i6 = (i3 * i4) + i5;
                int i7 = 1;
                while (i6 != 0) {
                    int length = bArr2.length - i7;
                    bArr5[length] = (byte) (bArr5[length] ^ ((byte) i6));
                    i6 >>>= 8;
                    i7++;
                }
                this.engine.processBlock(bArr5, 0, bArr5, 0);
                System.arraycopy(bArr5, 0, bArr4, 0, 8);
                System.arraycopy(bArr5, 8, bArr3, 8 * (i5 - 1), 8);
            }
        }
        this.extractedAIV = bArr4;
        return bArr3;
    }
}