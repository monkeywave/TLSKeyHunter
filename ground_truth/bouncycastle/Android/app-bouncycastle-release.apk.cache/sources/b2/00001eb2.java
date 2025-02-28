package org.bouncycastle.crypto.prng.drbg;

import kotlin.UByte;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class CTRSP800DRBG implements SP80090DRBG {
    private static final int AES_MAX_BITS_REQUEST = 262144;
    private static final long AES_RESEED_MAX = 140737488355328L;
    private static final byte[] K_BITS = Hex.decodeStrict("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static final int TDEA_MAX_BITS_REQUEST = 4096;
    private static final long TDEA_RESEED_MAX = 2147483648L;
    private byte[] _Key;

    /* renamed from: _V */
    private byte[] f891_V;
    private BlockCipher _engine;
    private EntropySource _entropySource;
    private boolean _isTDEA;
    private int _keySizeInBits;
    private long _reseedCounter = 0;
    private int _securityStrength;
    private int _seedLength;

    public CTRSP800DRBG(BlockCipher blockCipher, int i, int i2, EntropySource entropySource, byte[] bArr, byte[] bArr2) {
        this._isTDEA = false;
        this._entropySource = entropySource;
        this._engine = blockCipher;
        this._keySizeInBits = i;
        this._securityStrength = i2;
        this._seedLength = (blockCipher.getBlockSize() * 8) + i;
        this._isTDEA = isTDEA(blockCipher);
        if (i2 > 256) {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }
        if (getMaxSecurityStrength(blockCipher, i) < i2) {
            throw new IllegalArgumentException("Requested security strength is not supported by block cipher and key size");
        }
        if (entropySource.entropySize() < i2) {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }
        CTR_DRBG_Instantiate_algorithm(getEntropy(), bArr2, bArr);
    }

    private void BCC(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
        int blockSize = this._engine.getBlockSize();
        byte[] bArr5 = new byte[blockSize];
        int length = bArr4.length / blockSize;
        byte[] bArr6 = new byte[blockSize];
        this._engine.init(true, new KeyParameter(expandKey(bArr2)));
        this._engine.processBlock(bArr3, 0, bArr5, 0);
        for (int i = 0; i < length; i++) {
            Bytes.xor(blockSize, bArr5, 0, bArr4, i * blockSize, bArr6, 0);
            this._engine.processBlock(bArr6, 0, bArr5, 0);
        }
        System.arraycopy(bArr5, 0, bArr, 0, bArr.length);
    }

    private byte[] Block_Cipher_df(byte[] bArr, int i) {
        int blockSize = this._engine.getBlockSize();
        int length = bArr.length;
        int i2 = i / 8;
        byte[] bArr2 = new byte[((((length + 9) + blockSize) - 1) / blockSize) * blockSize];
        copyIntToByteArray(bArr2, length, 0);
        copyIntToByteArray(bArr2, i2, 4);
        System.arraycopy(bArr, 0, bArr2, 8, length);
        bArr2[length + 8] = ByteCompanionObject.MIN_VALUE;
        int i3 = this._keySizeInBits;
        int i4 = (i3 / 8) + blockSize;
        byte[] bArr3 = new byte[i4];
        byte[] bArr4 = new byte[blockSize];
        byte[] bArr5 = new byte[blockSize];
        int i5 = i3 / 8;
        byte[] bArr6 = new byte[i5];
        System.arraycopy(K_BITS, 0, bArr6, 0, i5);
        int i6 = 0;
        while (true) {
            int i7 = i6 * blockSize;
            if (i7 * 8 >= this._keySizeInBits + (blockSize * 8)) {
                break;
            }
            copyIntToByteArray(bArr5, i6, 0);
            BCC(bArr4, bArr6, bArr5, bArr2);
            int i8 = i4 - i7;
            if (i8 > blockSize) {
                i8 = blockSize;
            }
            System.arraycopy(bArr4, 0, bArr3, i7, i8);
            i6++;
        }
        byte[] bArr7 = new byte[blockSize];
        System.arraycopy(bArr3, 0, bArr6, 0, i5);
        System.arraycopy(bArr3, i5, bArr7, 0, blockSize);
        byte[] bArr8 = new byte[i2];
        this._engine.init(true, new KeyParameter(expandKey(bArr6)));
        int i9 = 0;
        while (true) {
            int i10 = i9 * blockSize;
            if (i10 >= i2) {
                return bArr8;
            }
            this._engine.processBlock(bArr7, 0, bArr7, 0);
            int i11 = i2 - i10;
            if (i11 > blockSize) {
                i11 = blockSize;
            }
            System.arraycopy(bArr7, 0, bArr8, i10, i11);
            i9++;
        }
    }

    private void CTR_DRBG_Instantiate_algorithm(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        byte[] Block_Cipher_df = Block_Cipher_df(Arrays.concatenate(bArr, bArr2, bArr3), this._seedLength);
        int blockSize = this._engine.getBlockSize();
        byte[] bArr4 = new byte[(this._keySizeInBits + 7) / 8];
        this._Key = bArr4;
        byte[] bArr5 = new byte[blockSize];
        this.f891_V = bArr5;
        CTR_DRBG_Update(Block_Cipher_df, bArr4, bArr5);
        this._reseedCounter = 1L;
    }

    private void CTR_DRBG_Reseed_algorithm(byte[] bArr) {
        CTR_DRBG_Update(Block_Cipher_df(Arrays.concatenate(getEntropy(), bArr), this._seedLength), this._Key, this.f891_V);
        this._reseedCounter = 1L;
    }

    private void CTR_DRBG_Update(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        int length = bArr.length;
        byte[] bArr4 = new byte[length];
        byte[] bArr5 = new byte[this._engine.getBlockSize()];
        int blockSize = this._engine.getBlockSize();
        this._engine.init(true, new KeyParameter(expandKey(bArr2)));
        int i = 0;
        while (true) {
            int i2 = i * blockSize;
            if (i2 >= bArr.length) {
                Bytes.xorTo(bArr.length, bArr, bArr4);
                System.arraycopy(bArr4, 0, bArr2, 0, bArr2.length);
                System.arraycopy(bArr4, bArr2.length, bArr3, 0, bArr3.length);
                return;
            }
            addOneTo(bArr3);
            this._engine.processBlock(bArr3, 0, bArr5, 0);
            int i3 = length - i2;
            if (i3 > blockSize) {
                i3 = blockSize;
            }
            System.arraycopy(bArr5, 0, bArr4, i2, i3);
            i++;
        }
    }

    private void addOneTo(byte[] bArr) {
        int i = 1;
        for (int i2 = 1; i2 <= bArr.length; i2++) {
            int i3 = (bArr[bArr.length - i2] & UByte.MAX_VALUE) + i;
            i = i3 > 255 ? 1 : 0;
            bArr[bArr.length - i2] = (byte) i3;
        }
    }

    private void copyIntToByteArray(byte[] bArr, int i, int i2) {
        bArr[i2] = (byte) (i >> 24);
        bArr[i2 + 1] = (byte) (i >> 16);
        bArr[i2 + 2] = (byte) (i >> 8);
        bArr[i2 + 3] = (byte) i;
    }

    private byte[] getEntropy() {
        byte[] entropy = this._entropySource.getEntropy();
        if (entropy.length >= (this._securityStrength + 7) / 8) {
            return entropy;
        }
        throw new IllegalStateException("Insufficient entropy provided by entropy source");
    }

    private int getMaxSecurityStrength(BlockCipher blockCipher, int i) {
        if (isTDEA(blockCipher) && i == 168) {
            return 112;
        }
        if (blockCipher.getAlgorithmName().equals("AES")) {
            return i;
        }
        return -1;
    }

    private boolean isTDEA(BlockCipher blockCipher) {
        return blockCipher.getAlgorithmName().equals("DESede") || blockCipher.getAlgorithmName().equals("TDEA");
    }

    private void padKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        bArr2[i2] = (byte) (bArr[i] & 254);
        int i3 = i + 1;
        bArr2[i2 + 1] = (byte) ((bArr[i] << 7) | ((bArr[i3] & 252) >>> 1));
        int i4 = i + 2;
        bArr2[i2 + 2] = (byte) ((bArr[i3] << 6) | ((bArr[i4] & 248) >>> 2));
        int i5 = i + 3;
        bArr2[i2 + 3] = (byte) ((bArr[i4] << 5) | ((bArr[i5] & 240) >>> 3));
        int i6 = i + 4;
        bArr2[i2 + 4] = (byte) ((bArr[i5] << 4) | ((bArr[i6] & 224) >>> 4));
        int i7 = i + 5;
        bArr2[i2 + 5] = (byte) ((bArr[i6] << 3) | ((bArr[i7] & 192) >>> 5));
        int i8 = i + 6;
        bArr2[i2 + 6] = (byte) ((bArr[i7] << 2) | ((bArr[i8] & ByteCompanionObject.MIN_VALUE) >>> 6));
        int i9 = i2 + 7;
        bArr2[i9] = (byte) (bArr[i8] << 1);
        while (i2 <= i9) {
            byte b = bArr2[i2];
            bArr2[i2] = (byte) (((((b >> 7) ^ ((((((b >> 1) ^ (b >> 2)) ^ (b >> 3)) ^ (b >> 4)) ^ (b >> 5)) ^ (b >> 6))) ^ 1) & 1) | (b & 254));
            i2++;
        }
    }

    byte[] expandKey(byte[] bArr) {
        if (this._isTDEA) {
            byte[] bArr2 = new byte[24];
            padKey(bArr, 0, bArr2, 0);
            padKey(bArr, 7, bArr2, 8);
            padKey(bArr, 14, bArr2, 16);
            return bArr2;
        }
        return bArr;
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public int generate(byte[] bArr, byte[] bArr2, boolean z) {
        byte[] bArr3;
        boolean z2 = this._isTDEA;
        long j = this._reseedCounter;
        if (z2) {
            if (j > TDEA_RESEED_MAX) {
                return -1;
            }
            if (Utils.isTooLarge(bArr, 512)) {
                throw new IllegalArgumentException("Number of bits per request limited to 4096");
            }
        } else if (j > AES_RESEED_MAX) {
            return -1;
        } else {
            if (Utils.isTooLarge(bArr, 32768)) {
                throw new IllegalArgumentException("Number of bits per request limited to 262144");
            }
        }
        if (z) {
            CTR_DRBG_Reseed_algorithm(bArr2);
            bArr2 = null;
        }
        if (bArr2 != null) {
            bArr3 = Block_Cipher_df(bArr2, this._seedLength);
            CTR_DRBG_Update(bArr3, this._Key, this.f891_V);
        } else {
            bArr3 = new byte[this._seedLength / 8];
        }
        int length = this.f891_V.length;
        byte[] bArr4 = new byte[length];
        this._engine.init(true, new KeyParameter(expandKey(this._Key)));
        for (int i = 0; i <= bArr.length / length; i++) {
            int i2 = i * length;
            int length2 = bArr.length - i2 > length ? length : bArr.length - (this.f891_V.length * i);
            if (length2 != 0) {
                addOneTo(this.f891_V);
                this._engine.processBlock(this.f891_V, 0, bArr4, 0);
                System.arraycopy(bArr4, 0, bArr, i2, length2);
            }
        }
        CTR_DRBG_Update(bArr3, this._Key, this.f891_V);
        this._reseedCounter++;
        return bArr.length * 8;
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public int getBlockSize() {
        return this.f891_V.length * 8;
    }

    @Override // org.bouncycastle.crypto.prng.drbg.SP80090DRBG
    public void reseed(byte[] bArr) {
        CTR_DRBG_Reseed_algorithm(bArr);
    }
}