package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;

/* loaded from: classes2.dex */
public class OpenPGPCFBBlockCipher implements BlockCipher {

    /* renamed from: FR */
    private byte[] f799FR;
    private byte[] FRE;

    /* renamed from: IV */
    private byte[] f800IV;
    private int blockSize;
    private BlockCipher cipher;
    private int count;
    private boolean forEncryption;

    public OpenPGPCFBBlockCipher(BlockCipher blockCipher) {
        this.cipher = blockCipher;
        int blockSize = blockCipher.getBlockSize();
        this.blockSize = blockSize;
        this.f800IV = new byte[blockSize];
        this.f799FR = new byte[blockSize];
        this.FRE = new byte[blockSize];
    }

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        int i3;
        int i4 = this.blockSize;
        if (i + i4 <= bArr.length) {
            if (i2 + i4 <= bArr2.length) {
                int i5 = this.count;
                int i6 = 2;
                int i7 = 0;
                if (i5 > i4) {
                    byte b = bArr[i];
                    this.f799FR[i4 - 2] = b;
                    bArr2[i2] = encryptByte(b, i4 - 2);
                    byte b2 = bArr[i + 1];
                    byte[] bArr3 = this.f799FR;
                    int i8 = this.blockSize;
                    bArr3[i8 - 1] = b2;
                    bArr2[i2 + 1] = encryptByte(b2, i8 - 1);
                    this.cipher.processBlock(this.f799FR, 0, this.FRE, 0);
                    while (i6 < this.blockSize) {
                        byte b3 = bArr[i + i6];
                        int i9 = i6 - 2;
                        this.f799FR[i9] = b3;
                        bArr2[i2 + i6] = encryptByte(b3, i9);
                        i6++;
                    }
                } else {
                    if (i5 != 0) {
                        if (i5 == i4) {
                            this.cipher.processBlock(this.f799FR, 0, this.FRE, 0);
                            byte b4 = bArr[i];
                            byte b5 = bArr[i + 1];
                            bArr2[i2] = encryptByte(b4, 0);
                            bArr2[i2 + 1] = encryptByte(b5, 1);
                            byte[] bArr4 = this.f799FR;
                            System.arraycopy(bArr4, 2, bArr4, 0, this.blockSize - 2);
                            byte[] bArr5 = this.f799FR;
                            int i10 = this.blockSize;
                            bArr5[i10 - 2] = b4;
                            bArr5[i10 - 1] = b5;
                            this.cipher.processBlock(bArr5, 0, this.FRE, 0);
                            while (true) {
                                i3 = this.blockSize;
                                if (i6 >= i3) {
                                    break;
                                }
                                byte b6 = bArr[i + i6];
                                int i11 = i6 - 2;
                                this.f799FR[i11] = b6;
                                bArr2[i2 + i6] = encryptByte(b6, i11);
                                i6++;
                            }
                        }
                    } else {
                        this.cipher.processBlock(this.f799FR, 0, this.FRE, 0);
                        while (true) {
                            i3 = this.blockSize;
                            if (i7 >= i3) {
                                break;
                            }
                            int i12 = i + i7;
                            this.f799FR[i7] = bArr[i12];
                            bArr2[i2 + i7] = encryptByte(bArr[i12], i7);
                            i7++;
                        }
                    }
                    this.count += i3;
                }
                return this.blockSize;
            }
            throw new OutputLengthException("output buffer too short");
        }
        throw new DataLengthException("input buffer too short");
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        int i3;
        int i4 = this.blockSize;
        if (i + i4 <= bArr.length) {
            if (i2 + i4 <= bArr2.length) {
                int i5 = this.count;
                int i6 = 2;
                int i7 = 0;
                if (i5 > i4) {
                    byte[] bArr3 = this.f799FR;
                    int i8 = i4 - 2;
                    byte encryptByte = encryptByte(bArr[i], i4 - 2);
                    bArr2[i2] = encryptByte;
                    bArr3[i8] = encryptByte;
                    byte[] bArr4 = this.f799FR;
                    int i9 = this.blockSize;
                    int i10 = i9 - 1;
                    byte encryptByte2 = encryptByte(bArr[i + 1], i9 - 1);
                    bArr2[i2 + 1] = encryptByte2;
                    bArr4[i10] = encryptByte2;
                    this.cipher.processBlock(this.f799FR, 0, this.FRE, 0);
                    while (i6 < this.blockSize) {
                        byte[] bArr5 = this.f799FR;
                        int i11 = i6 - 2;
                        byte encryptByte3 = encryptByte(bArr[i + i6], i11);
                        bArr2[i2 + i6] = encryptByte3;
                        bArr5[i11] = encryptByte3;
                        i6++;
                    }
                } else {
                    if (i5 != 0) {
                        if (i5 == i4) {
                            this.cipher.processBlock(this.f799FR, 0, this.FRE, 0);
                            bArr2[i2] = encryptByte(bArr[i], 0);
                            bArr2[i2 + 1] = encryptByte(bArr[i + 1], 1);
                            byte[] bArr6 = this.f799FR;
                            System.arraycopy(bArr6, 2, bArr6, 0, this.blockSize - 2);
                            System.arraycopy(bArr2, i2, this.f799FR, this.blockSize - 2, 2);
                            this.cipher.processBlock(this.f799FR, 0, this.FRE, 0);
                            while (true) {
                                i3 = this.blockSize;
                                if (i6 >= i3) {
                                    break;
                                }
                                byte[] bArr7 = this.f799FR;
                                int i12 = i6 - 2;
                                byte encryptByte4 = encryptByte(bArr[i + i6], i12);
                                bArr2[i2 + i6] = encryptByte4;
                                bArr7[i12] = encryptByte4;
                                i6++;
                            }
                        }
                    } else {
                        this.cipher.processBlock(this.f799FR, 0, this.FRE, 0);
                        while (true) {
                            i3 = this.blockSize;
                            if (i7 >= i3) {
                                break;
                            }
                            byte[] bArr8 = this.f799FR;
                            byte encryptByte5 = encryptByte(bArr[i + i7], i7);
                            bArr2[i2 + i7] = encryptByte5;
                            bArr8[i7] = encryptByte5;
                            i7++;
                        }
                    }
                    this.count += i3;
                }
                return this.blockSize;
            }
            throw new OutputLengthException("output buffer too short");
        }
        throw new DataLengthException("input buffer too short");
    }

    private byte encryptByte(byte b, int i) {
        return (byte) (b ^ this.FRE[i]);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/OpenPGPCFB";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.forEncryption = z;
        reset();
        this.cipher.init(true, cipherParameters);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        return this.forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        this.count = 0;
        byte[] bArr = this.f800IV;
        byte[] bArr2 = this.f799FR;
        System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
        this.cipher.reset();
    }
}