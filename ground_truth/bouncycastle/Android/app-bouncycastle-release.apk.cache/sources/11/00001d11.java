package org.bouncycastle.crypto.encodings;

import java.math.BigInteger;
import kotlin.UByte;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/* loaded from: classes2.dex */
public class ISO9796d1Encoding implements AsymmetricBlockCipher {
    private int bitSize;
    private AsymmetricBlockCipher engine;
    private boolean forEncryption;
    private BigInteger modulus;
    private int padBits = 0;
    private static final BigInteger SIXTEEN = BigInteger.valueOf(16);
    private static final BigInteger SIX = BigInteger.valueOf(6);
    private static byte[] shadows = {14, 3, 5, 8, 9, 4, 2, 15, 0, 13, 11, 6, 7, 10, 12, 1};
    private static byte[] inverse = {8, 15, 6, 1, 5, 2, 11, 12, 3, 4, 13, 10, 14, 9, 0, 7};

    public ISO9796d1Encoding(AsymmetricBlockCipher asymmetricBlockCipher) {
        this.engine = asymmetricBlockCipher;
    }

    private static byte[] convertOutputDecryptOnly(BigInteger bigInteger) {
        byte[] byteArray = bigInteger.toByteArray();
        if (byteArray[0] == 0) {
            int length = byteArray.length - 1;
            byte[] bArr = new byte[length];
            System.arraycopy(byteArray, 1, bArr, 0, length);
            return bArr;
        }
        return byteArray;
    }

    private byte[] decodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] processBlock = this.engine.processBlock(bArr, i, i2);
        int i3 = (this.bitSize + 13) / 16;
        BigInteger bigInteger = new BigInteger(1, processBlock);
        BigInteger bigInteger2 = SIXTEEN;
        BigInteger mod = bigInteger.mod(bigInteger2);
        BigInteger bigInteger3 = SIX;
        if (!mod.equals(bigInteger3)) {
            if (!this.modulus.subtract(bigInteger).mod(bigInteger2).equals(bigInteger3)) {
                throw new InvalidCipherTextException("resulting integer iS or (modulus - iS) is not congruent to 6 mod 16");
            }
            bigInteger = this.modulus.subtract(bigInteger);
        }
        byte[] convertOutputDecryptOnly = convertOutputDecryptOnly(bigInteger);
        if ((convertOutputDecryptOnly[convertOutputDecryptOnly.length - 1] & 15) == 6) {
            convertOutputDecryptOnly[convertOutputDecryptOnly.length - 1] = (byte) (((convertOutputDecryptOnly[convertOutputDecryptOnly.length - 1] & UByte.MAX_VALUE) >>> 4) | (inverse[(convertOutputDecryptOnly[convertOutputDecryptOnly.length - 2] & UByte.MAX_VALUE) >> 4] << 4));
            byte[] bArr2 = shadows;
            byte b = convertOutputDecryptOnly[1];
            byte b2 = bArr2[b & 15];
            convertOutputDecryptOnly[0] = (byte) (b2 | (bArr2[(b & UByte.MAX_VALUE) >>> 4] << 4));
            int i4 = 1;
            int i5 = 0;
            boolean z = false;
            for (int length = convertOutputDecryptOnly.length - 1; length >= convertOutputDecryptOnly.length - (i3 * 2); length -= 2) {
                byte[] bArr3 = shadows;
                byte b3 = convertOutputDecryptOnly[length];
                int i6 = bArr3[b3 & 15] | (bArr3[(b3 & UByte.MAX_VALUE) >>> 4] << 4);
                int i7 = length - 1;
                byte b4 = convertOutputDecryptOnly[i7];
                if (((b4 ^ i6) & 255) != 0) {
                    if (z) {
                        throw new InvalidCipherTextException("invalid tsums in block");
                    }
                    i4 = (b4 ^ i6) & 255;
                    z = true;
                    i5 = i7;
                }
            }
            convertOutputDecryptOnly[i5] = 0;
            int length2 = (convertOutputDecryptOnly.length - i5) / 2;
            byte[] bArr4 = new byte[length2];
            for (int i8 = 0; i8 < length2; i8++) {
                bArr4[i8] = convertOutputDecryptOnly[(i8 * 2) + i5 + 1];
            }
            this.padBits = i4 - 1;
            return bArr4;
        }
        throw new InvalidCipherTextException("invalid forcing byte in block");
    }

    private byte[] encodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        int i3 = this.bitSize;
        int i4 = (i3 + 7) / 8;
        byte[] bArr2 = new byte[i4];
        int i5 = 1;
        int i6 = this.padBits + 1;
        int i7 = (i3 + 13) / 16;
        int i8 = 0;
        while (i8 < i7) {
            if (i8 > i7 - i2) {
                int i9 = i7 - i8;
                System.arraycopy(bArr, (i + i2) - i9, bArr2, i4 - i7, i9);
            } else {
                System.arraycopy(bArr, i, bArr2, i4 - (i8 + i2), i2);
            }
            i8 += i2;
        }
        for (int i10 = i4 - (i7 * 2); i10 != i4; i10 += 2) {
            byte b = bArr2[(i4 - i7) + (i10 / 2)];
            byte[] bArr3 = shadows;
            bArr2[i10] = (byte) (bArr3[b & 15] | (bArr3[(b & UByte.MAX_VALUE) >>> 4] << 4));
            bArr2[i10 + 1] = b;
        }
        int i11 = i4 - (i2 * 2);
        bArr2[i11] = (byte) (bArr2[i11] ^ i6);
        int i12 = i4 - 1;
        bArr2[i12] = (byte) ((bArr2[i12] << 4) | 6);
        int i13 = 8 - ((this.bitSize - 1) % 8);
        if (i13 != 8) {
            byte b2 = (byte) (bArr2[0] & (255 >>> i13));
            bArr2[0] = b2;
            bArr2[0] = (byte) ((128 >>> i13) | b2);
            i5 = 0;
        } else {
            bArr2[0] = 0;
            bArr2[1] = (byte) (bArr2[1] | ByteCompanionObject.MIN_VALUE);
        }
        return this.engine.processBlock(bArr2, i5, i4 - i5);
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        int inputBlockSize = this.engine.getInputBlockSize();
        return this.forEncryption ? (inputBlockSize + 1) / 2 : inputBlockSize;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        int outputBlockSize = this.engine.getOutputBlockSize();
        return this.forEncryption ? outputBlockSize : (outputBlockSize + 1) / 2;
    }

    public int getPadBits() {
        return this.padBits;
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        RSAKeyParameters rSAKeyParameters = cipherParameters instanceof ParametersWithRandom ? (RSAKeyParameters) ((ParametersWithRandom) cipherParameters).getParameters() : (RSAKeyParameters) cipherParameters;
        this.engine.init(z, cipherParameters);
        BigInteger modulus = rSAKeyParameters.getModulus();
        this.modulus = modulus;
        this.bitSize = modulus.bitLength();
        this.forEncryption = z;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        return this.forEncryption ? encodeBlock(bArr, i, i2) : decodeBlock(bArr, i, i2);
    }

    public void setPadBits(int i) {
        if (i > 7) {
            throw new IllegalArgumentException("padBits > 7");
        }
        this.padBits = i;
    }
}