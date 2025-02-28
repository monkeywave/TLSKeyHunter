package org.bouncycastle.crypto.fpe;

import java.math.BigInteger;
import kotlin.UByte;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.util.RadixConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
class SP80038G {
    protected static final int BLOCK_SIZE = 16;
    static final String FF1_DISABLED = "org.bouncycastle.fpe.disable_ff1";
    static final String FPE_DISABLED = "org.bouncycastle.fpe.disable";
    protected static final double LOG2 = Math.log(2.0d);
    protected static final double TWO_TO_96 = Math.pow(2.0d, 96.0d);

    SP80038G() {
    }

    protected static int calculateB_FF1(int i, int i2) {
        int numberOfTrailingZeros = Integers.numberOfTrailingZeros(i);
        int i3 = numberOfTrailingZeros * i2;
        int i4 = i >>> numberOfTrailingZeros;
        if (i4 != 1) {
            i3 += BigInteger.valueOf(i4).pow(i2).bitLength();
        }
        return (i3 + 7) / 8;
    }

    protected static BigInteger[] calculateModUV(BigInteger bigInteger, int i, int i2) {
        BigInteger pow = bigInteger.pow(i);
        BigInteger[] bigIntegerArr = {pow, pow};
        if (i2 != i) {
            bigIntegerArr[1] = pow.multiply(bigInteger);
        }
        return bigIntegerArr;
    }

    protected static byte[] calculateP_FF1(int i, byte b, int i2, int i3) {
        byte[] bArr = {1, 2, 1, 0, (byte) (i >> 8), (byte) i, 10, b};
        Pack.intToBigEndian(i2, bArr, 8);
        Pack.intToBigEndian(i3, bArr, 12);
        return bArr;
    }

    protected static byte[] calculateTweak64_FF3_1(byte[] bArr) {
        byte b = bArr[0];
        byte b2 = bArr[1];
        byte b3 = bArr[2];
        byte b4 = bArr[3];
        return new byte[]{b, b2, b3, (byte) (b4 & 240), bArr[4], bArr[5], bArr[6], (byte) (b4 << 4)};
    }

    protected static BigInteger calculateY_FF1(BlockCipher blockCipher, byte[] bArr, int i, int i2, int i3, byte[] bArr2, short[] sArr, RadixConverter radixConverter) {
        int length = bArr.length;
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(radixConverter.fromEncoding(sArr));
        int i4 = ((-(length + i + 1)) & 15) + length;
        int i5 = i4 + 1 + i;
        byte[] bArr3 = new byte[i5];
        System.arraycopy(bArr, 0, bArr3, 0, length);
        bArr3[i4] = (byte) i3;
        System.arraycopy(asUnsignedByteArray, 0, bArr3, i5 - asUnsignedByteArray.length, asUnsignedByteArray.length);
        byte[] prf = prf(blockCipher, Arrays.concatenate(bArr2, bArr3));
        if (i2 > 16) {
            int i6 = (i2 + 15) / 16;
            byte[] bArr4 = new byte[i6 * 16];
            int bigEndianToInt = Pack.bigEndianToInt(prf, 12);
            System.arraycopy(prf, 0, bArr4, 0, 16);
            for (int i7 = 1; i7 < i6; i7++) {
                int i8 = i7 * 16;
                System.arraycopy(prf, 0, bArr4, i8, 12);
                Pack.intToBigEndian(bigEndianToInt ^ i7, bArr4, i8 + 12);
                blockCipher.processBlock(bArr4, i8, bArr4, i8);
            }
            prf = bArr4;
        }
        return num(prf, 0, i2);
    }

    protected static BigInteger calculateY_FF3(BlockCipher blockCipher, byte[] bArr, int i, int i2, short[] sArr, RadixConverter radixConverter) {
        byte[] bArr2 = new byte[16];
        Pack.intToBigEndian(Pack.bigEndianToInt(bArr, i) ^ i2, bArr2, 0);
        BigIntegers.asUnsignedByteArray(radixConverter.fromEncoding(sArr), bArr2, 4, 12);
        Arrays.reverseInPlace(bArr2);
        blockCipher.processBlock(bArr2, 0, bArr2, 0);
        Arrays.reverseInPlace(bArr2);
        return num(bArr2, 0, 16);
    }

    protected static void checkArgs(BlockCipher blockCipher, boolean z, int i, byte[] bArr, int i2, int i3) {
        checkCipher(blockCipher);
        if (i < 2 || i > 256) {
            throw new IllegalArgumentException();
        }
        checkData(z, i, bArr, i2, i3);
    }

    protected static void checkArgs(BlockCipher blockCipher, boolean z, int i, short[] sArr, int i2, int i3) {
        checkCipher(blockCipher);
        if (i < 2 || i > 65536) {
            throw new IllegalArgumentException();
        }
        checkData(z, i, sArr, i2, i3);
    }

    protected static void checkCipher(BlockCipher blockCipher) {
        if (16 != blockCipher.getBlockSize()) {
            throw new IllegalArgumentException();
        }
    }

    protected static void checkData(boolean z, int i, byte[] bArr, int i2, int i3) {
        checkLength(z, i, i3);
        for (int i4 = 0; i4 < i3; i4++) {
            if ((bArr[i2 + i4] & UByte.MAX_VALUE) >= i) {
                throw new IllegalArgumentException("input data outside of radix");
            }
        }
    }

    protected static void checkData(boolean z, int i, short[] sArr, int i2, int i3) {
        checkLength(z, i, i3);
        for (int i4 = 0; i4 < i3; i4++) {
            if ((sArr[i2 + i4] & 65535) >= i) {
                throw new IllegalArgumentException("input data outside of radix");
            }
        }
    }

    private static void checkLength(boolean z, int i, int i2) {
        int floor;
        if (i2 >= 2) {
            double d = i;
            if (Math.pow(d, i2) >= 1000000.0d) {
                if (!z && i2 > (floor = ((int) Math.floor(Math.log(TWO_TO_96) / Math.log(d))) * 2)) {
                    throw new IllegalArgumentException("maximum input length is " + floor);
                }
                return;
            }
        }
        throw new IllegalArgumentException("input too short");
    }

    static short[] decFF1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, int i, int i2, int i3, short[] sArr, short[] sArr2) {
        int radix = radixConverter.getRadix();
        int length = bArr.length;
        int calculateB_FF1 = calculateB_FF1(radix, i3);
        int i4 = (calculateB_FF1 + 7) & (-4);
        byte[] calculateP_FF1 = calculateP_FF1(radix, (byte) i2, i, length);
        BigInteger[] calculateModUV = calculateModUV(BigInteger.valueOf(radix), i2, i3);
        short[] sArr3 = sArr;
        short[] sArr4 = sArr2;
        int i5 = i2;
        int i6 = 9;
        while (i6 >= 0) {
            short[] sArr5 = sArr4;
            int i7 = calculateB_FF1;
            short[] sArr6 = sArr3;
            i5 = i - i5;
            radixConverter.toEncoding(radixConverter.fromEncoding(sArr5).subtract(calculateY_FF1(blockCipher, bArr, calculateB_FF1, i4, i6, calculateP_FF1, sArr3, radixConverter)).mod(calculateModUV[i6 & 1]), i5, sArr5);
            i6--;
            sArr3 = sArr5;
            sArr4 = sArr6;
            calculateB_FF1 = i7;
        }
        return Arrays.concatenate(sArr3, sArr4);
    }

    private static short[] decFF3_1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, int i, int i2, int i3, short[] sArr, short[] sArr2) {
        int i4 = i3;
        BigInteger[] calculateModUV = calculateModUV(BigInteger.valueOf(radixConverter.getRadix()), i2, i4);
        Arrays.reverseInPlace(sArr);
        Arrays.reverseInPlace(sArr2);
        short[] sArr3 = sArr;
        short[] sArr4 = sArr2;
        int i5 = 7;
        while (i5 >= 0) {
            int i6 = i - i4;
            int i7 = i5 & 1;
            radixConverter.toEncoding(radixConverter.fromEncoding(sArr4).subtract(calculateY_FF3(blockCipher, bArr, 4 - (i7 * 4), i5, sArr3, radixConverter)).mod(calculateModUV[1 - i7]), i6, sArr4);
            i5--;
            i4 = i6;
            short[] sArr5 = sArr4;
            sArr4 = sArr3;
            sArr3 = sArr5;
        }
        Arrays.reverseInPlace(sArr3);
        Arrays.reverseInPlace(sArr4);
        return Arrays.concatenate(sArr3, sArr4);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] decryptFF1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        checkArgs(blockCipher, true, radixConverter.getRadix(), bArr2, i, i2);
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        return toByte(decFF1(blockCipher, radixConverter, bArr, i2, i3, i4, toShort(bArr2, i, i3), toShort(bArr2, i + i3, i4)));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short[] decryptFF1w(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, short[] sArr, int i, int i2) {
        checkArgs(blockCipher, true, radixConverter.getRadix(), sArr, i, i2);
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        short[] sArr2 = new short[i3];
        short[] sArr3 = new short[i4];
        System.arraycopy(sArr, i, sArr2, 0, i3);
        System.arraycopy(sArr, i + i3, sArr3, 0, i4);
        return decFF1(blockCipher, radixConverter, bArr, i2, i3, i4, sArr2, sArr3);
    }

    static byte[] decryptFF3(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        checkArgs(blockCipher, false, radixConverter.getRadix(), bArr2, i, i2);
        if (bArr.length == 8) {
            return implDecryptFF3(blockCipher, radixConverter, bArr, bArr2, i, i2);
        }
        throw new IllegalArgumentException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] decryptFF3_1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        checkArgs(blockCipher, false, radixConverter.getRadix(), bArr2, i, i2);
        if (bArr.length == 7) {
            return implDecryptFF3(blockCipher, radixConverter, calculateTweak64_FF3_1(bArr), bArr2, i, i2);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short[] decryptFF3_1w(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, short[] sArr, int i, int i2) {
        checkArgs(blockCipher, false, radixConverter.getRadix(), sArr, i, i2);
        if (bArr.length == 7) {
            return implDecryptFF3w(blockCipher, radixConverter, calculateTweak64_FF3_1(bArr), sArr, i, i2);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    private static short[] encFF1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, int i, int i2, int i3, short[] sArr, short[] sArr2) {
        int radix = radixConverter.getRadix();
        int length = bArr.length;
        int calculateB_FF1 = calculateB_FF1(radix, i3);
        int i4 = (calculateB_FF1 + 7) & (-4);
        byte[] calculateP_FF1 = calculateP_FF1(radix, (byte) i2, i, length);
        BigInteger[] calculateModUV = calculateModUV(BigInteger.valueOf(radix), i2, i3);
        short[] sArr3 = sArr;
        short[] sArr4 = sArr2;
        int i5 = 0;
        int i6 = i3;
        while (i5 < 10) {
            short[] sArr5 = sArr4;
            int i7 = i5;
            short[] sArr6 = sArr3;
            i6 = i - i6;
            radixConverter.toEncoding(radixConverter.fromEncoding(sArr6).add(calculateY_FF1(blockCipher, bArr, calculateB_FF1, i4, i5, calculateP_FF1, sArr5, radixConverter)).mod(calculateModUV[i7 & 1]), i6, sArr6);
            i5 = i7 + 1;
            sArr3 = sArr5;
            sArr4 = sArr6;
        }
        return Arrays.concatenate(sArr3, sArr4);
    }

    private static short[] encFF3_1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, int i, int i2, int i3, short[] sArr, short[] sArr2) {
        int i4 = i2;
        BigInteger[] calculateModUV = calculateModUV(BigInteger.valueOf(radixConverter.getRadix()), i4, i3);
        Arrays.reverseInPlace(sArr);
        Arrays.reverseInPlace(sArr2);
        short[] sArr3 = sArr;
        short[] sArr4 = sArr2;
        int i5 = 0;
        while (i5 < 8) {
            int i6 = i - i4;
            int i7 = i5 & 1;
            radixConverter.toEncoding(radixConverter.fromEncoding(sArr3).add(calculateY_FF3(blockCipher, bArr, 4 - (i7 * 4), i5, sArr4, radixConverter)).mod(calculateModUV[1 - i7]), i6, sArr3);
            i5++;
            i4 = i6;
            short[] sArr5 = sArr4;
            sArr4 = sArr3;
            sArr3 = sArr5;
        }
        Arrays.reverseInPlace(sArr3);
        Arrays.reverseInPlace(sArr4);
        return Arrays.concatenate(sArr3, sArr4);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] encryptFF1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        checkArgs(blockCipher, true, radixConverter.getRadix(), bArr2, i, i2);
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        return toByte(encFF1(blockCipher, radixConverter, bArr, i2, i3, i4, toShort(bArr2, i, i3), toShort(bArr2, i + i3, i4)));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short[] encryptFF1w(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, short[] sArr, int i, int i2) {
        checkArgs(blockCipher, true, radixConverter.getRadix(), sArr, i, i2);
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        short[] sArr2 = new short[i3];
        short[] sArr3 = new short[i4];
        System.arraycopy(sArr, i, sArr2, 0, i3);
        System.arraycopy(sArr, i + i3, sArr3, 0, i4);
        return encFF1(blockCipher, radixConverter, bArr, i2, i3, i4, sArr2, sArr3);
    }

    static byte[] encryptFF3(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        checkArgs(blockCipher, false, radixConverter.getRadix(), bArr2, i, i2);
        if (bArr.length == 8) {
            return implEncryptFF3(blockCipher, radixConverter, bArr, bArr2, i, i2);
        }
        throw new IllegalArgumentException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] encryptFF3_1(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        checkArgs(blockCipher, false, radixConverter.getRadix(), bArr2, i, i2);
        if (bArr.length == 7) {
            return encryptFF3(blockCipher, radixConverter, calculateTweak64_FF3_1(bArr), bArr2, i, i2);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static short[] encryptFF3_1w(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, short[] sArr, int i, int i2) {
        checkArgs(blockCipher, false, radixConverter.getRadix(), sArr, i, i2);
        if (bArr.length == 7) {
            return encryptFF3w(blockCipher, radixConverter, calculateTweak64_FF3_1(bArr), sArr, i, i2);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    static short[] encryptFF3w(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, short[] sArr, int i, int i2) {
        checkArgs(blockCipher, false, radixConverter.getRadix(), sArr, i, i2);
        if (bArr.length == 8) {
            return implEncryptFF3w(blockCipher, radixConverter, bArr, sArr, i, i2);
        }
        throw new IllegalArgumentException();
    }

    protected static byte[] implDecryptFF3(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        return toByte(decFF3_1(blockCipher, radixConverter, bArr, i2, i3, i4, toShort(bArr2, i, i4), toShort(bArr2, i + i4, i3)));
    }

    protected static short[] implDecryptFF3w(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, short[] sArr, int i, int i2) {
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        short[] sArr2 = new short[i4];
        short[] sArr3 = new short[i3];
        System.arraycopy(sArr, i, sArr2, 0, i4);
        System.arraycopy(sArr, i + i4, sArr3, 0, i3);
        return decFF3_1(blockCipher, radixConverter, bArr, i2, i3, i4, sArr2, sArr3);
    }

    protected static byte[] implEncryptFF3(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, byte[] bArr2, int i, int i2) {
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        return toByte(encFF3_1(blockCipher, radixConverter, bArr, i2, i3, i4, toShort(bArr2, i, i4), toShort(bArr2, i + i4, i3)));
    }

    protected static short[] implEncryptFF3w(BlockCipher blockCipher, RadixConverter radixConverter, byte[] bArr, short[] sArr, int i, int i2) {
        int i3 = i2 / 2;
        int i4 = i2 - i3;
        short[] sArr2 = new short[i4];
        short[] sArr3 = new short[i3];
        System.arraycopy(sArr, i, sArr2, 0, i4);
        System.arraycopy(sArr, i + i4, sArr3, 0, i3);
        return encFF3_1(blockCipher, radixConverter, bArr, i2, i3, i4, sArr2, sArr3);
    }

    protected static BigInteger num(byte[] bArr, int i, int i2) {
        return new BigInteger(1, Arrays.copyOfRange(bArr, i, i2 + i));
    }

    protected static byte[] prf(BlockCipher blockCipher, byte[] bArr) {
        if (bArr.length % 16 == 0) {
            int length = bArr.length / 16;
            byte[] bArr2 = new byte[16];
            for (int i = 0; i < length; i++) {
                Bytes.xorTo(16, bArr, i * 16, bArr2, 0);
                blockCipher.processBlock(bArr2, 0, bArr2, 0);
            }
            return bArr2;
        }
        throw new IllegalArgumentException();
    }

    private static byte[] toByte(short[] sArr) {
        int length = sArr.length;
        byte[] bArr = new byte[length];
        for (int i = 0; i != length; i++) {
            bArr[i] = (byte) sArr[i];
        }
        return bArr;
    }

    private static short[] toShort(byte[] bArr, int i, int i2) {
        short[] sArr = new short[i2];
        for (int i3 = 0; i3 != i2; i3++) {
            sArr[i3] = (short) (bArr[i + i3] & UByte.MAX_VALUE);
        }
        return sArr;
    }
}