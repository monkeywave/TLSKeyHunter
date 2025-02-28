package org.bouncycastle.pqc.crypto.bike;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class BIKERing {
    private static final int PERMUTATION_CUTOFF = 64;
    private final int bits;
    private final Map<Integer, Integer> halfPowers;
    private final int size;
    private final int sizeExt;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BIKERing(int i) {
        HashMap hashMap = new HashMap();
        this.halfPowers = hashMap;
        if (((-65535) & i) != 1) {
            throw new IllegalArgumentException();
        }
        this.bits = i;
        int i2 = (i + 63) >>> 6;
        this.size = i2;
        this.sizeExt = i2 * 2;
        generateHalfPowersInv(hashMap, i);
    }

    private static int generateHalfPower(int i, int i2, int i3) {
        int i4 = 1;
        while (i3 >= 32) {
            i4 = (int) ((((BodyPartID.bodyIdMax & (i2 * i4)) * i) + i4) >>> 32);
            i3 -= 32;
        }
        if (i3 > 0) {
            return (int) ((((BodyPartID.bodyIdMax & ((i2 * i4) & ((-1) >>> (-i3)))) * i) + i4) >>> i3);
        }
        return i4;
    }

    private static void generateHalfPowersInv(Map<Integer, Integer> map, int i) {
        int i2;
        int i3 = i - 2;
        int numberOfLeadingZeros = 32 - Integers.numberOfLeadingZeros(i3);
        int inverse32 = Mod.inverse32(-i);
        for (int i4 = 1; i4 < numberOfLeadingZeros; i4++) {
            int i5 = 1 << (i4 - 1);
            if (i5 >= 64 && !map.containsKey(Integers.valueOf(i5))) {
                map.put(Integers.valueOf(i5), Integers.valueOf(generateHalfPower(i, inverse32, i5)));
            }
            int i6 = 1 << i4;
            if ((i3 & i6) != 0 && (i2 = (i6 - 1) & i3) >= 64 && !map.containsKey(Integers.valueOf(i2))) {
                map.put(Integers.valueOf(i2), Integers.valueOf(generateHalfPower(i, inverse32, i2)));
            }
        }
    }

    private static int implModAdd(int i, int i2, int i3) {
        int i4 = (i2 + i3) - i;
        return i4 + (i & (i4 >> 31));
    }

    private static void implMulwAcc(long[] jArr, long j, long j2, long[] jArr2, int i) {
        long j3 = j;
        jArr[1] = j2;
        for (int i2 = 2; i2 < 16; i2 += 2) {
            long j4 = jArr[i2 >>> 1] << 1;
            jArr[i2] = j4;
            jArr[i2 + 1] = j4 ^ j2;
        }
        int i3 = (int) j3;
        long j5 = jArr[i3 & 15] ^ (jArr[(i3 >>> 4) & 15] << 4);
        long j6 = 0;
        int i4 = 56;
        do {
            int i5 = (int) (j3 >>> i4);
            long j7 = jArr[i5 & 15] ^ (jArr[(i5 >>> 4) & 15] << 4);
            j5 ^= j7 << i4;
            j6 ^= j7 >>> (-i4);
            i4 -= 8;
        } while (i4 > 0);
        for (int i6 = 0; i6 < 7; i6++) {
            j3 = (j3 & (-72340172838076674L)) >>> 1;
            j6 ^= ((j2 << i6) >> 63) & j3;
        }
        jArr2[i] = jArr2[i] ^ j5;
        int i7 = i + 1;
        jArr2[i7] = jArr2[i7] ^ j6;
    }

    private void implPermute(long[] jArr, int i, long[] jArr2) {
        int i2 = this.bits;
        int intValue = this.halfPowers.get(Integers.valueOf(i)).intValue();
        int implModAdd = implModAdd(i2, intValue, intValue);
        int implModAdd2 = implModAdd(i2, implModAdd, implModAdd);
        int implModAdd3 = implModAdd(i2, implModAdd2, implModAdd2);
        int i3 = i2 - implModAdd3;
        int implModAdd4 = implModAdd(i2, i3, intValue);
        int implModAdd5 = implModAdd(i2, i3, implModAdd);
        int implModAdd6 = implModAdd(i2, implModAdd4, implModAdd);
        int implModAdd7 = implModAdd(i2, i3, implModAdd2);
        int implModAdd8 = implModAdd(i2, implModAdd4, implModAdd2);
        int implModAdd9 = implModAdd(i2, implModAdd5, implModAdd2);
        int implModAdd10 = implModAdd(i2, implModAdd6, implModAdd2);
        int i4 = 0;
        while (true) {
            int i5 = this.size;
            if (i4 >= i5) {
                int i6 = i5 - 1;
                jArr2[i6] = jArr2[i6] & ((-1) >>> (-i2));
                return;
            }
            long j = 0;
            for (int i7 = 0; i7 < 64; i7 += 8) {
                i3 = implModAdd(i2, i3, implModAdd3);
                implModAdd4 = implModAdd(i2, implModAdd4, implModAdd3);
                implModAdd5 = implModAdd(i2, implModAdd5, implModAdd3);
                implModAdd6 = implModAdd(i2, implModAdd6, implModAdd3);
                implModAdd7 = implModAdd(i2, implModAdd7, implModAdd3);
                implModAdd8 = implModAdd(i2, implModAdd8, implModAdd3);
                implModAdd9 = implModAdd(i2, implModAdd9, implModAdd3);
                implModAdd10 = implModAdd(i2, implModAdd10, implModAdd3);
                j = j | (((jArr[i3 >>> 6] >>> i3) & 1) << i7) | (((jArr[implModAdd4 >>> 6] >>> implModAdd4) & 1) << (i7 + 1)) | (((jArr[implModAdd5 >>> 6] >>> implModAdd5) & 1) << (i7 + 2)) | (((jArr[implModAdd6 >>> 6] >>> implModAdd6) & 1) << (i7 + 3)) | (((jArr[implModAdd7 >>> 6] >>> implModAdd7) & 1) << (i7 + 4)) | (((jArr[implModAdd8 >>> 6] >>> implModAdd8) & 1) << (i7 + 5)) | (((jArr[implModAdd9 >>> 6] >>> implModAdd9) & 1) << (i7 + 6)) | (((jArr[implModAdd10 >>> 6] >>> implModAdd10) & 1) << (i7 + 7));
            }
            jArr2[i4] = j;
            i4++;
        }
    }

    private void implSquare(long[] jArr, long[] jArr2) {
        Interleave.expand64To128(jArr, 0, this.size, jArr2, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void add(long[] jArr, long[] jArr2, long[] jArr3) {
        for (int i = 0; i < this.size; i++) {
            jArr3[i] = jArr[i] ^ jArr2[i];
        }
    }

    void addTo(long[] jArr, long[] jArr2) {
        for (int i = 0; i < this.size; i++) {
            jArr2[i] = jArr2[i] ^ jArr[i];
        }
    }

    void copy(long[] jArr, long[] jArr2) {
        for (int i = 0; i < this.size; i++) {
            jArr2[i] = jArr[i];
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long[] create() {
        return new long[this.size];
    }

    long[] createExt() {
        return new long[this.sizeExt];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void decodeBytes(byte[] bArr, long[] jArr) {
        Pack.littleEndianToLong(bArr, 0, jArr, 0, this.size - 1);
        byte[] bArr2 = new byte[8];
        System.arraycopy(bArr, (this.size - 1) << 3, bArr2, 0, ((this.bits & 63) + 7) >>> 3);
        jArr[this.size - 1] = Pack.littleEndianToLong(bArr2, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] encodeBitsTransposed(long[] jArr) {
        byte[] bArr = new byte[this.bits];
        bArr[0] = (byte) (jArr[0] & 1);
        int i = 1;
        while (true) {
            int i2 = this.bits;
            if (i >= i2) {
                return bArr;
            }
            bArr[i2 - i] = (byte) ((jArr[i >>> 6] >>> (i & 63)) & 1);
            i++;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void encodeBytes(long[] jArr, byte[] bArr) {
        Pack.longToLittleEndian(jArr, 0, this.size - 1, bArr, 0);
        byte[] bArr2 = new byte[8];
        Pack.longToLittleEndian(jArr[this.size - 1], bArr2, 0);
        System.arraycopy(bArr2, 0, bArr, (this.size - 1) << 3, ((this.bits & 63) + 7) >>> 3);
    }

    int getSize() {
        return this.size;
    }

    int getSizeExt() {
        return this.sizeExt;
    }

    protected void implMultiplyAcc(long[] jArr, long[] jArr2, long[] jArr3) {
        int i;
        long[] jArr4 = new long[16];
        int i2 = 0;
        for (int i3 = 0; i3 < this.size; i3++) {
            implMulwAcc(jArr4, jArr[i3], jArr2[i3], jArr3, i3 << 1);
        }
        long j = jArr3[0];
        long j2 = jArr3[1];
        for (int i4 = 1; i4 < this.size; i4++) {
            int i5 = i4 << 1;
            j ^= jArr3[i5];
            jArr3[i4] = j ^ j2;
            j2 ^= jArr3[i5 + 1];
        }
        long j3 = j ^ j2;
        while (true) {
            i = this.size;
            if (i2 >= i) {
                break;
            }
            jArr3[i + i2] = jArr3[i2] ^ j3;
            i2++;
        }
        int i6 = i - 1;
        for (int i7 = 1; i7 < i6 * 2; i7++) {
            int min = Math.min(i6, i7);
            int i8 = i7 - min;
            for (int i9 = min; i8 < i9; i9--) {
                implMulwAcc(jArr4, jArr[i8] ^ jArr[i9], jArr2[i8] ^ jArr2[i9], jArr3, i7);
                i8++;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void inv(long[] jArr, long[] jArr2) {
        long[] create = create();
        long[] create2 = create();
        long[] create3 = create();
        copy(jArr, create);
        copy(jArr, create3);
        int i = this.bits - 2;
        int numberOfLeadingZeros = 32 - Integers.numberOfLeadingZeros(i);
        for (int i2 = 1; i2 < numberOfLeadingZeros; i2++) {
            squareN(create, 1 << (i2 - 1), create2);
            multiply(create, create2, create);
            int i3 = 1 << i2;
            if ((i & i3) != 0) {
                squareN(create, (i3 - 1) & i, create2);
                multiply(create3, create2, create3);
            }
        }
        square(create3, jArr2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void multiply(long[] jArr, long[] jArr2, long[] jArr3) {
        long[] createExt = createExt();
        implMultiplyAcc(jArr, jArr2, createExt);
        reduce(createExt, jArr3);
    }

    void reduce(long[] jArr, long[] jArr2) {
        int i = 64 - (this.bits & 63);
        int i2 = this.size;
        Nat.shiftUpBits64(i2, jArr, i2, i, jArr[i2 - 1], jArr2, 0);
        addTo(jArr, jArr2);
        int i3 = this.size - 1;
        jArr2[i3] = jArr2[i3] & ((-1) >>> i);
    }

    void square(long[] jArr, long[] jArr2) {
        long[] createExt = createExt();
        implSquare(jArr, createExt);
        reduce(createExt, jArr2);
    }

    void squareN(long[] jArr, int i, long[] jArr2) {
        if (i >= 64) {
            implPermute(jArr, i, jArr2);
            return;
        }
        long[] createExt = createExt();
        implSquare(jArr, createExt);
        while (true) {
            reduce(createExt, jArr2);
            i--;
            if (i <= 0) {
                return;
            }
            implSquare(jArr2, createExt);
        }
    }
}