package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Pointer {
    protected long[] array;

    /* renamed from: cp */
    protected int f1275cp;

    public Pointer() {
        this.f1275cp = 0;
    }

    public Pointer(int i) {
        this.array = new long[i];
        this.f1275cp = 0;
    }

    public Pointer(Pointer pointer) {
        this.array = pointer.array;
        this.f1275cp = pointer.f1275cp;
    }

    public Pointer(Pointer pointer, int i) {
        this.array = pointer.array;
        this.f1275cp = pointer.f1275cp + i;
    }

    public void changeIndex(int i) {
        this.f1275cp = i;
    }

    public void changeIndex(Pointer pointer) {
        this.array = pointer.array;
        this.f1275cp = pointer.f1275cp;
    }

    public void changeIndex(Pointer pointer, int i) {
        this.array = pointer.array;
        this.f1275cp = pointer.f1275cp + i;
    }

    public void copyFrom(int i, Pointer pointer, int i2, int i3) {
        System.arraycopy(pointer.array, pointer.f1275cp + i2, this.array, this.f1275cp + i, i3);
    }

    public void copyFrom(Pointer pointer, int i) {
        System.arraycopy(pointer.array, pointer.f1275cp, this.array, this.f1275cp, i);
    }

    public void fill(int i, byte[] bArr, int i2, int i3) {
        long[] jArr;
        int i4;
        int i5 = this.f1275cp + i;
        int i6 = 0;
        int i7 = 0;
        while (true) {
            jArr = this.array;
            if (i5 >= jArr.length || (i4 = i7 + 8) > i3) {
                break;
            }
            jArr[i5] = Pack.littleEndianToLong(bArr, i2);
            i2 += 8;
            i5++;
            i7 = i4;
        }
        if (i7 >= i3 || i5 >= jArr.length) {
            return;
        }
        jArr[i5] = 0;
        while (i6 < 8 && i7 < i3) {
            long[] jArr2 = this.array;
            jArr2[i5] = jArr2[i5] | ((bArr[i2] & 255) << (i6 << 3));
            i6++;
            i2++;
            i7++;
        }
    }

    public void fillRandom(int i, SecureRandom secureRandom, int i2) {
        byte[] bArr = new byte[i2];
        secureRandom.nextBytes(bArr);
        fill(i, bArr, 0, i2);
    }

    public long get() {
        return this.array[this.f1275cp];
    }

    public long get(int i) {
        return this.array[this.f1275cp + i];
    }

    public long[] getArray() {
        return this.array;
    }

    public int getD_for_not0_or_plus(int i, int i2) {
        int i3 = this.f1275cp;
        int i4 = 0;
        long j = 0;
        while (i2 > 0) {
            int i5 = i3 + 1;
            long j2 = this.array[i3];
            int i6 = 1;
            while (i6 < i) {
                j2 |= this.array[i5];
                i6++;
                i5++;
            }
            j |= GeMSSUtils.ORBITS_UINT(j2);
            i4 = (int) (i4 + j);
            i2--;
            i3 = i5;
        }
        return i4;
    }

    public long getDotProduct(int i, Pointer pointer, int i2, int i3) {
        int i4 = i + this.f1275cp;
        int i5 = i2 + pointer.f1275cp;
        int i6 = i4 + 1;
        int i7 = i5 + 1;
        long j = this.array[i4] & pointer.array[i5];
        int i8 = 1;
        while (i8 < i3) {
            j ^= this.array[i6] & pointer.array[i7];
            i8++;
            i7++;
            i6++;
        }
        return j;
    }

    public int getIndex() {
        return this.f1275cp;
    }

    public int getLength() {
        return this.array.length - this.f1275cp;
    }

    public void indexReset() {
        this.f1275cp = 0;
    }

    public int is0_gf2n(int i, int i2) {
        long j = get(i);
        for (int i3 = 1; i3 < i2; i3++) {
            j |= get(i + i3);
        }
        return (int) GeMSSUtils.NORBITS_UINT(j);
    }

    public int isEqual_nocst_gf2(Pointer pointer, int i) {
        int i2 = pointer.f1275cp;
        int i3 = this.f1275cp;
        int i4 = 0;
        while (i4 < i) {
            int i5 = i3 + 1;
            int i6 = i2 + 1;
            if (this.array[i3] != pointer.array[i2]) {
                return 0;
            }
            i4++;
            i2 = i6;
            i3 = i5;
        }
        return 1;
    }

    public void move(int i) {
        this.f1275cp += i;
    }

    public void moveIncremental() {
        this.f1275cp++;
    }

    public int searchDegree(int i, int i2, int i3) {
        while (is0_gf2n(i * i3, i3) != 0 && i >= i2) {
            i--;
        }
        return i;
    }

    public void set(int i, long j) {
        this.array[this.f1275cp + i] = j;
    }

    public void set(long j) {
        this.array[this.f1275cp] = j;
    }

    public void set1_gf2n(int i, int i2) {
        int i3 = this.f1275cp + i;
        int i4 = i3 + 1;
        this.array[i3] = 1;
        int i5 = 1;
        while (i5 < i2) {
            this.array[i4] = 0;
            i5++;
            i4++;
        }
    }

    public void setAnd(int i, long j) {
        long[] jArr = this.array;
        int i2 = this.f1275cp + i;
        jArr[i2] = jArr[i2] & j;
    }

    public void setAnd(long j) {
        long[] jArr = this.array;
        int i = this.f1275cp;
        jArr[i] = j & jArr[i];
    }

    public void setClear(int i) {
        this.array[this.f1275cp + i] = 0;
    }

    public void setRangeClear(int i, int i2) {
        int i3 = i + this.f1275cp;
        Arrays.fill(this.array, i3, i2 + i3, 0L);
    }

    public void setRangeFromXor(int i, Pointer pointer, int i2, Pointer pointer2, int i3, int i4) {
        int i5 = i + this.f1275cp;
        int i6 = i2 + pointer.f1275cp;
        int i7 = i3 + pointer2.f1275cp;
        int i8 = 0;
        while (i8 < i4) {
            this.array[i5] = pointer.array[i6] ^ pointer2.array[i7];
            i8++;
            i5++;
            i7++;
            i6++;
        }
    }

    public void setRangeFromXor(Pointer pointer, Pointer pointer2, int i) {
        int i2 = this.f1275cp;
        int i3 = pointer.f1275cp;
        int i4 = pointer2.f1275cp;
        int i5 = 0;
        while (i5 < i) {
            this.array[i2] = pointer.array[i3] ^ pointer2.array[i4];
            i5++;
            i2++;
            i4++;
            i3++;
        }
    }

    public void setRangeFromXorAndMask_xor(Pointer pointer, Pointer pointer2, long j, int i) {
        int i2 = this.f1275cp;
        int i3 = pointer.f1275cp;
        int i4 = pointer2.f1275cp;
        int i5 = 0;
        while (i5 < i) {
            long[] jArr = this.array;
            long[] jArr2 = pointer.array;
            long j2 = jArr2[i3];
            long[] jArr3 = pointer2.array;
            long j3 = (j2 ^ jArr3[i4]) & j;
            jArr[i2] = j3;
            jArr2[i3] = j3 ^ jArr2[i3];
            jArr3[i4] = jArr3[i4] ^ jArr[i2];
            i5++;
            i4++;
            i2++;
            i3++;
        }
    }

    public void setRangePointerUnion(PointerUnion pointerUnion, int i) {
        if (pointerUnion.remainder == 0) {
            System.arraycopy(pointerUnion.array, pointerUnion.f1275cp, this.array, this.f1275cp, i);
            return;
        }
        int i2 = (8 - pointerUnion.remainder) << 3;
        int i3 = pointerUnion.remainder << 3;
        int i4 = this.f1275cp;
        int i5 = pointerUnion.f1275cp;
        int i6 = 0;
        while (i6 < i) {
            i5++;
            this.array[i4] = (pointerUnion.array[i5] >>> i3) ^ (pointerUnion.array[i5] << i2);
            i6++;
            i4++;
        }
    }

    public void setRangePointerUnion(PointerUnion pointerUnion, int i, int i2) {
        int i3 = i2 & 63;
        int i4 = 64 - i3;
        int i5 = this.f1275cp;
        int i6 = pointerUnion.f1275cp;
        int i7 = 0;
        if (pointerUnion.remainder == 0) {
            while (i7 < i) {
                i6++;
                this.array[i5] = (pointerUnion.array[i6] >>> i3) ^ (pointerUnion.array[i6] << i4);
                i7++;
                i5++;
            }
            return;
        }
        int i8 = pointerUnion.remainder << 3;
        int i9 = (8 - pointerUnion.remainder) << 3;
        while (i7 < i) {
            int i10 = i6 + 1;
            this.array[i5] = (((pointerUnion.array[i6] >>> i8) | (pointerUnion.array[i10] << i9)) >>> i3) ^ (((pointerUnion.array[i10] >>> i8) | (pointerUnion.array[i6 + 2] << i9)) << i4);
            i7++;
            i5++;
            i6 = i10;
        }
    }

    public void setRangePointerUnion_Check(PointerUnion pointerUnion, int i, int i2) {
        int i3 = i2 & 63;
        int i4 = 64 - i3;
        int i5 = this.f1275cp;
        int i6 = pointerUnion.f1275cp;
        int i7 = 0;
        if (pointerUnion.remainder == 0) {
            while (i7 < i && i6 < pointerUnion.array.length - 1) {
                i6++;
                this.array[i5] = (pointerUnion.array[i6] >>> i3) ^ (pointerUnion.array[i6] << i4);
                i7++;
                i5++;
            }
            if (i7 < i) {
                this.array[i5] = pointerUnion.array[i6] >>> i3;
                return;
            }
            return;
        }
        int i8 = pointerUnion.remainder << 3;
        int i9 = (8 - pointerUnion.remainder) << 3;
        while (i7 < i && i6 < pointerUnion.array.length - 2) {
            int i10 = i6 + 1;
            this.array[i5] = (((pointerUnion.array[i6] >>> i8) | (pointerUnion.array[i10] << i9)) >>> i3) ^ (((pointerUnion.array[i10] >>> i8) | (pointerUnion.array[i6 + 2] << i9)) << i4);
            i7++;
            i5++;
            i6 = i10;
        }
        if (i7 < i) {
            int i11 = i6 + 1;
            this.array[i5] = ((pointerUnion.array[i11] >>> i8) << i4) ^ (((pointerUnion.array[i11] << i9) | (pointerUnion.array[i6] >>> i8)) >>> i3);
        }
    }

    public void setRangeRotate(int i, Pointer pointer, int i2, int i3, int i4) {
        int i5 = 64 - i4;
        int i6 = i + this.f1275cp;
        int i7 = i2 + pointer.f1275cp;
        int i8 = 0;
        while (i8 < i3) {
            long[] jArr = this.array;
            long[] jArr2 = pointer.array;
            i7++;
            jArr[i6] = (jArr2[i7] >>> i5) ^ (jArr2[i7] << i4);
            i8++;
            i6++;
        }
    }

    public int setRange_xi(long j, int i, int i2) {
        int i3 = 0;
        while (i3 < i2) {
            this.array[this.f1275cp + i] = -((j >>> i3) & 1);
            i3++;
            i++;
        }
        return i;
    }

    public void setXor(int i, long j) {
        long[] jArr = this.array;
        int i2 = this.f1275cp + i;
        jArr[i2] = jArr[i2] ^ j;
    }

    public void setXor(long j) {
        long[] jArr = this.array;
        int i = this.f1275cp;
        jArr[i] = j ^ jArr[i];
    }

    public void setXorMatrix(Pointer pointer, int i, int i2) {
        int i3 = this.f1275cp;
        for (int i4 = 0; i4 < i2; i4++) {
            int i5 = i3;
            int i6 = 0;
            while (i6 < i) {
                long[] jArr = this.array;
                long j = jArr[i5];
                long[] jArr2 = pointer.array;
                int i7 = pointer.f1275cp;
                pointer.f1275cp = i7 + 1;
                jArr[i5] = j ^ jArr2[i7];
                i6++;
                i5++;
            }
        }
        this.f1275cp += i;
    }

    public void setXorMatrix_NoMove(Pointer pointer, int i, int i2) {
        int i3 = this.f1275cp;
        for (int i4 = 0; i4 < i2; i4++) {
            int i5 = i3;
            int i6 = 0;
            while (i6 < i) {
                long[] jArr = this.array;
                long j = jArr[i5];
                long[] jArr2 = pointer.array;
                int i7 = pointer.f1275cp;
                pointer.f1275cp = i7 + 1;
                jArr[i5] = j ^ jArr2[i7];
                i6++;
                i5++;
            }
        }
    }

    public void setXorRange(int i, Pointer pointer, int i2, int i3) {
        int i4 = i + this.f1275cp;
        int i5 = i2 + pointer.f1275cp;
        int i6 = 0;
        while (i6 < i3) {
            long[] jArr = this.array;
            jArr[i4] = jArr[i4] ^ pointer.array[i5];
            i6++;
            i4++;
            i5++;
        }
    }

    public void setXorRange(int i, PointerUnion pointerUnion, int i2, int i3) {
        int i4 = i + this.f1275cp;
        int i5 = i2 + pointerUnion.f1275cp;
        int i6 = 0;
        if (pointerUnion.remainder == 0) {
            while (i6 < i3) {
                long[] jArr = this.array;
                jArr[i4] = jArr[i4] ^ pointerUnion.array[i5];
                i6++;
                i4++;
                i5++;
            }
            return;
        }
        int i7 = pointerUnion.remainder << 3;
        int i8 = (8 - pointerUnion.remainder) << 3;
        while (i6 < i3) {
            long[] jArr2 = this.array;
            i5++;
            jArr2[i4] = jArr2[i4] ^ ((pointerUnion.array[i5] >>> i7) | (pointerUnion.array[i5] << i8));
            i6++;
            i4++;
        }
    }

    public void setXorRange(Pointer pointer, int i) {
        int i2 = this.f1275cp;
        int i3 = pointer.f1275cp;
        int i4 = 0;
        while (i4 < i) {
            long[] jArr = this.array;
            jArr[i2] = jArr[i2] ^ pointer.array[i3];
            i4++;
            i2++;
            i3++;
        }
    }

    public void setXorRange(Pointer pointer, int i, int i2) {
        int i3 = this.f1275cp;
        int i4 = i + pointer.f1275cp;
        int i5 = 0;
        while (i5 < i2) {
            long[] jArr = this.array;
            jArr[i3] = jArr[i3] ^ pointer.array[i4];
            i5++;
            i3++;
            i4++;
        }
    }

    public void setXorRangeAndMask(Pointer pointer, int i, long j) {
        int i2 = this.f1275cp;
        int i3 = pointer.f1275cp;
        int i4 = 0;
        while (i4 < i) {
            long[] jArr = this.array;
            jArr[i2] = jArr[i2] ^ (pointer.array[i3] & j);
            i4++;
            i2++;
            i3++;
        }
    }

    public void setXorRangeAndMaskMove(Pointer pointer, int i, long j) {
        int i2 = this.f1275cp;
        int i3 = 0;
        while (i3 < i) {
            long[] jArr = this.array;
            long j2 = jArr[i2];
            long[] jArr2 = pointer.array;
            int i4 = pointer.f1275cp;
            pointer.f1275cp = i4 + 1;
            jArr[i2] = j2 ^ (jArr2[i4] & j);
            i3++;
            i2++;
        }
    }

    public void setXorRangeXor(int i, Pointer pointer, int i2, Pointer pointer2, int i3, int i4) {
        int i5 = i + this.f1275cp;
        int i6 = i2 + pointer.f1275cp;
        int i7 = i3 + pointer2.f1275cp;
        int i8 = 0;
        while (i8 < i4) {
            long[] jArr = this.array;
            jArr[i5] = (pointer.array[i6] ^ pointer2.array[i7]) ^ jArr[i5];
            i8++;
            i5++;
            i7++;
            i6++;
        }
    }

    public void setXorRange_SelfMove(Pointer pointer, int i) {
        int i2 = pointer.f1275cp;
        int i3 = 0;
        while (i3 < i) {
            long[] jArr = this.array;
            int i4 = this.f1275cp;
            this.f1275cp = i4 + 1;
            jArr[i4] = jArr[i4] ^ pointer.array[i2];
            i3++;
            i2++;
        }
    }

    public void swap(Pointer pointer) {
        long[] jArr = pointer.array;
        int i = pointer.f1275cp;
        pointer.array = this.array;
        pointer.f1275cp = this.f1275cp;
        this.array = jArr;
        this.f1275cp = i;
    }

    public byte[] toBytes(int i) {
        byte[] bArr = new byte[i];
        for (int i2 = 0; i2 < i; i2++) {
            bArr[i2] = (byte) (this.array[this.f1275cp + (i2 >>> 3)] >>> ((i2 & 7) << 3));
        }
        return bArr;
    }
}