package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class CramerShoupCiphertext {

    /* renamed from: e */
    BigInteger f608e;

    /* renamed from: u1 */
    BigInteger f609u1;

    /* renamed from: u2 */
    BigInteger f610u2;

    /* renamed from: v */
    BigInteger f611v;

    public CramerShoupCiphertext() {
    }

    public CramerShoupCiphertext(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f609u1 = bigInteger;
        this.f610u2 = bigInteger2;
        this.f608e = bigInteger3;
        this.f611v = bigInteger4;
    }

    public CramerShoupCiphertext(byte[] bArr) {
        int bigEndianToInt = Pack.bigEndianToInt(bArr, 0);
        int i = 4 + bigEndianToInt;
        this.f609u1 = new BigInteger(Arrays.copyOfRange(bArr, 4, i));
        int i2 = bigEndianToInt + 8;
        int bigEndianToInt2 = Pack.bigEndianToInt(bArr, i) + i2;
        this.f610u2 = new BigInteger(Arrays.copyOfRange(bArr, i2, bigEndianToInt2));
        int bigEndianToInt3 = Pack.bigEndianToInt(bArr, bigEndianToInt2);
        int i3 = bigEndianToInt2 + 4;
        int i4 = bigEndianToInt3 + i3;
        this.f608e = new BigInteger(Arrays.copyOfRange(bArr, i3, i4));
        int bigEndianToInt4 = Pack.bigEndianToInt(bArr, i4);
        int i5 = i4 + 4;
        this.f611v = new BigInteger(Arrays.copyOfRange(bArr, i5, bigEndianToInt4 + i5));
    }

    public BigInteger getE() {
        return this.f608e;
    }

    public BigInteger getU1() {
        return this.f609u1;
    }

    public BigInteger getU2() {
        return this.f610u2;
    }

    public BigInteger getV() {
        return this.f611v;
    }

    public void setE(BigInteger bigInteger) {
        this.f608e = bigInteger;
    }

    public void setU1(BigInteger bigInteger) {
        this.f609u1 = bigInteger;
    }

    public void setU2(BigInteger bigInteger) {
        this.f610u2 = bigInteger;
    }

    public void setV(BigInteger bigInteger) {
        this.f611v = bigInteger;
    }

    public byte[] toByteArray() {
        byte[] byteArray = this.f609u1.toByteArray();
        int length = byteArray.length;
        byte[] byteArray2 = this.f610u2.toByteArray();
        int length2 = byteArray2.length;
        byte[] byteArray3 = this.f608e.toByteArray();
        int length3 = byteArray3.length;
        byte[] byteArray4 = this.f611v.toByteArray();
        int length4 = byteArray4.length;
        byte[] bArr = new byte[length + length2 + length3 + length4 + 16];
        Pack.intToBigEndian(length, bArr, 0);
        System.arraycopy(byteArray, 0, bArr, 4, length);
        Pack.intToBigEndian(length2, bArr, 4 + length);
        int i = length + 8;
        System.arraycopy(byteArray2, 0, bArr, i, length2);
        int i2 = i + length2;
        Pack.intToBigEndian(length3, bArr, i2);
        int i3 = i2 + 4;
        System.arraycopy(byteArray3, 0, bArr, i3, length3);
        int i4 = i3 + length3;
        Pack.intToBigEndian(length4, bArr, i4);
        System.arraycopy(byteArray4, 0, bArr, i4 + 4, length4);
        return bArr;
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("u1: " + this.f609u1.toString());
        stringBuffer.append("\nu2: " + this.f610u2.toString());
        stringBuffer.append("\ne: " + this.f608e.toString());
        stringBuffer.append("\nv: " + this.f611v.toString());
        return stringBuffer.toString();
    }
}