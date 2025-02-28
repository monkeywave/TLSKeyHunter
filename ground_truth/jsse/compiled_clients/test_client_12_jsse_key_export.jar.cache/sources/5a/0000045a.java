package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/CramerShoupCiphertext.class */
public class CramerShoupCiphertext {

    /* renamed from: u1 */
    BigInteger f320u1;

    /* renamed from: u2 */
    BigInteger f321u2;

    /* renamed from: e */
    BigInteger f322e;

    /* renamed from: v */
    BigInteger f323v;

    public CramerShoupCiphertext() {
    }

    public CramerShoupCiphertext(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f320u1 = bigInteger;
        this.f321u2 = bigInteger2;
        this.f322e = bigInteger3;
        this.f323v = bigInteger4;
    }

    public CramerShoupCiphertext(byte[] bArr) {
        int bigEndianToInt = Pack.bigEndianToInt(bArr, 0);
        int i = 0 + 4;
        int i2 = i + bigEndianToInt;
        this.f320u1 = new BigInteger(Arrays.copyOfRange(bArr, i, i + bigEndianToInt));
        int bigEndianToInt2 = Pack.bigEndianToInt(bArr, i2);
        int i3 = i2 + 4;
        int i4 = i3 + bigEndianToInt2;
        this.f321u2 = new BigInteger(Arrays.copyOfRange(bArr, i3, i3 + bigEndianToInt2));
        int bigEndianToInt3 = Pack.bigEndianToInt(bArr, i4);
        int i5 = i4 + 4;
        int i6 = i5 + bigEndianToInt3;
        this.f322e = new BigInteger(Arrays.copyOfRange(bArr, i5, i5 + bigEndianToInt3));
        int bigEndianToInt4 = Pack.bigEndianToInt(bArr, i6);
        int i7 = i6 + 4;
        int i8 = i7 + bigEndianToInt4;
        this.f323v = new BigInteger(Arrays.copyOfRange(bArr, i7, i7 + bigEndianToInt4));
    }

    public BigInteger getU1() {
        return this.f320u1;
    }

    public void setU1(BigInteger bigInteger) {
        this.f320u1 = bigInteger;
    }

    public BigInteger getU2() {
        return this.f321u2;
    }

    public void setU2(BigInteger bigInteger) {
        this.f321u2 = bigInteger;
    }

    public BigInteger getE() {
        return this.f322e;
    }

    public void setE(BigInteger bigInteger) {
        this.f322e = bigInteger;
    }

    public BigInteger getV() {
        return this.f323v;
    }

    public void setV(BigInteger bigInteger) {
        this.f323v = bigInteger;
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("u1: " + this.f320u1.toString());
        stringBuffer.append("\nu2: " + this.f321u2.toString());
        stringBuffer.append("\ne: " + this.f322e.toString());
        stringBuffer.append("\nv: " + this.f323v.toString());
        return stringBuffer.toString();
    }

    public byte[] toByteArray() {
        byte[] byteArray = this.f320u1.toByteArray();
        int length = byteArray.length;
        byte[] byteArray2 = this.f321u2.toByteArray();
        int length2 = byteArray2.length;
        byte[] byteArray3 = this.f322e.toByteArray();
        int length3 = byteArray3.length;
        byte[] byteArray4 = this.f323v.toByteArray();
        int length4 = byteArray4.length;
        byte[] bArr = new byte[length + length2 + length3 + length4 + 16];
        Pack.intToBigEndian(length, bArr, 0);
        int i = 0 + 4;
        System.arraycopy(byteArray, 0, bArr, i, length);
        int i2 = i + length;
        Pack.intToBigEndian(length2, bArr, i2);
        int i3 = i2 + 4;
        System.arraycopy(byteArray2, 0, bArr, i3, length2);
        int i4 = i3 + length2;
        Pack.intToBigEndian(length3, bArr, i4);
        int i5 = i4 + 4;
        System.arraycopy(byteArray3, 0, bArr, i5, length3);
        int i6 = i5 + length3;
        Pack.intToBigEndian(length4, bArr, i6);
        int i7 = i6 + 4;
        System.arraycopy(byteArray4, 0, bArr, i7, length4);
        int i8 = i7 + length4;
        return bArr;
    }
}