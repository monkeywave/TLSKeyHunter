package org.bouncycastle.asn1.p009x9;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;

/* renamed from: org.bouncycastle.asn1.x9.X9IntegerConverter */
/* loaded from: classes.dex */
public class X9IntegerConverter {
    public int getByteLength(ECCurve eCCurve) {
        return eCCurve.getFieldElementEncodingLength();
    }

    public int getByteLength(ECFieldElement eCFieldElement) {
        return eCFieldElement.getEncodedLength();
    }

    public byte[] integerToBytes(BigInteger bigInteger, int i) {
        byte[] byteArray = bigInteger.toByteArray();
        if (i < byteArray.length) {
            byte[] bArr = new byte[i];
            System.arraycopy(byteArray, byteArray.length - i, bArr, 0, i);
            return bArr;
        } else if (i > byteArray.length) {
            byte[] bArr2 = new byte[i];
            System.arraycopy(byteArray, 0, bArr2, i - byteArray.length, byteArray.length);
            return bArr2;
        } else {
            return byteArray;
        }
    }
}