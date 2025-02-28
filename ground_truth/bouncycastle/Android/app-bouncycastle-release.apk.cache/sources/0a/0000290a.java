package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;

/* loaded from: classes2.dex */
public class UINT8 extends UintBase {
    private static final BigInteger MAX = BigInteger.valueOf(255);

    public UINT8(int i) {
        super(i);
    }

    public UINT8(long j) {
        super(j);
    }

    public UINT8(BigInteger bigInteger) {
        super(bigInteger);
    }

    protected UINT8(ASN1Integer aSN1Integer) {
        super(aSN1Integer);
    }

    public static UINT8 getInstance(Object obj) {
        if (obj instanceof UINT8) {
            return (UINT8) obj;
        }
        if (obj != null) {
            return new UINT8(ASN1Integer.getInstance(obj));
        }
        return null;
    }

    @Override // org.bouncycastle.oer.its.ieee1609dot2.basetypes.UintBase
    protected void assertLimit() {
        if (this.value.signum() < 0) {
            throw new IllegalArgumentException("value must not be negative");
        }
        BigInteger bigInteger = this.value;
        BigInteger bigInteger2 = MAX;
        if (bigInteger.compareTo(bigInteger2) > 0) {
            throw new IllegalArgumentException("value 0x" + this.value.toString(16) + "  must not exceed 0x" + bigInteger2.toString(16));
        }
    }
}