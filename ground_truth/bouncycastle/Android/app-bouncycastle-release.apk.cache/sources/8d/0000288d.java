package org.bouncycastle.oer.its.ieee1609dot2;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/* loaded from: classes2.dex */
public class PduFunctionalType extends ASN1Object {
    private final BigInteger functionalType;
    private static final BigInteger MAX = BigInteger.valueOf(255);
    public static final PduFunctionalType tlsHandshake = new PduFunctionalType(1);
    public static final PduFunctionalType iso21177ExtendedAuth = new PduFunctionalType(2);

    public PduFunctionalType(long j) {
        this(BigInteger.valueOf(j));
    }

    public PduFunctionalType(BigInteger bigInteger) {
        this.functionalType = assertValue(bigInteger);
    }

    private PduFunctionalType(ASN1Integer aSN1Integer) {
        this(aSN1Integer.getValue());
    }

    public PduFunctionalType(byte[] bArr) {
        this(new BigInteger(bArr));
    }

    private static BigInteger assertValue(BigInteger bigInteger) {
        if (bigInteger.signum() >= 0) {
            BigInteger bigInteger2 = MAX;
            if (bigInteger.compareTo(bigInteger2) <= 0) {
                return bigInteger;
            }
            throw new IllegalArgumentException("value exceeds " + bigInteger2);
        }
        throw new IllegalArgumentException("value less than 0");
    }

    public static PduFunctionalType getInstance(Object obj) {
        if (obj instanceof PduFunctionalType) {
            return (PduFunctionalType) obj;
        }
        if (obj != null) {
            return new PduFunctionalType(ASN1Integer.getInstance(obj));
        }
        return null;
    }

    public BigInteger getFunctionalType() {
        return this.functionalType;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new ASN1Integer(this.functionalType);
    }
}