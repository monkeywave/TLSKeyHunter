package org.bouncycastle.oer.its.etsi103097.extension;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/* loaded from: classes2.dex */
public class ExtId extends ASN1Object {
    private static final BigInteger MAX = BigInteger.valueOf(255);
    private final BigInteger extId;

    public ExtId(long j) {
        this(BigInteger.valueOf(j));
    }

    public ExtId(BigInteger bigInteger) {
        if (bigInteger.signum() < 0 || bigInteger.compareTo(MAX) > 0) {
            throw new IllegalArgumentException("value " + bigInteger + " outside of range 0...255");
        }
        this.extId = bigInteger;
    }

    private ExtId(ASN1Integer aSN1Integer) {
        this(aSN1Integer.getValue());
    }

    public ExtId(byte[] bArr) {
        this(new BigInteger(bArr));
    }

    public static ExtId getInstance(Object obj) {
        if (obj instanceof ExtId) {
            return (ExtId) obj;
        }
        if (obj != null) {
            return new ExtId(ASN1Integer.getInstance(obj));
        }
        return null;
    }

    public BigInteger getExtId() {
        return this.extId;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new ASN1Integer(this.extId);
    }
}