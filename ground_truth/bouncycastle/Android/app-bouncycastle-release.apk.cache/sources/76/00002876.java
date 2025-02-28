package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/* loaded from: classes2.dex */
public class CounterSignature extends Ieee1609Dot2Data {
    protected CounterSignature(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public CounterSignature(UINT8 uint8, Ieee1609Dot2Content ieee1609Dot2Content) {
        super(uint8, ieee1609Dot2Content);
    }

    public static Ieee1609Dot2Data getInstance(Object obj) {
        if (obj instanceof Ieee1609Dot2Data) {
            return (Ieee1609Dot2Data) obj;
        }
        if (obj != null) {
            return new CounterSignature(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}