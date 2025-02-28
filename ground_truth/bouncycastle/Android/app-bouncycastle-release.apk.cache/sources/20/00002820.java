package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId;

/* loaded from: classes2.dex */
public class CrlEntry extends HashedId {
    private CrlEntry(ASN1OctetString aSN1OctetString) {
        super(aSN1OctetString.getOctets());
    }

    public CrlEntry(byte[] bArr) {
        super(bArr);
        if (bArr.length != 8) {
            throw new IllegalArgumentException("expected 8 bytes");
        }
    }

    public static CrlEntry getInstance(Object obj) {
        if (obj instanceof CrlEntry) {
            return (CrlEntry) obj;
        }
        if (obj != null) {
            return new CrlEntry(ASN1OctetString.getInstance(obj));
        }
        return null;
    }
}