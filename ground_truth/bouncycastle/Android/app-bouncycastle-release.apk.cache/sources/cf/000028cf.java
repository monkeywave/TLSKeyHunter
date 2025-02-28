package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class LinkageSeed extends ASN1Object {
    private final byte[] linkageSeed;

    private LinkageSeed(ASN1OctetString aSN1OctetString) {
        this(aSN1OctetString.getOctets());
    }

    public LinkageSeed(byte[] bArr) {
        if (bArr.length != 16) {
            throw new IllegalArgumentException("linkage seed not 16 bytes");
        }
        this.linkageSeed = Arrays.clone(bArr);
    }

    public static LinkageSeed getInstance(Object obj) {
        if (obj instanceof LinkageSeed) {
            return (LinkageSeed) obj;
        }
        if (obj != null) {
            return new LinkageSeed(DEROctetString.getInstance(obj));
        }
        return null;
    }

    public byte[] getLinkageSeed() {
        return this.linkageSeed;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DEROctetString(this.linkageSeed);
    }
}