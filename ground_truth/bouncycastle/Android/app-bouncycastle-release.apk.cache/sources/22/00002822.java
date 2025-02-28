package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/* loaded from: classes2.dex */
public class CtlDelete extends ASN1Object implements ASN1Choice {
    public static final int cert = 0;

    /* renamed from: dc */
    public static final int f1149dc = 1;
    private final int choice;
    private final ASN1Encodable ctlDelete;

    public CtlDelete(int i, ASN1Encodable aSN1Encodable) {
        ASN1Encodable hashedId8;
        this.choice = i;
        if (i == 0) {
            hashedId8 = HashedId8.getInstance(aSN1Encodable);
        } else if (i != 1) {
            throw new IllegalArgumentException("invalid choice value " + i);
        } else {
            hashedId8 = DcDelete.getInstance(aSN1Encodable);
        }
        this.ctlDelete = hashedId8;
    }

    private CtlDelete(ASN1TaggedObject aSN1TaggedObject) {
        this(aSN1TaggedObject.getTagNo(), aSN1TaggedObject.getExplicitBaseObject());
    }

    public static CtlDelete cert(HashedId8 hashedId8) {
        return new CtlDelete(0, hashedId8);
    }

    /* renamed from: dc */
    public static CtlDelete m29dc(DcDelete dcDelete) {
        return new CtlDelete(1, dcDelete);
    }

    public static CtlDelete getInstance(Object obj) {
        if (obj instanceof CtlDelete) {
            return (CtlDelete) obj;
        }
        if (obj != null) {
            return new CtlDelete(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getCtlDelete() {
        return this.ctlDelete;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.ctlDelete);
    }
}