package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes2.dex */
public class CtlEntry extends ASN1Object implements ASN1Choice {

    /* renamed from: aa */
    public static final int f1150aa = 2;

    /* renamed from: dc */
    public static final int f1151dc = 3;

    /* renamed from: ea */
    public static final int f1152ea = 1;
    public static final int rca = 0;
    public static final int tlm = 4;
    private final int choice;
    private final ASN1Encodable ctlEntry;

    public CtlEntry(int i, ASN1Encodable aSN1Encodable) {
        this.choice = i;
        this.ctlEntry = aSN1Encodable;
    }

    private CtlEntry(ASN1TaggedObject aSN1TaggedObject) {
        ASN1Encodable rootCaEntry;
        int tagNo = aSN1TaggedObject.getTagNo();
        this.choice = tagNo;
        if (tagNo == 0) {
            rootCaEntry = RootCaEntry.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        } else if (tagNo == 1) {
            rootCaEntry = EaEntry.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        } else if (tagNo == 2) {
            rootCaEntry = AaEntry.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        } else if (tagNo == 3) {
            rootCaEntry = DcEntry.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        } else if (tagNo != 4) {
            throw new IllegalArgumentException("invalid choice value " + tagNo);
        } else {
            rootCaEntry = TlmEntry.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        }
        this.ctlEntry = rootCaEntry;
    }

    /* renamed from: aa */
    public static CtlEntry m28aa(AaEntry aaEntry) {
        return new CtlEntry(2, aaEntry);
    }

    /* renamed from: dc */
    public static CtlEntry m27dc(DcEntry dcEntry) {
        return new CtlEntry(3, dcEntry);
    }

    /* renamed from: ea */
    public static CtlEntry m26ea(EaEntry eaEntry) {
        return new CtlEntry(1, eaEntry);
    }

    public static CtlEntry getInstance(Object obj) {
        if (obj instanceof CtlEntry) {
            return (CtlEntry) obj;
        }
        if (obj != null) {
            return new CtlEntry(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public static CtlEntry rca(RootCaEntry rootCaEntry) {
        return new CtlEntry(0, rootCaEntry);
    }

    public static CtlEntry tlm(TlmEntry tlmEntry) {
        return new CtlEntry(4, tlmEntry);
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getCtlEntry() {
        return this.ctlEntry;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.ctlEntry);
    }
}