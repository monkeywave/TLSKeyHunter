package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/* loaded from: classes2.dex */
public class CtlCommand extends ASN1Object implements ASN1Choice {
    public static final int add = 0;
    public static final int delete = 1;
    private final int choice;
    private final ASN1Encodable ctlCommand;

    public CtlCommand(int i, ASN1Encodable aSN1Encodable) {
        this.choice = i;
        this.ctlCommand = aSN1Encodable;
    }

    private CtlCommand(ASN1TaggedObject aSN1TaggedObject) {
        ASN1Encodable ctlEntry;
        int tagNo = aSN1TaggedObject.getTagNo();
        this.choice = tagNo;
        if (tagNo == 0) {
            ctlEntry = CtlEntry.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        } else if (tagNo != 1) {
            throw new IllegalArgumentException("invalid choice value " + tagNo);
        } else {
            ctlEntry = CtlDelete.getInstance(aSN1TaggedObject.getExplicitBaseObject());
        }
        this.ctlCommand = ctlEntry;
    }

    public static CtlCommand add(CtlEntry ctlEntry) {
        return new CtlCommand(0, ctlEntry);
    }

    public static CtlCommand delete(CtlDelete ctlDelete) {
        return new CtlCommand(1, ctlDelete);
    }

    public static CtlCommand getInstance(Object obj) {
        if (obj instanceof CtlCommand) {
            return (CtlCommand) obj;
        }
        if (obj != null) {
            return new CtlCommand(ASN1TaggedObject.getInstance(obj, 128));
        }
        return null;
    }

    public int getChoice() {
        return this.choice;
    }

    public ASN1Encodable getCtlCommand() {
        return this.ctlCommand;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(this.choice, this.ctlCommand);
    }
}