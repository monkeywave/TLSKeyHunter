package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/* loaded from: classes2.dex */
public class ToBeSignedRcaCtl extends CtlFormat {
    protected ToBeSignedRcaCtl(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public ToBeSignedRcaCtl(Version version, Time32 time32, ASN1Boolean aSN1Boolean, UINT8 uint8, SequenceOfCtlCommand sequenceOfCtlCommand) {
        super(version, time32, aSN1Boolean, uint8, sequenceOfCtlCommand);
    }

    public static ToBeSignedRcaCtl getInstance(Object obj) {
        if (obj instanceof ToBeSignedRcaCtl) {
            return (ToBeSignedRcaCtl) obj;
        }
        if (obj != null) {
            return new ToBeSignedRcaCtl(ASN1Sequence.getInstance(obj));
        }
        return null;
    }
}