package org.bouncycastle.oer.its.template.etsi102941;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;

/* loaded from: classes2.dex */
public class EtsiTs102941TypesLinkCertificate {
    public static final OERDefinition.Builder ToBeSignedLinkCertificate;
    public static final OERDefinition.Builder ToBeSignedLinkCertificateRca;
    public static final OERDefinition.Builder ToBeSignedLinkCertificateTlm;

    static {
        OERDefinition.Builder typeName = OERDefinition.seq(Ieee1609Dot2BaseTypes.Time32.label("expiryTime"), IEEE1609dot2.HashedData.label("certificateHash"), OERDefinition.extension(new Object[0])).typeName("ToBeSignedLinkCertificate");
        ToBeSignedLinkCertificate = typeName;
        ToBeSignedLinkCertificateTlm = typeName.typeName("ToBeSignedLinkCertificateTlm");
        ToBeSignedLinkCertificateRca = typeName.typeName("ToBeSignedLinkCertificateRca");
    }
}