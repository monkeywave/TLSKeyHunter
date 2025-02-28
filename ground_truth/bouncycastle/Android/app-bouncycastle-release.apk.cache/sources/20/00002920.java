package org.bouncycastle.oer.its.template.etsi103097;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;

/* loaded from: classes2.dex */
public class EtsiTs103097Module {
    public static final OERDefinition.Builder EtsiTs103097Certificate = IEEE1609dot2.ExplicitCertificate.typeName("EtsiTs103097Certificate");
    public static final OERDefinition.Builder EtsiTs103097Data;
    public static final OERDefinition.Builder EtsiTs103097Data_Encrypted;
    public static final OERDefinition.Builder EtsiTs103097Data_Encrypted_Unicast;
    public static final OERDefinition.Builder EtsiTs103097Data_Signed;
    public static final OERDefinition.Builder EtsiTs103097Data_SignedAndEncrypted;
    public static final OERDefinition.Builder EtsiTs103097Data_SignedAndEncrypted_Unicast;
    public static final OERDefinition.Builder EtsiTs103097Data_SignedExternalPayload;
    public static final OERDefinition.Builder EtsiTs103097Data_Unsecured;

    static {
        OERDefinition.Builder typeName = IEEE1609dot2.Ieee1609Dot2Data.typeName("EtsiTs103097Data");
        EtsiTs103097Data = typeName;
        EtsiTs103097Data_Unsecured = typeName.typeName("EtsiTs103097DataUnsecured");
        EtsiTs103097Data_Signed = typeName.typeName("EtsiTs103097DataSigned");
        EtsiTs103097Data_SignedExternalPayload = typeName.typeName("EtsiTs103097DataSignedExternalPayload");
        EtsiTs103097Data_Encrypted = typeName.typeName("EtsiTs103097DataEncrypted");
        EtsiTs103097Data_SignedAndEncrypted = typeName.typeName("EtsiTs103097DataSignedAndEncrypted");
        EtsiTs103097Data_Encrypted_Unicast = typeName.typeName("EtsiTs103097DataEncryptedUnicast");
        EtsiTs103097Data_SignedAndEncrypted_Unicast = typeName.typeName("EtsiTs103097DataSignedAndEncryptedUnicast");
    }
}