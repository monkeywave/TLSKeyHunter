package org.bouncycastle.oer.its.template.etsi102941;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;

/* loaded from: classes2.dex */
public class EtsiTs102941MessagesCa {
    public static final OERDefinition.Builder AuthorizationValidationRequestMessage;
    public static final OERDefinition.Builder CaCertificateRekeyingMessage;
    public static final OERDefinition.Builder CaCertificateRequestMessage;
    public static final OERDefinition.Builder EtsiTs102941Data;
    public static final OERDefinition.Builder EtsiTs102941DataContent;
    public static final OERDefinition.Builder RcaDoubleSignedLinkCertificateMessage;
    public static final OERDefinition.Builder RcaSingleSignedLinkCertificateMessage;
    public static final OERDefinition.Builder TlmLinkCertificateMessage;
    public static final OERDefinition.Builder EnrolmentRequestMessage = EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("EnrolmentRequestMessage");
    public static final OERDefinition.Builder EnrolmentResponseMessage = EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("EnrolmentResponseMessage");
    public static final OERDefinition.Builder AuthorizationRequestMessage = EtsiTs103097Module.EtsiTs103097Data_Encrypted_Unicast.typeName("AuthorizationRequestMessage");
    public static final OERDefinition.Builder AuthorizationRequestMessageWithPop = EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("AuthorizationRequestMessageWithPop");
    public static final OERDefinition.Builder AuthorizationResponseMessage = EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("AuthorizationResponseMessage");
    public static final OERDefinition.Builder CertificateRevocationListMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("CertificateRevocationListMessage");
    public static final OERDefinition.Builder TlmCertificateTrustListMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("TlmCertificateTrustListMessage");
    public static final OERDefinition.Builder RcaCertificateTrustListMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("RcaCertificateTrustListMessage");

    static {
        OERDefinition.Builder typeName = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("RcaSingleSignedLinkCertificateMessage");
        RcaSingleSignedLinkCertificateMessage = typeName;
        OERDefinition.Builder typeName2 = OERDefinition.choice(EtsiTs102941TypesEnrolment.InnerEcRequestSignedForPop.label("enrolmentRequest"), EtsiTs102941TypesEnrolment.InnerEcResponse.label("enrolmentResponse"), EtsiTs102941TypesAuthorization.InnerAtRequest.label("authorizationRequest"), EtsiTs102941TypesAuthorization.InnerAtResponse.label("authorizationResponse"), EtsiTs102941TrustLists.ToBeSignedCrl.label("certificateRevocationList"), EtsiTs102941TrustLists.ToBeSignedTlmCtl.label("certificateTrustListTlm"), EtsiTs102941TrustLists.ToBeSignedRcaCtl.label("certificateTrustListRca"), EtsiTs102941TypesAuthorizationValidation.AuthorizationValidationRequest.label("authorizationValidationRequest"), EtsiTs102941TypesAuthorizationValidation.AuthorizationValidationResponse.label("authorizationValidationResponse"), EtsiTs102941TypesCaManagement.CaCertificateRequest.label("caCertificateRequest"), OERDefinition.extension(EtsiTs102941TypesLinkCertificate.ToBeSignedLinkCertificateTlm.label("linkCertificateTlm"), EtsiTs102941TypesLinkCertificate.ToBeSignedLinkCertificateRca.label("singleSignedLinkCertificateRca"), typeName.label("doubleSignedlinkCertificateRca"))).typeName("EtsiTs102941DataContent");
        EtsiTs102941DataContent = typeName2;
        EtsiTs102941Data = OERDefinition.seq(EtsiTs102941BaseTypes.Version.label("version"), typeName2.label("content")).typeName("EtsiTs102941Data");
        AuthorizationValidationRequestMessage = EtsiTs103097Module.EtsiTs103097Data_SignedAndEncrypted_Unicast.typeName("AuthorizationValidationRequestMessage");
        CaCertificateRequestMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("CaCertificateRequestMessage");
        CaCertificateRekeyingMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("CaCertificateRekeyingMessage");
        TlmLinkCertificateMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("TlmLinkCertificateMessage");
        RcaDoubleSignedLinkCertificateMessage = EtsiTs103097Module.EtsiTs103097Data_Signed.typeName("RcaDoubleSignedLinkCertificateMessage");
    }
}