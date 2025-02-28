package org.bouncycastle.oer.its.template.etsi102941;

import java.math.BigInteger;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;

/* loaded from: classes2.dex */
public class EtsiTs102941TypesAuthorizationValidation {
    public static final OERDefinition.Builder AuthorizationValidationRequest;
    public static final OERDefinition.Builder AuthorizationValidationResponse;
    public static final OERDefinition.Builder AuthorizationValidationResponseCode;

    static {
        OERDefinition.Builder typeName = OERDefinition.enumeration(OERDefinition.enumItem("ok", BigInteger.ZERO), "cantparse", "badcontenttype", "imnottherecipient", "unknownencryptionalgorithm", "decryptionfailed", "invalidaa", "invalidaasignature", "wrongea", "unknownits", "invalidsignature", "invalidencryptionkey", "deniedpermissions", "deniedtoomanycerts", "deniedrequest").typeName("AuthorizationValidationResponseCode");
        AuthorizationValidationResponseCode = typeName;
        AuthorizationValidationRequest = OERDefinition.seq(EtsiTs102941TypesAuthorization.SharedAtRequest.label("sharedAtRequest"), EtsiTs102941BaseTypes.EcSignature.label("ecSignature"), OERDefinition.extension(new Object[0])).typeName("AuthorizationValidationRequest");
        AuthorizationValidationResponse = OERDefinition.seq(OERDefinition.octets(16).label("requestHash"), typeName.label("responseCode"), OERDefinition.optional(EtsiTs102941BaseTypes.CertificateSubjectAttributes.label("confirmedSubjectAttributes")), OERDefinition.extension(new Object[0])).typeName("AuthorizationValidationResponse");
    }
}