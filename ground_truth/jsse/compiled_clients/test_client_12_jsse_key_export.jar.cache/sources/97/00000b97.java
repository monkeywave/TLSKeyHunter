package org.bouncycastle.jcajce.util;

import java.io.IOException;
import java.security.AlgorithmParameters;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/util/AlgorithmParametersUtils.class */
public class AlgorithmParametersUtils {
    private AlgorithmParametersUtils() {
    }

    public static ASN1Encodable extractParameters(AlgorithmParameters algorithmParameters) throws IOException {
        ASN1Primitive fromByteArray;
        try {
            fromByteArray = ASN1Primitive.fromByteArray(algorithmParameters.getEncoded("ASN.1"));
        } catch (Exception e) {
            fromByteArray = ASN1Primitive.fromByteArray(algorithmParameters.getEncoded());
        }
        return fromByteArray;
    }

    public static void loadParameters(AlgorithmParameters algorithmParameters, ASN1Encodable aSN1Encodable) throws IOException {
        try {
            algorithmParameters.init(aSN1Encodable.toASN1Primitive().getEncoded(), "ASN.1");
        } catch (Exception e) {
            algorithmParameters.init(aSN1Encodable.toASN1Primitive().getEncoded());
        }
    }
}