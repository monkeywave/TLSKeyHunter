package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/spec/EdDSAParameterSpec.class */
public class EdDSAParameterSpec implements AlgorithmParameterSpec {
    public static final String Ed25519 = "Ed25519";
    public static final String Ed448 = "Ed448";
    private final String curveName;

    public EdDSAParameterSpec(String str) {
        if (str.equalsIgnoreCase(Ed25519)) {
            this.curveName = Ed25519;
        } else if (str.equalsIgnoreCase(Ed448)) {
            this.curveName = Ed448;
        } else if (str.equals(EdECObjectIdentifiers.id_Ed25519.getId())) {
            this.curveName = Ed25519;
        } else if (!str.equals(EdECObjectIdentifiers.id_Ed448.getId())) {
            throw new IllegalArgumentException("unrecognized curve name: " + str);
        } else {
            this.curveName = Ed448;
        }
    }

    public String getCurveName() {
        return this.curveName;
    }
}