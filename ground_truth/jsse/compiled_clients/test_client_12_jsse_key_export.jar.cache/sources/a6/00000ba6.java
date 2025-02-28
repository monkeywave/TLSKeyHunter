package org.bouncycastle.jce;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.p003x9.X9ECParameters;
import org.bouncycastle.crypto.p004ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/ECNamedCurveTable.class */
public class ECNamedCurveTable {
    public static ECNamedCurveParameterSpec getParameterSpec(String str) {
        X9ECParameters byName = CustomNamedCurves.getByName(str);
        if (byName == null) {
            try {
                byName = CustomNamedCurves.getByOID(new ASN1ObjectIdentifier(str));
            } catch (IllegalArgumentException e) {
            }
            if (byName == null) {
                byName = org.bouncycastle.asn1.p003x9.ECNamedCurveTable.getByName(str);
                if (byName == null) {
                    try {
                        byName = org.bouncycastle.asn1.p003x9.ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(str));
                    } catch (IllegalArgumentException e2) {
                    }
                }
            }
        }
        if (byName == null) {
            return null;
        }
        return new ECNamedCurveParameterSpec(str, byName.getCurve(), byName.getG(), byName.getN(), byName.getH(), byName.getSeed());
    }

    public static Enumeration getNames() {
        return org.bouncycastle.asn1.p003x9.ECNamedCurveTable.getNames();
    }
}