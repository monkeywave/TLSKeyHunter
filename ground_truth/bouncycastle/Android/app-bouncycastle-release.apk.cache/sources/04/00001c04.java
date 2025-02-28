package org.bouncycastle.asn1.p009x9;

import java.util.Enumeration;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.anssi.ANSSINamedCurves;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.p007gm.GMNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.crypto.p010ec.CustomNamedCurves;
import org.bouncycastle.internal.asn1.cryptlib.CryptlibObjectIdentifiers;

/* renamed from: org.bouncycastle.asn1.x9.ECNamedCurveTable */
/* loaded from: classes.dex */
public class ECNamedCurveTable {
    private static void addEnumeration(Vector vector, Enumeration enumeration) {
        while (enumeration.hasMoreElements()) {
            vector.addElement(enumeration.nextElement());
        }
    }

    public static X9ECParameters getByName(String str) {
        X9ECParameters byName = X962NamedCurves.getByName(str);
        if (byName == null) {
            byName = SECNamedCurves.getByName(str);
        }
        if (byName == null) {
            byName = NISTNamedCurves.getByName(str);
        }
        if (byName == null) {
            byName = TeleTrusTNamedCurves.getByName(str);
        }
        if (byName == null) {
            byName = ANSSINamedCurves.getByName(str);
        }
        if (byName == null) {
            byName = ECGOST3410NamedCurves.getByNameX9(str);
        }
        return byName == null ? GMNamedCurves.getByName(str) : byName;
    }

    public static X9ECParametersHolder getByNameLazy(String str) {
        X9ECParametersHolder byNameLazy = X962NamedCurves.getByNameLazy(str);
        if (byNameLazy == null) {
            byNameLazy = SECNamedCurves.getByNameLazy(str);
        }
        if (byNameLazy == null) {
            byNameLazy = NISTNamedCurves.getByNameLazy(str);
        }
        if (byNameLazy == null) {
            byNameLazy = TeleTrusTNamedCurves.getByNameLazy(str);
        }
        if (byNameLazy == null) {
            byNameLazy = ANSSINamedCurves.getByNameLazy(str);
        }
        if (byNameLazy == null) {
            byNameLazy = ECGOST3410NamedCurves.getByNameLazy(str);
        }
        return byNameLazy == null ? GMNamedCurves.getByNameLazy(str) : byNameLazy;
    }

    public static X9ECParameters getByOID(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        X9ECParameters byOID = X962NamedCurves.getByOID(aSN1ObjectIdentifier);
        if (byOID == null) {
            byOID = SECNamedCurves.getByOID(aSN1ObjectIdentifier);
        }
        if (byOID == null) {
            byOID = TeleTrusTNamedCurves.getByOID(aSN1ObjectIdentifier);
        }
        if (byOID == null) {
            byOID = ANSSINamedCurves.getByOID(aSN1ObjectIdentifier);
        }
        if (byOID == null) {
            byOID = ECGOST3410NamedCurves.getByOIDX9(aSN1ObjectIdentifier);
        }
        return byOID == null ? GMNamedCurves.getByOID(aSN1ObjectIdentifier) : byOID;
    }

    public static X9ECParametersHolder getByOIDLazy(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        X9ECParametersHolder byOIDLazy = X962NamedCurves.getByOIDLazy(aSN1ObjectIdentifier);
        if (byOIDLazy == null) {
            byOIDLazy = SECNamedCurves.getByOIDLazy(aSN1ObjectIdentifier);
        }
        if (byOIDLazy == null) {
            byOIDLazy = TeleTrusTNamedCurves.getByOIDLazy(aSN1ObjectIdentifier);
        }
        if (byOIDLazy == null) {
            byOIDLazy = ANSSINamedCurves.getByOIDLazy(aSN1ObjectIdentifier);
        }
        if (byOIDLazy == null) {
            byOIDLazy = ECGOST3410NamedCurves.getByOIDLazy(aSN1ObjectIdentifier);
        }
        return byOIDLazy == null ? GMNamedCurves.getByOIDLazy(aSN1ObjectIdentifier) : byOIDLazy;
    }

    public static String getName(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        String name = X962NamedCurves.getName(aSN1ObjectIdentifier);
        if (name == null) {
            name = SECNamedCurves.getName(aSN1ObjectIdentifier);
        }
        if (name == null) {
            name = NISTNamedCurves.getName(aSN1ObjectIdentifier);
        }
        if (name == null) {
            name = TeleTrusTNamedCurves.getName(aSN1ObjectIdentifier);
        }
        if (name == null) {
            name = ANSSINamedCurves.getName(aSN1ObjectIdentifier);
        }
        if (name == null) {
            name = ECGOST3410NamedCurves.getName(aSN1ObjectIdentifier);
        }
        if (name == null) {
            name = GMNamedCurves.getName(aSN1ObjectIdentifier);
        }
        return name == null ? CustomNamedCurves.getName(aSN1ObjectIdentifier) : name;
    }

    public static Enumeration getNames() {
        Vector vector = new Vector();
        addEnumeration(vector, X962NamedCurves.getNames());
        addEnumeration(vector, SECNamedCurves.getNames());
        addEnumeration(vector, NISTNamedCurves.getNames());
        addEnumeration(vector, TeleTrusTNamedCurves.getNames());
        addEnumeration(vector, ANSSINamedCurves.getNames());
        addEnumeration(vector, ECGOST3410NamedCurves.getNames());
        addEnumeration(vector, GMNamedCurves.getNames());
        return vector.elements();
    }

    public static ASN1ObjectIdentifier getOID(String str) {
        ASN1ObjectIdentifier oid = X962NamedCurves.getOID(str);
        if (oid == null) {
            oid = SECNamedCurves.getOID(str);
        }
        if (oid == null) {
            oid = NISTNamedCurves.getOID(str);
        }
        if (oid == null) {
            oid = TeleTrusTNamedCurves.getOID(str);
        }
        if (oid == null) {
            oid = ANSSINamedCurves.getOID(str);
        }
        if (oid == null) {
            oid = ECGOST3410NamedCurves.getOID(str);
        }
        if (oid == null) {
            oid = GMNamedCurves.getOID(str);
        }
        return (oid == null && str.equals("curve25519")) ? CryptlibObjectIdentifiers.curvey25519 : oid;
    }
}