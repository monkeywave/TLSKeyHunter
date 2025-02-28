package org.bouncycastle.jcajce.provider.asymmetric.p014ec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.p009x9.X962Parameters;
import org.bouncycastle.asn1.p009x9.X9ECParameters;
import org.bouncycastle.asn1.p009x9.X9ECPoint;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.p016ec.ECCurve;

/* JADX INFO: Access modifiers changed from: package-private */
/* renamed from: org.bouncycastle.jcajce.provider.asymmetric.ec.ECUtils */
/* loaded from: classes2.dex */
public class ECUtils {
    ECUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey privateKey) throws InvalidKeyException {
        return privateKey instanceof BCECPrivateKey ? ((BCECPrivateKey) privateKey).engineGetKeyParameters() : ECUtil.generatePrivateKeyParameter(privateKey);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey publicKey) throws InvalidKeyException {
        return publicKey instanceof BCECPublicKey ? ((BCECPublicKey) publicKey).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(publicKey);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static X9ECParameters getDomainParametersFromGenSpec(ECGenParameterSpec eCGenParameterSpec, ProviderConfiguration providerConfiguration) {
        return getDomainParametersFromName(eCGenParameterSpec.getName(), providerConfiguration);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static X962Parameters getDomainParametersFromName(ECParameterSpec eCParameterSpec, boolean z) {
        if (!(eCParameterSpec instanceof ECNamedCurveSpec)) {
            if (eCParameterSpec == null) {
                return new X962Parameters((ASN1Null) DERNull.INSTANCE);
            }
            ECCurve convertCurve = EC5Util.convertCurve(eCParameterSpec.getCurve());
            return new X962Parameters(new X9ECParameters(convertCurve, new X9ECPoint(EC5Util.convertPoint(convertCurve, eCParameterSpec.getGenerator()), z), eCParameterSpec.getOrder(), BigInteger.valueOf(eCParameterSpec.getCofactor()), eCParameterSpec.getCurve().getSeed()));
        }
        ECNamedCurveSpec eCNamedCurveSpec = (ECNamedCurveSpec) eCParameterSpec;
        ASN1ObjectIdentifier namedCurveOid = ECUtil.getNamedCurveOid(eCNamedCurveSpec.getName());
        if (namedCurveOid == null) {
            namedCurveOid = new ASN1ObjectIdentifier(eCNamedCurveSpec.getName());
        }
        return new X962Parameters(namedCurveOid);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static X9ECParameters getDomainParametersFromName(String str, ProviderConfiguration providerConfiguration) {
        if (str == null || str.length() < 1) {
            return null;
        }
        int indexOf = str.indexOf(32);
        if (indexOf > 0) {
            str = str.substring(indexOf + 1);
        }
        ASN1ObjectIdentifier oid = getOID(str);
        if (oid == null) {
            return ECUtil.getNamedCurveByName(str);
        }
        X9ECParameters namedCurveByOid = ECUtil.getNamedCurveByOid(oid);
        return (namedCurveByOid != null || providerConfiguration == null) ? namedCurveByOid : (X9ECParameters) providerConfiguration.getAdditionalECParameters().get(oid);
    }

    private static ASN1ObjectIdentifier getOID(String str) {
        char charAt = str.charAt(0);
        if (charAt < '0' || charAt > '2') {
            return null;
        }
        try {
            return new ASN1ObjectIdentifier(str);
        } catch (Exception unused) {
            return null;
        }
    }
}