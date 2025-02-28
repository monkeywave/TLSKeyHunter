package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.p009x9.ECNamedCurveTable;
import org.bouncycastle.asn1.p009x9.X962Parameters;
import org.bouncycastle.asn1.p009x9.X9ECParameters;
import org.bouncycastle.asn1.p009x9.X9ECParametersHolder;
import org.bouncycastle.crypto.p010ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.Polynomial;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.math.p016ec.ECAlgorithms;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class EC5Util {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static class CustomCurves {
        private static Map CURVE_MAP = createCurveMap();

        private CustomCurves() {
        }

        private static Map createCurveMap() {
            HashMap hashMap = new HashMap();
            Enumeration names = CustomNamedCurves.getNames();
            while (names.hasMoreElements()) {
                String str = (String) names.nextElement();
                X9ECParametersHolder byNameLazy = ECNamedCurveTable.getByNameLazy(str);
                if (byNameLazy != null) {
                    ECCurve curve = byNameLazy.getCurve();
                    if (ECAlgorithms.isFpCurve(curve)) {
                        hashMap.put(curve, CustomNamedCurves.getByNameLazy(str).getCurve());
                    }
                }
            }
            ECCurve curve2 = CustomNamedCurves.getByNameLazy("Curve25519").getCurve();
            hashMap.put(new ECCurve.C1333Fp(curve2.getField().getCharacteristic(), curve2.getA().toBigInteger(), curve2.getB().toBigInteger(), curve2.getOrder(), curve2.getCofactor(), true), curve2);
            return hashMap;
        }

        static ECCurve substitute(ECCurve eCCurve) {
            ECCurve eCCurve2 = (ECCurve) CURVE_MAP.get(eCCurve);
            return eCCurve2 != null ? eCCurve2 : eCCurve;
        }
    }

    public static EllipticCurve convertCurve(ECCurve eCCurve, byte[] bArr) {
        return new EllipticCurve(convertField(eCCurve.getField()), eCCurve.getA().toBigInteger(), eCCurve.getB().toBigInteger(), null);
    }

    public static ECCurve convertCurve(EllipticCurve ellipticCurve) {
        ECField field = ellipticCurve.getField();
        BigInteger a = ellipticCurve.getA();
        BigInteger b = ellipticCurve.getB();
        if (field instanceof ECFieldFp) {
            return CustomCurves.substitute(new ECCurve.C1333Fp(((ECFieldFp) field).getP(), a, b, null, null));
        }
        ECFieldF2m eCFieldF2m = (ECFieldF2m) field;
        int m = eCFieldF2m.getM();
        int[] convertMidTerms = ECUtil.convertMidTerms(eCFieldF2m.getMidTermsOfReductionPolynomial());
        return new ECCurve.F2m(m, convertMidTerms[0], convertMidTerms[1], convertMidTerms[2], a, b, (BigInteger) null, (BigInteger) null);
    }

    public static ECField convertField(FiniteField finiteField) {
        if (ECAlgorithms.isFpField(finiteField)) {
            return new ECFieldFp(finiteField.getCharacteristic());
        }
        Polynomial minimalPolynomial = ((PolynomialExtensionField) finiteField).getMinimalPolynomial();
        int[] exponentsPresent = minimalPolynomial.getExponentsPresent();
        return new ECFieldF2m(minimalPolynomial.getDegree(), Arrays.reverseInPlace(Arrays.copyOfRange(exponentsPresent, 1, exponentsPresent.length - 1)));
    }

    public static ECPoint convertPoint(org.bouncycastle.math.p016ec.ECPoint eCPoint) {
        org.bouncycastle.math.p016ec.ECPoint normalize = eCPoint.normalize();
        return new ECPoint(normalize.getAffineXCoord().toBigInteger(), normalize.getAffineYCoord().toBigInteger());
    }

    public static org.bouncycastle.math.p016ec.ECPoint convertPoint(ECParameterSpec eCParameterSpec, ECPoint eCPoint) {
        return convertPoint(convertCurve(eCParameterSpec.getCurve()), eCPoint);
    }

    public static org.bouncycastle.math.p016ec.ECPoint convertPoint(ECCurve eCCurve, ECPoint eCPoint) {
        return eCCurve.createPoint(eCPoint.getAffineX(), eCPoint.getAffineY());
    }

    public static ECParameterSpec convertSpec(EllipticCurve ellipticCurve, org.bouncycastle.jce.spec.ECParameterSpec eCParameterSpec) {
        ECPoint convertPoint = convertPoint(eCParameterSpec.getG());
        return eCParameterSpec instanceof ECNamedCurveParameterSpec ? new ECNamedCurveSpec(((ECNamedCurveParameterSpec) eCParameterSpec).getName(), ellipticCurve, convertPoint, eCParameterSpec.getN(), eCParameterSpec.getH()) : new ECParameterSpec(ellipticCurve, convertPoint, eCParameterSpec.getN(), eCParameterSpec.getH().intValue());
    }

    public static org.bouncycastle.jce.spec.ECParameterSpec convertSpec(ECParameterSpec eCParameterSpec) {
        ECCurve convertCurve = convertCurve(eCParameterSpec.getCurve());
        org.bouncycastle.math.p016ec.ECPoint convertPoint = convertPoint(convertCurve, eCParameterSpec.getGenerator());
        BigInteger order = eCParameterSpec.getOrder();
        BigInteger valueOf = BigInteger.valueOf(eCParameterSpec.getCofactor());
        byte[] seed = eCParameterSpec.getCurve().getSeed();
        return eCParameterSpec instanceof ECNamedCurveSpec ? new ECNamedCurveParameterSpec(((ECNamedCurveSpec) eCParameterSpec).getName(), convertCurve, convertPoint, order, valueOf, seed) : new org.bouncycastle.jce.spec.ECParameterSpec(convertCurve, convertPoint, order, valueOf, seed);
    }

    public static ECParameterSpec convertToSpec(X962Parameters x962Parameters, ECCurve eCCurve) {
        ECParameterSpec eCNamedCurveSpec;
        if (x962Parameters.isNamedCurve()) {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) x962Parameters.getParameters();
            X9ECParameters namedCurveByOid = ECUtil.getNamedCurveByOid(aSN1ObjectIdentifier);
            if (namedCurveByOid == null) {
                Map additionalECParameters = BouncyCastleProvider.CONFIGURATION.getAdditionalECParameters();
                if (!additionalECParameters.isEmpty()) {
                    namedCurveByOid = (X9ECParameters) additionalECParameters.get(aSN1ObjectIdentifier);
                }
            }
            return new ECNamedCurveSpec(ECUtil.getCurveName(aSN1ObjectIdentifier), convertCurve(eCCurve, namedCurveByOid.getSeed()), convertPoint(namedCurveByOid.getG()), namedCurveByOid.getN(), namedCurveByOid.getH());
        } else if (x962Parameters.isImplicitlyCA()) {
            return null;
        } else {
            ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(x962Parameters.getParameters());
            if (aSN1Sequence.size() > 3) {
                X9ECParameters x9ECParameters = X9ECParameters.getInstance(aSN1Sequence);
                EllipticCurve convertCurve = convertCurve(eCCurve, x9ECParameters.getSeed());
                eCNamedCurveSpec = x9ECParameters.getH() != null ? new ECParameterSpec(convertCurve, convertPoint(x9ECParameters.getG()), x9ECParameters.getN(), x9ECParameters.getH().intValue()) : new ECParameterSpec(convertCurve, convertPoint(x9ECParameters.getG()), x9ECParameters.getN(), 1);
            } else {
                GOST3410PublicKeyAlgParameters gOST3410PublicKeyAlgParameters = GOST3410PublicKeyAlgParameters.getInstance(aSN1Sequence);
                ECNamedCurveParameterSpec parameterSpec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(gOST3410PublicKeyAlgParameters.getPublicKeyParamSet()));
                eCNamedCurveSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(gOST3410PublicKeyAlgParameters.getPublicKeyParamSet()), convertCurve(parameterSpec.getCurve(), parameterSpec.getSeed()), convertPoint(parameterSpec.getG()), parameterSpec.getN(), parameterSpec.getH());
            }
            return eCNamedCurveSpec;
        }
    }

    public static ECParameterSpec convertToSpec(X9ECParameters x9ECParameters) {
        return new ECParameterSpec(convertCurve(x9ECParameters.getCurve(), null), convertPoint(x9ECParameters.getG()), x9ECParameters.getN(), x9ECParameters.getH().intValue());
    }

    public static ECParameterSpec convertToSpec(ECDomainParameters eCDomainParameters) {
        return new ECParameterSpec(convertCurve(eCDomainParameters.getCurve(), null), convertPoint(eCDomainParameters.getG()), eCDomainParameters.getN(), eCDomainParameters.getH().intValue());
    }

    public static ECCurve getCurve(ProviderConfiguration providerConfiguration, X962Parameters x962Parameters) {
        Set acceptableNamedCurves = providerConfiguration.getAcceptableNamedCurves();
        if (!x962Parameters.isNamedCurve()) {
            if (x962Parameters.isImplicitlyCA()) {
                return providerConfiguration.getEcImplicitlyCa().getCurve();
            }
            ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(x962Parameters.getParameters());
            if (acceptableNamedCurves.isEmpty()) {
                return (aSN1Sequence.size() > 3 ? X9ECParameters.getInstance(aSN1Sequence) : ECGOST3410NamedCurves.getByOIDX9(ASN1ObjectIdentifier.getInstance(aSN1Sequence.getObjectAt(0)))).getCurve();
            }
            throw new IllegalStateException("encoded parameters not acceptable");
        }
        ASN1ObjectIdentifier aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(x962Parameters.getParameters());
        if (acceptableNamedCurves.isEmpty() || acceptableNamedCurves.contains(aSN1ObjectIdentifier)) {
            X9ECParameters namedCurveByOid = ECUtil.getNamedCurveByOid(aSN1ObjectIdentifier);
            if (namedCurveByOid == null) {
                namedCurveByOid = (X9ECParameters) providerConfiguration.getAdditionalECParameters().get(aSN1ObjectIdentifier);
            }
            return namedCurveByOid.getCurve();
        }
        throw new IllegalStateException("named curve not acceptable");
    }

    public static ECDomainParameters getDomainParameters(ProviderConfiguration providerConfiguration, ECParameterSpec eCParameterSpec) {
        if (eCParameterSpec == null) {
            org.bouncycastle.jce.spec.ECParameterSpec ecImplicitlyCa = providerConfiguration.getEcImplicitlyCa();
            return new ECDomainParameters(ecImplicitlyCa.getCurve(), ecImplicitlyCa.getG(), ecImplicitlyCa.getN(), ecImplicitlyCa.getH(), ecImplicitlyCa.getSeed());
        }
        return ECUtil.getDomainParameters(providerConfiguration, convertSpec(eCParameterSpec));
    }
}