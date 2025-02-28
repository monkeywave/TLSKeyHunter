package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.p003x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/x509/X509SignatureUtil.class */
class X509SignatureUtil {
    private static final Map<ASN1ObjectIdentifier, String> algNames = new HashMap();
    private static final ASN1Null derNull;

    X509SignatureUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isCompositeAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
        return MiscObjectIdentifiers.id_alg_composite.equals((ASN1Primitive) algorithmIdentifier.getAlgorithm());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void setSignatureParameters(Signature signature, ASN1Encodable aSN1Encodable) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (aSN1Encodable == null || derNull.equals(aSN1Encodable)) {
            return;
        }
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(signature.getAlgorithm(), signature.getProvider());
        try {
            algorithmParameters.init(aSN1Encodable.toASN1Primitive().getEncoded());
            if (signature.getAlgorithm().endsWith("MGF1")) {
                try {
                    signature.setParameter(algorithmParameters.getParameterSpec(PSSParameterSpec.class));
                } catch (GeneralSecurityException e) {
                    throw new SignatureException("Exception extracting parameters: " + e.getMessage());
                }
            }
        } catch (IOException e2) {
            throw new SignatureException("IOException decoding parameters: " + e2.getMessage());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getSignatureName(AlgorithmIdentifier algorithmIdentifier) {
        ASN1Encodable parameters = algorithmIdentifier.getParameters();
        if (parameters != null && !derNull.equals(parameters)) {
            if (algorithmIdentifier.getAlgorithm().equals((ASN1Primitive) PKCSObjectIdentifiers.id_RSASSA_PSS)) {
                return getDigestAlgName(RSASSAPSSparams.getInstance(parameters).getHashAlgorithm().getAlgorithm()) + "withRSAandMGF1";
            } else if (algorithmIdentifier.getAlgorithm().equals((ASN1Primitive) X9ObjectIdentifiers.ecdsa_with_SHA2)) {
                return getDigestAlgName((ASN1ObjectIdentifier) ASN1Sequence.getInstance(parameters).getObjectAt(0)) + "withECDSA";
            }
        }
        String str = algNames.get(algorithmIdentifier.getAlgorithm());
        return str != null ? str : findAlgName(algorithmIdentifier.getAlgorithm());
    }

    private static String getDigestAlgName(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        String digestName = MessageDigestUtils.getDigestName(aSN1ObjectIdentifier);
        int indexOf = digestName.indexOf(45);
        return (indexOf <= 0 || digestName.startsWith("SHA3")) ? digestName : digestName.substring(0, indexOf) + digestName.substring(indexOf + 1);
    }

    private static String findAlgName(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        String lookupAlg;
        String lookupAlg2;
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null || (lookupAlg2 = lookupAlg(provider, aSN1ObjectIdentifier)) == null) {
            Provider[] providers = Security.getProviders();
            for (int i = 0; i != providers.length; i++) {
                if (provider != providers[i] && (lookupAlg = lookupAlg(providers[i], aSN1ObjectIdentifier)) != null) {
                    return lookupAlg;
                }
            }
            return aSN1ObjectIdentifier.getId();
        }
        return lookupAlg2;
    }

    private static String lookupAlg(Provider provider, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        String property = provider.getProperty("Alg.Alias.Signature." + aSN1ObjectIdentifier);
        if (property != null) {
            return property;
        }
        String property2 = provider.getProperty("Alg.Alias.Signature.OID." + aSN1ObjectIdentifier);
        if (property2 != null) {
            return property2;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void prettyPrintSignature(byte[] bArr, StringBuffer stringBuffer, String str) {
        if (bArr.length <= 20) {
            stringBuffer.append("            Signature: ").append(Hex.toHexString(bArr)).append(str);
            return;
        }
        stringBuffer.append("            Signature: ").append(Hex.toHexString(bArr, 0, 20)).append(str);
        for (int i = 20; i < bArr.length; i += 20) {
            if (i < bArr.length - 20) {
                stringBuffer.append("                       ").append(Hex.toHexString(bArr, i, 20)).append(str);
            } else {
                stringBuffer.append("                       ").append(Hex.toHexString(bArr, i, bArr.length - i)).append(str);
            }
        }
    }

    static {
        algNames.put(EdECObjectIdentifiers.id_Ed25519, EdDSAParameterSpec.Ed25519);
        algNames.put(EdECObjectIdentifiers.id_Ed448, EdDSAParameterSpec.Ed448);
        algNames.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1withDSA");
        algNames.put(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1withDSA");
        derNull = DERNull.INSTANCE;
    }
}