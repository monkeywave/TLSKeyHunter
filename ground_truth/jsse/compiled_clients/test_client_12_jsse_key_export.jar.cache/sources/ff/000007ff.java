package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Fingerprint;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/rsa/RSAUtil.class */
public class RSAUtil {
    public static final ASN1ObjectIdentifier[] rsaOids = {PKCSObjectIdentifiers.rsaEncryption, X509ObjectIdentifiers.id_ea_rsa, PKCSObjectIdentifiers.id_RSAES_OAEP, PKCSObjectIdentifiers.id_RSASSA_PSS};

    public static boolean isRsaOid(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        for (int i = 0; i != rsaOids.length; i++) {
            if (aSN1ObjectIdentifier.equals((ASN1Primitive) rsaOids[i])) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RSAKeyParameters generatePublicKeyParameter(RSAPublicKey rSAPublicKey) {
        return rSAPublicKey instanceof BCRSAPublicKey ? ((BCRSAPublicKey) rSAPublicKey).engineGetKeyParameters() : new RSAKeyParameters(false, rSAPublicKey.getModulus(), rSAPublicKey.getPublicExponent());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RSAKeyParameters generatePrivateKeyParameter(RSAPrivateKey rSAPrivateKey) {
        if (rSAPrivateKey instanceof BCRSAPrivateKey) {
            return ((BCRSAPrivateKey) rSAPrivateKey).engineGetKeyParameters();
        }
        if (rSAPrivateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rSAPrivateCrtKey = (RSAPrivateCrtKey) rSAPrivateKey;
            return new RSAPrivateCrtKeyParameters(rSAPrivateCrtKey.getModulus(), rSAPrivateCrtKey.getPublicExponent(), rSAPrivateCrtKey.getPrivateExponent(), rSAPrivateCrtKey.getPrimeP(), rSAPrivateCrtKey.getPrimeQ(), rSAPrivateCrtKey.getPrimeExponentP(), rSAPrivateCrtKey.getPrimeExponentQ(), rSAPrivateCrtKey.getCrtCoefficient());
        }
        return new RSAKeyParameters(true, rSAPrivateKey.getModulus(), rSAPrivateKey.getPrivateExponent());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String generateKeyFingerprint(BigInteger bigInteger) {
        return new Fingerprint(bigInteger.toByteArray()).toString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String generateExponentFingerprint(BigInteger bigInteger) {
        return new Fingerprint(bigInteger.toByteArray(), 32).toString();
    }
}