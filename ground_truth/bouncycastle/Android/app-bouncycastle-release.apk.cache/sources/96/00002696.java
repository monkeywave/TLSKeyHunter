package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class ProvAlgorithmChecker extends PKIXCertPathChecker {
    static final int KU_DIGITAL_SIGNATURE = 0;
    static final int KU_KEY_AGREEMENT = 4;
    static final int KU_KEY_ENCIPHERMENT = 2;
    private final BCAlgorithmConstraints algorithmConstraints;
    private final JcaJceHelper helper;
    private final boolean isInFipsMode;
    private X509Certificate issuerCert;
    private static final Map<String, String> sigAlgNames = createSigAlgNames();
    private static final Set<String> sigAlgNoParams = createSigAlgNoParams();
    private static final byte[] DER_NULL_ENCODING = {5, 0};
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha256 = JsseUtils.getJcaSignatureAlgorithmBC("SHA256withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha384 = JsseUtils.getJcaSignatureAlgorithmBC("SHA384withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha512 = JsseUtils.getJcaSignatureAlgorithmBC("SHA512withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha256 = JsseUtils.getJcaSignatureAlgorithmBC("SHA256withRSAandMGF1", "RSA");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha384 = JsseUtils.getJcaSignatureAlgorithmBC("SHA384withRSAandMGF1", "RSA");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha512 = JsseUtils.getJcaSignatureAlgorithmBC("SHA512withRSAandMGF1", "RSA");

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvAlgorithmChecker(boolean z, JcaJceHelper jcaJceHelper, BCAlgorithmConstraints bCAlgorithmConstraints) {
        if (jcaJceHelper == null) {
            throw new NullPointerException("'helper' cannot be null");
        }
        if (bCAlgorithmConstraints == null) {
            throw new NullPointerException("'algorithmConstraints' cannot be null");
        }
        this.isInFipsMode = z;
        this.helper = jcaJceHelper;
        this.algorithmConstraints = bCAlgorithmConstraints;
        this.issuerCert = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void checkCertPathExtras(JcaJceHelper jcaJceHelper, BCAlgorithmConstraints bCAlgorithmConstraints, X509Certificate[] x509CertificateArr, KeyPurposeId keyPurposeId, int i) throws CertPathValidatorException {
        X509Certificate x509Certificate = x509CertificateArr[x509CertificateArr.length - 1];
        if (x509CertificateArr.length > 1) {
            checkIssuedBy(jcaJceHelper, bCAlgorithmConstraints, x509CertificateArr[x509CertificateArr.length - 2], x509Certificate);
        }
        checkEndEntity(jcaJceHelper, bCAlgorithmConstraints, x509CertificateArr[0], keyPurposeId, i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void checkChain(boolean z, JcaJceHelper jcaJceHelper, BCAlgorithmConstraints bCAlgorithmConstraints, Set<X509Certificate> set, X509Certificate[] x509CertificateArr, KeyPurposeId keyPurposeId, int i) throws CertPathValidatorException {
        int length = x509CertificateArr.length;
        while (length > 0 && set.contains(x509CertificateArr[length - 1])) {
            length--;
        }
        if (length < x509CertificateArr.length) {
            X509Certificate x509Certificate = x509CertificateArr[length];
            if (length > 0) {
                checkIssuedBy(jcaJceHelper, bCAlgorithmConstraints, x509CertificateArr[length - 1], x509Certificate);
            }
        } else {
            checkIssued(jcaJceHelper, bCAlgorithmConstraints, x509CertificateArr[length - 1]);
        }
        ProvAlgorithmChecker provAlgorithmChecker = new ProvAlgorithmChecker(z, jcaJceHelper, bCAlgorithmConstraints);
        provAlgorithmChecker.init(false);
        for (int i2 = length - 1; i2 >= 0; i2--) {
            provAlgorithmChecker.check(x509CertificateArr[i2], Collections.emptySet());
        }
        checkEndEntity(jcaJceHelper, bCAlgorithmConstraints, x509CertificateArr[0], keyPurposeId, i);
    }

    private static void checkEndEntity(JcaJceHelper jcaJceHelper, BCAlgorithmConstraints bCAlgorithmConstraints, X509Certificate x509Certificate, KeyPurposeId keyPurposeId, int i) throws CertPathValidatorException {
        if (keyPurposeId != null && !supportsExtendedKeyUsage(x509Certificate, keyPurposeId)) {
            throw new CertPathValidatorException("Certificate doesn't support '" + getExtendedKeyUsageName(keyPurposeId) + "' ExtendedKeyUsage");
        }
        if (i >= 0) {
            if (!supportsKeyUsage(x509Certificate, i)) {
                throw new CertPathValidatorException("Certificate doesn't support '" + getKeyUsageName(i) + "' KeyUsage");
            }
            if (!bCAlgorithmConstraints.permits(getKeyUsagePrimitives(i), x509Certificate.getPublicKey())) {
                throw new CertPathValidatorException("Public key not permitted for '" + getKeyUsageName(i) + "' KeyUsage");
            }
        }
    }

    private static void checkIssued(JcaJceHelper jcaJceHelper, BCAlgorithmConstraints bCAlgorithmConstraints, X509Certificate x509Certificate) throws CertPathValidatorException {
        String sigAlgName = getSigAlgName(x509Certificate, null);
        if (!JsseUtils.isNameSpecified(sigAlgName)) {
            throw new CertPathValidatorException("Signature algorithm could not be determined");
        }
        if (!bCAlgorithmConstraints.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName, getSigAlgParams(jcaJceHelper, x509Certificate))) {
            throw new CertPathValidatorException("Signature algorithm '" + sigAlgName + "' not permitted with given parameters");
        }
    }

    private static void checkIssuedBy(JcaJceHelper jcaJceHelper, BCAlgorithmConstraints bCAlgorithmConstraints, X509Certificate x509Certificate, X509Certificate x509Certificate2) throws CertPathValidatorException {
        String sigAlgName = getSigAlgName(x509Certificate, x509Certificate2);
        if (!JsseUtils.isNameSpecified(sigAlgName)) {
            throw new CertPathValidatorException("Signature algorithm could not be determined");
        }
        if (!bCAlgorithmConstraints.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName, x509Certificate2.getPublicKey(), getSigAlgParams(jcaJceHelper, x509Certificate))) {
            throw new CertPathValidatorException("Signature algorithm '" + sigAlgName + "' not permitted with given parameters and issuer public key");
        }
    }

    private static Map<String, String> createSigAlgNames() {
        HashMap hashMap = new HashMap(4);
        hashMap.put(EdECObjectIdentifiers.id_Ed25519.getId(), EdDSAParameterSpec.Ed25519);
        hashMap.put(EdECObjectIdentifiers.id_Ed448.getId(), EdDSAParameterSpec.Ed448);
        hashMap.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "SHA1withDSA");
        hashMap.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "SHA1withDSA");
        return Collections.unmodifiableMap(hashMap);
    }

    private static Set<String> createSigAlgNoParams() {
        HashSet hashSet = new HashSet();
        hashSet.add(OIWObjectIdentifiers.dsaWithSHA1.getId());
        hashSet.add(X9ObjectIdentifiers.id_dsa_with_sha1.getId());
        hashSet.add(PKCSObjectIdentifiers.id_RSASSA_PSS.getId());
        return Collections.unmodifiableSet(hashSet);
    }

    static String getExtendedKeyUsageName(KeyPurposeId keyPurposeId) {
        return KeyPurposeId.id_kp_clientAuth.equals(keyPurposeId) ? "clientAuth" : KeyPurposeId.id_kp_serverAuth.equals(keyPurposeId) ? "serverAuth" : "(" + keyPurposeId + ")";
    }

    static String getKeyUsageName(int i) {
        return i != 0 ? i != 2 ? i != 4 ? "(" + i + ")" : "keyAgreement" : "keyEncipherment" : "digitalSignature";
    }

    static Set<BCCryptoPrimitive> getKeyUsagePrimitives(int i) {
        return i != 2 ? i != 4 ? JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC : JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC : JsseUtils.KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC;
    }

    static String getSigAlgName(X509Certificate x509Certificate, X509Certificate x509Certificate2) {
        ASN1ObjectIdentifier algorithm;
        String sigAlgOID = x509Certificate.getSigAlgOID();
        String str = sigAlgNames.get(sigAlgOID);
        if (str != null) {
            return str;
        }
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID)) {
            RSASSAPSSparams rSASSAPSSparams = RSASSAPSSparams.getInstance(x509Certificate.getSigAlgParams());
            if (rSASSAPSSparams != null && (algorithm = rSASSAPSSparams.getHashAlgorithm().getAlgorithm()) != null) {
                if (x509Certificate2 != null) {
                    x509Certificate = x509Certificate2;
                }
                try {
                    JcaTlsCertificate jcaTlsCertificate = new JcaTlsCertificate((JcaTlsCrypto) null, x509Certificate);
                    if (NISTObjectIdentifiers.id_sha256.equals((ASN1Primitive) algorithm)) {
                        if (jcaTlsCertificate.supportsSignatureAlgorithmCA((short) 9)) {
                            return SIG_ALG_NAME_rsa_pss_pss_sha256;
                        }
                        if (jcaTlsCertificate.supportsSignatureAlgorithmCA((short) 4)) {
                            return SIG_ALG_NAME_rsa_pss_rsae_sha256;
                        }
                    } else if (NISTObjectIdentifiers.id_sha384.equals((ASN1Primitive) algorithm)) {
                        if (jcaTlsCertificate.supportsSignatureAlgorithmCA((short) 10)) {
                            return SIG_ALG_NAME_rsa_pss_pss_sha384;
                        }
                        if (jcaTlsCertificate.supportsSignatureAlgorithmCA((short) 5)) {
                            return SIG_ALG_NAME_rsa_pss_rsae_sha384;
                        }
                    } else if (NISTObjectIdentifiers.id_sha512.equals((ASN1Primitive) algorithm)) {
                        if (jcaTlsCertificate.supportsSignatureAlgorithmCA((short) 11)) {
                            return SIG_ALG_NAME_rsa_pss_pss_sha512;
                        }
                        if (jcaTlsCertificate.supportsSignatureAlgorithmCA((short) 6)) {
                            return SIG_ALG_NAME_rsa_pss_rsae_sha512;
                        }
                    }
                } catch (IOException unused) {
                }
            }
            return null;
        }
        return x509Certificate.getSigAlgName();
    }

    static AlgorithmParameters getSigAlgParams(JcaJceHelper jcaJceHelper, X509Certificate x509Certificate) throws CertPathValidatorException {
        byte[] sigAlgParams = x509Certificate.getSigAlgParams();
        if (sigAlgParams == null) {
            return null;
        }
        String sigAlgOID = x509Certificate.getSigAlgOID();
        if (sigAlgNoParams.contains(sigAlgOID) && Arrays.areEqual(DER_NULL_ENCODING, sigAlgParams)) {
            return null;
        }
        try {
            AlgorithmParameters createAlgorithmParameters = jcaJceHelper.createAlgorithmParameters(sigAlgOID);
            try {
                createAlgorithmParameters.init(sigAlgParams);
                return createAlgorithmParameters;
            } catch (Exception e) {
                throw new CertPathValidatorException(e);
            }
        } catch (GeneralSecurityException unused) {
            return null;
        }
    }

    static boolean isValidFIPSPublicKey(PublicKey publicKey) {
        try {
            AlgorithmIdentifier algorithm = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm();
            if (X9ObjectIdentifiers.id_ecPublicKey.equals((ASN1Primitive) algorithm.getAlgorithm())) {
                ASN1Encodable parameters = algorithm.getParameters();
                if (parameters != null) {
                    return parameters.toASN1Primitive() instanceof ASN1ObjectIdentifier;
                }
                return false;
            }
            return true;
        } catch (Exception unused) {
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean permitsKeyUsage(PublicKey publicKey, boolean[] zArr, int i, BCAlgorithmConstraints bCAlgorithmConstraints) {
        return supportsKeyUsage(zArr, i) && bCAlgorithmConstraints.permits(getKeyUsagePrimitives(i), publicKey);
    }

    static boolean supportsExtendedKeyUsage(X509Certificate x509Certificate, KeyPurposeId keyPurposeId) {
        try {
            return supportsExtendedKeyUsage(x509Certificate.getExtendedKeyUsage(), keyPurposeId);
        } catch (CertificateParsingException unused) {
            return false;
        }
    }

    static boolean supportsExtendedKeyUsage(List<String> list, KeyPurposeId keyPurposeId) {
        return list == null || list.contains(keyPurposeId.getId()) || list.contains(KeyPurposeId.anyExtendedKeyUsage.getId());
    }

    static boolean supportsKeyUsage(X509Certificate x509Certificate, int i) {
        return supportsKeyUsage(x509Certificate.getKeyUsage(), i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean supportsKeyUsage(boolean[] zArr, int i) {
        return zArr == null || (zArr.length > i && zArr[i]);
    }

    @Override // java.security.cert.PKIXCertPathChecker, java.security.cert.CertPathChecker
    public void check(Certificate certificate) throws CertPathValidatorException {
        check(certificate, Collections.emptySet());
    }

    @Override // java.security.cert.PKIXCertPathChecker
    public void check(Certificate certificate, Collection<String> collection) throws CertPathValidatorException {
        if (!(certificate instanceof X509Certificate)) {
            throw new CertPathValidatorException("checker can only be used for X.509 certificates");
        }
        X509Certificate x509Certificate = (X509Certificate) certificate;
        if (this.isInFipsMode && !isValidFIPSPublicKey(x509Certificate.getPublicKey())) {
            throw new CertPathValidatorException("non-FIPS public key found");
        }
        X509Certificate x509Certificate2 = this.issuerCert;
        if (x509Certificate2 != null) {
            checkIssuedBy(this.helper, this.algorithmConstraints, x509Certificate, x509Certificate2);
        }
        this.issuerCert = x509Certificate;
    }

    @Override // java.security.cert.PKIXCertPathChecker
    public Set<String> getSupportedExtensions() {
        return null;
    }

    @Override // java.security.cert.PKIXCertPathChecker, java.security.cert.CertPathChecker
    public void init(boolean z) throws CertPathValidatorException {
        if (z) {
            throw new CertPathValidatorException("forward checking not supported");
        }
        this.issuerCert = null;
    }

    @Override // java.security.cert.PKIXCertPathChecker, java.security.cert.CertPathChecker
    public boolean isForwardCheckingSupported() {
        return false;
    }
}