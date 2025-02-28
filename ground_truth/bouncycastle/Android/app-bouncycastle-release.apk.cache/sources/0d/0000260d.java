package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.internal.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvOcspRevocationChecker implements PKIXCertRevocationChecker {
    private static final int DEFAULT_OCSP_MAX_RESPONSE_SIZE = 32768;
    private static final int DEFAULT_OCSP_TIMEOUT = 15000;
    private static final Map oids;
    private final JcaJceHelper helper;
    private boolean isEnabledOCSP;
    private String ocspURL;
    private PKIXCertRevocationCheckerParameters parameters;
    private final ProvRevocationChecker parent;

    static {
        HashMap hashMap = new HashMap();
        oids = hashMap;
        hashMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
        hashMap.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        hashMap.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        hashMap.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        hashMap.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        hashMap.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        hashMap.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        hashMap.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
        hashMap.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
        hashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        hashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        hashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        hashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        hashMap.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        hashMap.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        hashMap.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        hashMap.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        hashMap.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        hashMap.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        hashMap.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        hashMap.put(IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
        hashMap.put(IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");
        hashMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
        hashMap.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
        hashMap.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
        hashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        hashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        hashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        hashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        hashMap.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        hashMap.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        hashMap.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        hashMap.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        hashMap.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
    }

    public ProvOcspRevocationChecker(ProvRevocationChecker provRevocationChecker, JcaJceHelper jcaJceHelper) {
        this.parent = provRevocationChecker;
        this.helper = jcaJceHelper;
    }

    private static byte[] calcKeyHash(MessageDigest messageDigest, PublicKey publicKey) {
        return messageDigest.digest(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getBytes());
    }

    private CertID createCertID(CertID certID, Certificate certificate, ASN1Integer aSN1Integer) throws CertPathValidatorException {
        return createCertID(certID.getHashAlgorithm(), certificate, aSN1Integer);
    }

    private CertID createCertID(AlgorithmIdentifier algorithmIdentifier, Certificate certificate, ASN1Integer aSN1Integer) throws CertPathValidatorException {
        try {
            MessageDigest createMessageDigest = this.helper.createMessageDigest(MessageDigestUtils.getDigestName(algorithmIdentifier.getAlgorithm()));
            return new CertID(algorithmIdentifier, new DEROctetString(createMessageDigest.digest(certificate.getSubject().getEncoded(ASN1Encoding.DER))), new DEROctetString(createMessageDigest.digest(certificate.getSubjectPublicKeyInfo().getPublicKeyData().getBytes())), aSN1Integer);
        } catch (Exception e) {
            throw new CertPathValidatorException("problem creating ID: " + e, e);
        }
    }

    private Certificate extractCert() throws CertPathValidatorException {
        try {
            return Certificate.getInstance(this.parameters.getSigningCert().getEncoded());
        } catch (Exception e) {
            throw new CertPathValidatorException("cannot process signing cert: " + e.getMessage(), e, this.parameters.getCertPath(), this.parameters.getIndex());
        }
    }

    private static String getDigestName(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        String digestName = MessageDigestUtils.getDigestName(aSN1ObjectIdentifier);
        int indexOf = digestName.indexOf(45);
        return (indexOf <= 0 || digestName.startsWith("SHA3")) ? digestName : digestName.substring(0, indexOf) + digestName.substring(indexOf + 1);
    }

    static URI getOcspResponderURI(X509Certificate x509Certificate) {
        byte[] extensionValue = x509Certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extensionValue == null) {
            return null;
        }
        AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(extensionValue).getOctets()).getAccessDescriptions();
        for (int i = 0; i != accessDescriptions.length; i++) {
            AccessDescription accessDescription = accessDescriptions[i];
            if (AccessDescription.id_ad_ocsp.equals((ASN1Primitive) accessDescription.getAccessMethod())) {
                GeneralName accessLocation = accessDescription.getAccessLocation();
                if (accessLocation.getTagNo() == 6) {
                    try {
                        return new URI(((ASN1String) accessLocation.getName()).getString());
                    } catch (URISyntaxException unused) {
                        continue;
                    }
                } else {
                    continue;
                }
            }
        }
        return null;
    }

    private static String getSignatureName(AlgorithmIdentifier algorithmIdentifier) {
        ASN1Encodable parameters = algorithmIdentifier.getParameters();
        if (parameters != null && !DERNull.INSTANCE.equals(parameters) && algorithmIdentifier.getAlgorithm().equals((ASN1Primitive) PKCSObjectIdentifiers.id_RSASSA_PSS)) {
            return getDigestName(RSASSAPSSparams.getInstance(parameters).getHashAlgorithm().getAlgorithm()) + "WITHRSAANDMGF1";
        }
        Map map = oids;
        boolean containsKey = map.containsKey(algorithmIdentifier.getAlgorithm());
        ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        return containsKey ? (String) map.get(algorithm) : algorithm.getId();
    }

    private static X509Certificate getSignerCert(BasicOCSPResponse basicOCSPResponse, X509Certificate x509Certificate, X509Certificate x509Certificate2, JcaJceHelper jcaJceHelper) throws NoSuchProviderException, NoSuchAlgorithmException {
        ResponderID responderID = basicOCSPResponse.getTbsResponseData().getResponderID();
        byte[] keyHash = responderID.getKeyHash();
        if (keyHash != null) {
            MessageDigest createMessageDigest = jcaJceHelper.createMessageDigest("SHA1");
            if (x509Certificate2 == null || !Arrays.areEqual(keyHash, calcKeyHash(createMessageDigest, x509Certificate2.getPublicKey()))) {
                if (x509Certificate == null || !Arrays.areEqual(keyHash, calcKeyHash(createMessageDigest, x509Certificate.getPublicKey()))) {
                    return null;
                }
                return x509Certificate;
            }
            return x509Certificate2;
        }
        X500Name x500Name = X500Name.getInstance(BCStrictStyle.INSTANCE, responderID.getName());
        if (x509Certificate2 == null || !x500Name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, x509Certificate2.getSubjectX500Principal().getEncoded()))) {
            if (x509Certificate == null || !x500Name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, x509Certificate.getSubjectX500Principal().getEncoded()))) {
                return null;
            }
            return x509Certificate;
        }
        return x509Certificate2;
    }

    private static boolean isEqualAlgId(AlgorithmIdentifier algorithmIdentifier, AlgorithmIdentifier algorithmIdentifier2) {
        if (algorithmIdentifier == algorithmIdentifier2 || algorithmIdentifier.equals(algorithmIdentifier2)) {
            return true;
        }
        if (algorithmIdentifier.getAlgorithm().equals((ASN1Primitive) algorithmIdentifier2.getAlgorithm())) {
            ASN1Encodable parameters = algorithmIdentifier.getParameters();
            ASN1Encodable parameters2 = algorithmIdentifier2.getParameters();
            if (parameters == parameters2) {
                return true;
            }
            if (parameters == null) {
                return DERNull.INSTANCE.equals(parameters2);
            }
            if (DERNull.INSTANCE.equals(parameters) && parameters2 == null) {
                return true;
            }
            return parameters.equals(parameters2);
        }
        return false;
    }

    private static boolean responderMatches(ResponderID responderID, X509Certificate x509Certificate, JcaJceHelper jcaJceHelper) throws NoSuchProviderException, NoSuchAlgorithmException {
        byte[] keyHash = responderID.getKeyHash();
        return keyHash != null ? Arrays.areEqual(keyHash, calcKeyHash(jcaJceHelper.createMessageDigest("SHA1"), x509Certificate.getPublicKey())) : X500Name.getInstance(BCStrictStyle.INSTANCE, responderID.getName()).equals(X500Name.getInstance(BCStrictStyle.INSTANCE, x509Certificate.getSubjectX500Principal().getEncoded()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean validatedOcspResponse(BasicOCSPResponse basicOCSPResponse, PKIXCertRevocationCheckerParameters pKIXCertRevocationCheckerParameters, byte[] bArr, X509Certificate x509Certificate, JcaJceHelper jcaJceHelper) throws CertPathValidatorException {
        try {
            ASN1Sequence certs = basicOCSPResponse.getCerts();
            Signature createSignature = jcaJceHelper.createSignature(getSignatureName(basicOCSPResponse.getSignatureAlgorithm()));
            X509Certificate signerCert = getSignerCert(basicOCSPResponse, pKIXCertRevocationCheckerParameters.getSigningCert(), x509Certificate, jcaJceHelper);
            if (signerCert == null && certs == null) {
                throw new CertPathValidatorException("OCSP responder certificate not found");
            }
            if (signerCert != null) {
                createSignature.initVerify(signerCert.getPublicKey());
            } else {
                X509Certificate x509Certificate2 = (X509Certificate) jcaJceHelper.createCertificateFactory("X.509").generateCertificate(new ByteArrayInputStream(certs.getObjectAt(0).toASN1Primitive().getEncoded()));
                x509Certificate2.verify(pKIXCertRevocationCheckerParameters.getSigningCert().getPublicKey());
                x509Certificate2.checkValidity(pKIXCertRevocationCheckerParameters.getValidDate());
                if (!responderMatches(basicOCSPResponse.getTbsResponseData().getResponderID(), x509Certificate2, jcaJceHelper)) {
                    throw new CertPathValidatorException("responder certificate does not match responderID", null, pKIXCertRevocationCheckerParameters.getCertPath(), pKIXCertRevocationCheckerParameters.getIndex());
                }
                List<String> extendedKeyUsage = x509Certificate2.getExtendedKeyUsage();
                if (extendedKeyUsage == null || !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
                    throw new CertPathValidatorException("responder certificate not valid for signing OCSP responses", null, pKIXCertRevocationCheckerParameters.getCertPath(), pKIXCertRevocationCheckerParameters.getIndex());
                }
                createSignature.initVerify(x509Certificate2);
            }
            createSignature.update(basicOCSPResponse.getTbsResponseData().getEncoded(ASN1Encoding.DER));
            if (createSignature.verify(basicOCSPResponse.getSignature().getOctets())) {
                if (bArr != null && !Arrays.areEqual(bArr, basicOCSPResponse.getTbsResponseData().getResponseExtensions().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getOctets())) {
                    throw new CertPathValidatorException("nonce mismatch in OCSP response", null, pKIXCertRevocationCheckerParameters.getCertPath(), pKIXCertRevocationCheckerParameters.getIndex());
                }
                return true;
            }
            return false;
        } catch (IOException e) {
            throw new CertPathValidatorException("OCSP response failure: " + e.getMessage(), e, pKIXCertRevocationCheckerParameters.getCertPath(), pKIXCertRevocationCheckerParameters.getIndex());
        } catch (CertPathValidatorException e2) {
            throw e2;
        } catch (GeneralSecurityException e3) {
            throw new CertPathValidatorException("OCSP response failure: " + e3.getMessage(), e3, pKIXCertRevocationCheckerParameters.getCertPath(), pKIXCertRevocationCheckerParameters.getIndex());
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:64:0x019e, code lost:
        if (isEqualAlgId(r0.getHashAlgorithm(), r1.getCertID().getHashAlgorithm()) != false) goto L59;
     */
    @Override // org.bouncycastle.jcajce.PKIXCertRevocationChecker
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void check(java.security.cert.Certificate r12) throws java.security.cert.CertPathValidatorException {
        /*
            Method dump skipped, instructions count: 659
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jce.provider.ProvOcspRevocationChecker.check(java.security.cert.Certificate):void");
    }

    public List<CertPathValidatorException> getSoftFailExceptions() {
        return null;
    }

    public Set<String> getSupportedExtensions() {
        return null;
    }

    public void init(boolean z) throws CertPathValidatorException {
        if (z) {
            throw new CertPathValidatorException("forward checking not supported");
        }
        this.parameters = null;
        this.isEnabledOCSP = Properties.isOverrideSet("ocsp.enable");
        this.ocspURL = Properties.getPropertyValue("ocsp.responderURL");
    }

    @Override // org.bouncycastle.jcajce.PKIXCertRevocationChecker
    public void initialize(PKIXCertRevocationCheckerParameters pKIXCertRevocationCheckerParameters) {
        this.parameters = pKIXCertRevocationCheckerParameters;
        this.isEnabledOCSP = Properties.isOverrideSet("ocsp.enable");
        this.ocspURL = Properties.getPropertyValue("ocsp.responderURL");
    }

    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override // org.bouncycastle.jcajce.PKIXCertRevocationChecker
    public void setParameter(String str, Object obj) {
    }
}