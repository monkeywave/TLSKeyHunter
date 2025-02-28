package org.openjsse.sun.security.validator;

import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.Timestamp;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import sun.security.action.GetBooleanAction;
import sun.security.action.GetPropertyAction;
import sun.security.provider.certpath.AlgorithmChecker;
import sun.security.provider.certpath.PKIXExtendedParameters;
import sun.security.validator.ValidatorException;
import sun.security.x509.X509CertImpl;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/validator/PKIXValidator.class */
public final class PKIXValidator extends Validator {
    private static final boolean checkTLSRevocation = ((Boolean) AccessController.doPrivileged((PrivilegedAction<Object>) new GetBooleanAction("com.sun.net.ssl.checkRevocation"))).booleanValue();
    private static final boolean ALLOW_NON_CA_ANCHOR = allowNonCaAnchor();
    private final Set<X509Certificate> trustedCerts;
    private final PKIXBuilderParameters parameterTemplate;
    private int certPathLength;
    private final Map<X500Principal, List<PublicKey>> trustedSubjects;
    private final CertificateFactory factory;
    private final boolean plugin;

    private static boolean allowNonCaAnchor() {
        String prop = GetPropertyAction.privilegedGetProperty("jdk.security.allowNonCaAnchor");
        return prop != null && (prop.isEmpty() || prop.equalsIgnoreCase("true"));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PKIXValidator(String variant, Collection<X509Certificate> trustedCerts) {
        super(Validator.TYPE_PKIX, variant);
        this.certPathLength = -1;
        this.trustedCerts = trustedCerts instanceof Set ? (Set) trustedCerts : new HashSet<>(trustedCerts);
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate cert : trustedCerts) {
            trustAnchors.add(new TrustAnchor(cert, null));
        }
        try {
            this.parameterTemplate = new PKIXBuilderParameters(trustAnchors, (CertSelector) null);
            this.factory = CertificateFactory.getInstance("X.509");
            setDefaultParameters(variant);
            this.plugin = variant.equals(Validator.VAR_PLUGIN_CODE_SIGNING);
            this.trustedSubjects = setTrustedSubjects();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Unexpected error: " + e.toString(), e);
        } catch (CertificateException e2) {
            throw new RuntimeException("Internal error", e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PKIXValidator(String variant, PKIXBuilderParameters params) {
        super(Validator.TYPE_PKIX, variant);
        this.certPathLength = -1;
        this.trustedCerts = new HashSet();
        for (TrustAnchor anchor : params.getTrustAnchors()) {
            X509Certificate cert = anchor.getTrustedCert();
            if (cert != null) {
                this.trustedCerts.add(cert);
            }
        }
        this.parameterTemplate = params;
        try {
            this.factory = CertificateFactory.getInstance("X.509");
            this.plugin = variant.equals(Validator.VAR_PLUGIN_CODE_SIGNING);
            this.trustedSubjects = setTrustedSubjects();
        } catch (CertificateException e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    private Map<X500Principal, List<PublicKey>> setTrustedSubjects() {
        List<PublicKey> keys;
        Map<X500Principal, List<PublicKey>> subjectMap = new HashMap<>();
        for (X509Certificate cert : this.trustedCerts) {
            X500Principal dn = cert.getSubjectX500Principal();
            if (subjectMap.containsKey(dn)) {
                keys = subjectMap.get(dn);
            } else {
                keys = new ArrayList<>();
                subjectMap.put(dn, keys);
            }
            keys.add(cert.getPublicKey());
        }
        return subjectMap;
    }

    @Override // org.openjsse.sun.security.validator.Validator
    public Collection<X509Certificate> getTrustedCertificates() {
        return this.trustedCerts;
    }

    public int getCertPathLength() {
        return this.certPathLength;
    }

    private void setDefaultParameters(String variant) {
        if (variant == Validator.VAR_TLS_SERVER || variant == Validator.VAR_TLS_CLIENT) {
            this.parameterTemplate.setRevocationEnabled(checkTLSRevocation);
        } else {
            this.parameterTemplate.setRevocationEnabled(false);
        }
    }

    public PKIXBuilderParameters getParameters() {
        return this.parameterTemplate;
    }

    @Override // org.openjsse.sun.security.validator.Validator
    X509Certificate[] engineValidate(X509Certificate[] chain, Collection<X509Certificate> otherCerts, List<byte[]> responseList, AlgorithmConstraints constraints, Object parameter) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("null or zero-length certificate chain");
        }
        PKIXBuilderParameters pkixParameters = null;
        try {
            pkixParameters = new PKIXExtendedParameters((PKIXBuilderParameters) this.parameterTemplate.clone(), parameter instanceof Timestamp ? (Timestamp) parameter : null, this.variant);
        } catch (InvalidAlgorithmParameterException e) {
        }
        if (constraints != null) {
            pkixParameters.addCertPathChecker(new AlgorithmChecker(constraints, this.variant));
        }
        if (!responseList.isEmpty()) {
            addResponses(pkixParameters, chain, responseList);
        }
        X500Principal prevIssuer = null;
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            X500Principal dn = cert.getSubjectX500Principal();
            if (i != 0 && !dn.equals(prevIssuer)) {
                return doBuild(chain, otherCerts, pkixParameters);
            }
            if (this.trustedCerts.contains(cert) || (this.trustedSubjects.containsKey(dn) && this.trustedSubjects.get(dn).contains(cert.getPublicKey()))) {
                if (i == 0) {
                    return new X509Certificate[]{chain[0]};
                }
                X509Certificate[] newChain = new X509Certificate[i];
                System.arraycopy(chain, 0, newChain, 0, i);
                return doValidate(newChain, pkixParameters);
            }
            prevIssuer = cert.getIssuerX500Principal();
        }
        X509Certificate last = chain[chain.length - 1];
        X500Principal issuer = last.getIssuerX500Principal();
        last.getSubjectX500Principal();
        if (this.trustedSubjects.containsKey(issuer) && isSignatureValid(this.trustedSubjects.get(issuer), last)) {
            return doValidate(chain, pkixParameters);
        }
        if (this.plugin) {
            if (chain.length > 1) {
                X509Certificate[] newChain2 = new X509Certificate[chain.length - 1];
                System.arraycopy(chain, 0, newChain2, 0, newChain2.length);
                try {
                    pkixParameters.setTrustAnchors(Collections.singleton(new TrustAnchor(chain[chain.length - 1], null)));
                    doValidate(newChain2, pkixParameters);
                } catch (InvalidAlgorithmParameterException iape) {
                    throw new CertificateException(iape);
                }
            }
            throw new ValidatorException(ValidatorException.T_NO_TRUST_ANCHOR);
        }
        return doBuild(chain, otherCerts, pkixParameters);
    }

    private boolean isSignatureValid(List<PublicKey> keys, X509Certificate sub) {
        if (this.plugin) {
            for (PublicKey key : keys) {
                try {
                    sub.verify(key);
                    return true;
                } catch (Exception e) {
                }
            }
            return false;
        }
        return true;
    }

    private static X509Certificate[] toArray(CertPath path, TrustAnchor anchor) throws CertificateException {
        X509Certificate trustedCert = anchor.getTrustedCert();
        if (trustedCert == null) {
            throw new ValidatorException("TrustAnchor must be specified as certificate");
        }
        verifyTrustAnchor(trustedCert);
        List<? extends Certificate> list = path.getCertificates();
        X509Certificate[] chain = new X509Certificate[list.size() + 1];
        list.toArray(chain);
        chain[chain.length - 1] = trustedCert;
        return chain;
    }

    private void setDate(PKIXBuilderParameters params) {
        Date date = this.validationDate;
        if (date != null) {
            params.setDate(date);
        }
    }

    private X509Certificate[] doValidate(X509Certificate[] chain, PKIXBuilderParameters params) throws CertificateException {
        try {
            setDate(params);
            CertPathValidator validator = CertPathValidator.getInstance(Validator.TYPE_PKIX);
            X509Certificate[] newChain = new X509Certificate[chain.length];
            for (int i = 0; i < chain.length; i++) {
                newChain[i] = new X509CertImpl(chain[i].getEncoded());
            }
            CertPath path = this.factory.generateCertPath(Arrays.asList(newChain));
            this.certPathLength = chain.length;
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(path, params);
            return toArray(path, result.getTrustAnchor());
        } catch (GeneralSecurityException e) {
            throw new ValidatorException("PKIX path validation failed: " + e.toString(), e);
        }
    }

    private static void verifyTrustAnchor(X509Certificate trustedCert) throws ValidatorException {
        if (ALLOW_NON_CA_ANCHOR || trustedCert.getVersion() < 3) {
            return;
        }
        if (trustedCert.getBasicConstraints() == -1) {
            throw new ValidatorException("TrustAnchor with subject \"" + trustedCert.getSubjectX500Principal() + "\" is not a CA certificate");
        }
        boolean[] keyUsageBits = trustedCert.getKeyUsage();
        if (keyUsageBits != null && !keyUsageBits[5]) {
            throw new ValidatorException("TrustAnchor with subject \"" + trustedCert.getSubjectX500Principal() + "\" does not have keyCertSign bit set in KeyUsage extension");
        }
    }

    private X509Certificate[] doBuild(X509Certificate[] chain, Collection<X509Certificate> otherCerts, PKIXBuilderParameters params) throws CertificateException {
        try {
            setDate(params);
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(chain[0]);
            params.setTargetCertConstraints(selector);
            Collection<X509Certificate> certs = new ArrayList<>();
            certs.addAll(Arrays.asList(chain));
            if (otherCerts != null) {
                certs.addAll(otherCerts);
            }
            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certs));
            params.addCertStore(store);
            CertPathBuilder builder = CertPathBuilder.getInstance(Validator.TYPE_PKIX);
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);
            return toArray(result.getCertPath(), result.getTrustAnchor());
        } catch (GeneralSecurityException e) {
            throw new ValidatorException("PKIX path building failed: " + e.toString(), e);
        }
    }

    private static void addResponses(PKIXBuilderParameters pkixParams, X509Certificate[] chain, List<byte[]> responseList) {
        if (pkixParams.isRevocationEnabled()) {
            try {
                PKIXRevocationChecker revChecker = null;
                List<PKIXCertPathChecker> checkerList = new ArrayList<>(pkixParams.getCertPathCheckers());
                Iterator<PKIXCertPathChecker> it = checkerList.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    PKIXCertPathChecker checker = it.next();
                    if (checker instanceof PKIXRevocationChecker) {
                        revChecker = (PKIXRevocationChecker) checker;
                        break;
                    }
                }
                if (revChecker == null) {
                    revChecker = (PKIXRevocationChecker) CertPathValidator.getInstance(Validator.TYPE_PKIX).getRevocationChecker();
                    checkerList.add(revChecker);
                }
                Map<X509Certificate, byte[]> responseMap = revChecker.getOcspResponses();
                int limit = Integer.min(chain.length, responseList.size());
                for (int idx = 0; idx < limit; idx++) {
                    byte[] respBytes = responseList.get(idx);
                    if (respBytes != null && respBytes.length > 0 && !responseMap.containsKey(chain[idx])) {
                        responseMap.put(chain[idx], respBytes);
                    }
                }
                revChecker.setOcspResponses(responseMap);
                pkixParams.setCertPathCheckers(checkerList);
            } catch (NoSuchAlgorithmException e) {
            }
        }
    }
}