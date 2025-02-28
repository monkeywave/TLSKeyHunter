package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.CertificatePair;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class X509LDAPCertStoreSpi extends CertStoreSpi {
    private static String[] FILTER_ESCAPE_TABLE = new String[93];
    private static String LDAP_PROVIDER = null;
    private static String REFERRALS_IGNORE = null;
    private static final String SEARCH_SECURITY_LEVEL = "none";
    private static final String URL_CONTEXT_PREFIX = "com.sun.jndi.url";
    private X509LDAPCertStoreParameters params;

    static {
        char c = 0;
        while (true) {
            String[] strArr = FILTER_ESCAPE_TABLE;
            if (c >= strArr.length) {
                strArr[42] = "\\2a";
                strArr[40] = "\\28";
                strArr[41] = "\\29";
                strArr[92] = "\\5c";
                strArr[0] = "\\00";
                LDAP_PROVIDER = "com.sun.jndi.ldap.LdapCtxFactory";
                REFERRALS_IGNORE = "ignore";
                return;
            }
            strArr[c] = String.valueOf(c);
            c = (char) (c + 1);
        }
    }

    public X509LDAPCertStoreSpi(CertStoreParameters certStoreParameters) throws InvalidAlgorithmParameterException {
        super(certStoreParameters);
        if (!(certStoreParameters instanceof X509LDAPCertStoreParameters)) {
            throw new InvalidAlgorithmParameterException(X509LDAPCertStoreSpi.class.getName() + ": parameter must be a " + X509LDAPCertStoreParameters.class.getName() + " object\n" + certStoreParameters.toString());
        }
        this.params = (X509LDAPCertStoreParameters) certStoreParameters;
    }

    private Set certSubjectSerialSearch(X509CertSelector x509CertSelector, String[] strArr, String str, String str2) throws CertStoreException {
        String name;
        String str3;
        Set search;
        HashSet hashSet = new HashSet();
        try {
            if (x509CertSelector.getSubjectAsBytes() == null && x509CertSelector.getSubjectAsString() == null && x509CertSelector.getCertificate() == null) {
                search = search(str, "*", strArr);
                hashSet.addAll(search);
                return hashSet;
            }
            if (x509CertSelector.getCertificate() != null) {
                name = x509CertSelector.getCertificate().getSubjectX500Principal().getName("RFC1779");
                str3 = x509CertSelector.getCertificate().getSerialNumber().toString();
            } else {
                name = x509CertSelector.getSubjectAsBytes() != null ? new X500Principal(x509CertSelector.getSubjectAsBytes()).getName("RFC1779") : x509CertSelector.getSubjectAsString();
                str3 = null;
            }
            hashSet.addAll(search(str, "*" + parseDN(name, str2) + "*", strArr));
            if (str3 != null && this.params.getSearchForSerialNumberIn() != null) {
                search = search(this.params.getSearchForSerialNumberIn(), "*" + str3 + "*", strArr);
                hashSet.addAll(search);
            }
            return hashSet;
        } catch (IOException e) {
            throw new CertStoreException("exception processing selector: " + e);
        }
    }

    private DirContext connectLDAP() throws NamingException {
        Properties properties = new Properties();
        properties.setProperty("java.naming.factory.initial", LDAP_PROVIDER);
        properties.setProperty("java.naming.batchsize", "0");
        properties.setProperty("java.naming.provider.url", this.params.getLdapURL());
        properties.setProperty("java.naming.factory.url.pkgs", URL_CONTEXT_PREFIX);
        properties.setProperty("java.naming.referral", REFERRALS_IGNORE);
        properties.setProperty("java.naming.security.authentication", SEARCH_SECURITY_LEVEL);
        return new InitialDirContext(properties);
    }

    private String filterEncode(String str) {
        if (str == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(str.length() * 2);
        int length = str.length();
        for (int i = 0; i < length; i++) {
            char charAt = str.charAt(i);
            String[] strArr = FILTER_ESCAPE_TABLE;
            if (charAt < strArr.length) {
                sb.append(strArr[charAt]);
            } else {
                sb.append(charAt);
            }
        }
        return sb.toString();
    }

    private Set getCACertificates(X509CertSelector x509CertSelector) throws CertStoreException {
        String[] strArr = {this.params.getCACertificateAttribute()};
        Set certSubjectSerialSearch = certSubjectSerialSearch(x509CertSelector, strArr, this.params.getLdapCACertificateAttributeName(), this.params.getCACertificateSubjectAttributeName());
        if (certSubjectSerialSearch.isEmpty()) {
            certSubjectSerialSearch.addAll(search(null, "*", strArr));
        }
        return certSubjectSerialSearch;
    }

    private Set getCrossCertificates(X509CertSelector x509CertSelector) throws CertStoreException {
        String[] strArr = {this.params.getCrossCertificateAttribute()};
        Set certSubjectSerialSearch = certSubjectSerialSearch(x509CertSelector, strArr, this.params.getLdapCrossCertificateAttributeName(), this.params.getCrossCertificateSubjectAttributeName());
        if (certSubjectSerialSearch.isEmpty()) {
            certSubjectSerialSearch.addAll(search(null, "*", strArr));
        }
        return certSubjectSerialSearch;
    }

    private Set getEndCertificates(X509CertSelector x509CertSelector) throws CertStoreException {
        return certSubjectSerialSearch(x509CertSelector, new String[]{this.params.getUserCertificateAttribute()}, this.params.getLdapUserCertificateAttributeName(), this.params.getUserCertificateSubjectAttributeName());
    }

    private String parseDN(String str, String str2) {
        String substring = str.substring(Strings.toLowerCase(str).indexOf(Strings.toLowerCase(str2)) + str2.length());
        int indexOf = substring.indexOf(44);
        if (indexOf == -1) {
            indexOf = substring.length();
        }
        while (substring.charAt(indexOf - 1) == '\\') {
            indexOf = substring.indexOf(44, indexOf + 1);
            if (indexOf == -1) {
                indexOf = substring.length();
            }
        }
        String substring2 = substring.substring(0, indexOf);
        String substring3 = substring2.substring(substring2.indexOf(61) + 1);
        if (substring3.charAt(0) == ' ') {
            substring3 = substring3.substring(1);
        }
        if (substring3.startsWith("\"")) {
            substring3 = substring3.substring(1);
        }
        if (substring3.endsWith("\"")) {
            substring3 = substring3.substring(0, substring3.length() - 1);
        }
        return filterEncode(substring3);
    }

    private Set search(String str, String str2, String[] strArr) throws CertStoreException {
        String[] strArr2;
        String str3 = str + "=" + str2;
        DirContext dirContext = null;
        if (str == null) {
            str3 = null;
        }
        HashSet hashSet = new HashSet();
        try {
            try {
                dirContext = connectLDAP();
                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(2);
                searchControls.setCountLimit(0L);
                for (int i = 0; i < strArr.length; i++) {
                    searchControls.setReturningAttributes(new String[]{strArr[i]});
                    String str4 = "(&(" + str3 + ")(" + strArr2[0] + "=*))";
                    if (str3 == null) {
                        str4 = "(" + strArr2[0] + "=*)";
                    }
                    NamingEnumeration search = dirContext.search(this.params.getBaseDN(), str4, searchControls);
                    while (search.hasMoreElements()) {
                        NamingEnumeration all = ((Attribute) ((SearchResult) search.next()).getAttributes().getAll().next()).getAll();
                        while (all.hasMore()) {
                            hashSet.add(all.next());
                        }
                    }
                }
                if (dirContext != null) {
                    try {
                        dirContext.close();
                    } catch (Exception unused) {
                    }
                }
                return hashSet;
            } catch (Exception e) {
                throw new CertStoreException("Error getting results from LDAP directory " + e);
            }
        } catch (Throwable th) {
            if (dirContext != null) {
                try {
                    dirContext.close();
                } catch (Exception unused2) {
                }
            }
            throw th;
        }
    }

    @Override // java.security.cert.CertStoreSpi
    public Collection engineGetCRLs(CRLSelector cRLSelector) throws CertStoreException {
        String certificateRevocationListIssuerAttributeName;
        String name;
        String[] strArr = {this.params.getCertificateRevocationListAttribute()};
        if (cRLSelector instanceof X509CRLSelector) {
            X509CRLSelector x509CRLSelector = (X509CRLSelector) cRLSelector;
            HashSet hashSet = new HashSet();
            String ldapCertificateRevocationListAttributeName = this.params.getLdapCertificateRevocationListAttributeName();
            HashSet<byte[]> hashSet2 = new HashSet();
            if (x509CRLSelector.getIssuerNames() != null) {
                for (Object obj : x509CRLSelector.getIssuerNames()) {
                    if (obj instanceof String) {
                        certificateRevocationListIssuerAttributeName = this.params.getCertificateRevocationListIssuerAttributeName();
                        name = (String) obj;
                    } else {
                        certificateRevocationListIssuerAttributeName = this.params.getCertificateRevocationListIssuerAttributeName();
                        name = new X500Principal((byte[]) obj).getName("RFC1779");
                    }
                    hashSet2.addAll(search(ldapCertificateRevocationListAttributeName, "*" + parseDN(name, certificateRevocationListIssuerAttributeName) + "*", strArr));
                }
            } else {
                hashSet2.addAll(search(ldapCertificateRevocationListAttributeName, "*", strArr));
            }
            hashSet2.addAll(search(null, "*", strArr));
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                for (byte[] bArr : hashSet2) {
                    CRL generateCRL = certificateFactory.generateCRL(new ByteArrayInputStream(bArr));
                    if (x509CRLSelector.match(generateCRL)) {
                        hashSet.add(generateCRL);
                    }
                }
                return hashSet;
            } catch (Exception e) {
                throw new CertStoreException("CRL cannot be constructed from LDAP result " + e);
            }
        }
        throw new CertStoreException("selector is not a X509CRLSelector");
    }

    @Override // java.security.cert.CertStoreSpi
    public Collection engineGetCertificates(CertSelector certSelector) throws CertStoreException {
        if (certSelector instanceof X509CertSelector) {
            X509CertSelector x509CertSelector = (X509CertSelector) certSelector;
            HashSet hashSet = new HashSet();
            Set<byte[]> endCertificates = getEndCertificates(x509CertSelector);
            endCertificates.addAll(getCACertificates(x509CertSelector));
            endCertificates.addAll(getCrossCertificates(x509CertSelector));
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                for (byte[] bArr : endCertificates) {
                    if (bArr != null && bArr.length != 0) {
                        ArrayList<byte[]> arrayList = new ArrayList();
                        arrayList.add(bArr);
                        try {
                            CertificatePair certificatePair = CertificatePair.getInstance(new ASN1InputStream(bArr).readObject());
                            arrayList.clear();
                            if (certificatePair.getForward() != null) {
                                arrayList.add(certificatePair.getForward().getEncoded());
                            }
                            if (certificatePair.getReverse() != null) {
                                arrayList.add(certificatePair.getReverse().getEncoded());
                            }
                        } catch (IOException | IllegalArgumentException unused) {
                        }
                        for (byte[] bArr2 : arrayList) {
                            try {
                                Certificate generateCertificate = certificateFactory.generateCertificate(new ByteArrayInputStream(bArr2));
                                if (x509CertSelector.match(generateCertificate)) {
                                    hashSet.add(generateCertificate);
                                }
                            } catch (Exception unused2) {
                            }
                        }
                    }
                }
                return hashSet;
            } catch (Exception e) {
                throw new CertStoreException("certificate cannot be constructed from LDAP result: " + e);
            }
        }
        throw new CertStoreException("selector is not a X509CertSelector");
    }
}