package org.openjsse.sun.security.util;

import java.io.IOException;
import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.StringTokenizer;
import javax.net.ssl.SNIHostName;
import javax.security.auth.x500.X500Principal;
import org.openjsse.sun.security.ssl.SSLLogger;
import org.openjsse.sun.security.util.RegisteredDomain;
import sun.net.util.IPAddressUtil;
import sun.security.util.DerValue;
import sun.security.x509.X500Name;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/HostnameChecker.class */
public class HostnameChecker {
    public static final byte TYPE_TLS = 1;
    public static final byte TYPE_LDAP = 2;
    private static final int ALTNAME_DNS = 2;
    private static final int ALTNAME_IP = 7;
    private final byte checkType;
    private static final HostnameChecker INSTANCE_TLS = new HostnameChecker((byte) 1);
    private static final HostnameChecker INSTANCE_LDAP = new HostnameChecker((byte) 2);

    private HostnameChecker(byte checkType) {
        this.checkType = checkType;
    }

    public static HostnameChecker getInstance(byte checkType) {
        if (checkType == 1) {
            return INSTANCE_TLS;
        }
        if (checkType == 2) {
            return INSTANCE_LDAP;
        }
        throw new IllegalArgumentException("Unknown check type: " + ((int) checkType));
    }

    public void match(String expectedName, X509Certificate cert, boolean chainsToPublicCA) throws CertificateException {
        if (expectedName == null) {
            throw new CertificateException("Hostname or IP address is undefined.");
        }
        if (isIpAddress(expectedName)) {
            matchIP(expectedName, cert);
        } else {
            matchDNS(expectedName, cert, chainsToPublicCA);
        }
    }

    public void match(String expectedName, X509Certificate cert) throws CertificateException {
        match(expectedName, cert, false);
    }

    private static boolean isIpAddress(String name) {
        if (IPAddressUtil.isIPv4LiteralAddress(name) || IPAddressUtil.isIPv6LiteralAddress(name)) {
            return true;
        }
        return false;
    }

    private static void matchIP(String expectedIP, X509Certificate cert) throws CertificateException {
        Collection<List<?>> subjAltNames = cert.getSubjectAlternativeNames();
        if (subjAltNames == null) {
            throw new CertificateException("No subject alternative names present");
        }
        for (List<?> next : subjAltNames) {
            if (((Integer) next.get(0)).intValue() == 7) {
                String ipAddress = (String) next.get(1);
                if (expectedIP.equalsIgnoreCase(ipAddress)) {
                    return;
                }
                try {
                    if (InetAddress.getByName(expectedIP).equals(InetAddress.getByName(ipAddress))) {
                        return;
                    }
                } catch (SecurityException e) {
                } catch (UnknownHostException e2) {
                }
            }
        }
        throw new CertificateException("No subject alternative names matching IP address " + expectedIP + " found");
    }

    private void matchDNS(String expectedName, X509Certificate cert, boolean chainsToPublicCA) throws CertificateException {
        try {
            new SNIHostName(expectedName);
            Collection<List<?>> subjAltNames = cert.getSubjectAlternativeNames();
            if (subjAltNames != null) {
                boolean foundDNS = false;
                for (List<?> next : subjAltNames) {
                    if (((Integer) next.get(0)).intValue() == 2) {
                        foundDNS = true;
                        String dnsName = (String) next.get(1);
                        if (isMatched(expectedName, dnsName, chainsToPublicCA)) {
                            return;
                        }
                    }
                }
                if (foundDNS) {
                    throw new CertificateException("No subject alternative DNS name matching " + expectedName + " found.");
                }
            }
            X500Name subjectName = getSubjectX500Name(cert);
            DerValue derValue = subjectName.findMostSpecificAttribute(X500Name.commonName_oid);
            if (derValue != null) {
                try {
                    String cname = derValue.getAsString();
                    if (!Normalizer.isNormalized(cname, Normalizer.Form.NFKC)) {
                        throw new CertificateException("Not a formal name " + cname);
                    }
                    if (isMatched(expectedName, cname, chainsToPublicCA)) {
                        return;
                    }
                } catch (IOException e) {
                }
            }
            String msg = "No name matching " + expectedName + " found";
            throw new CertificateException(msg);
        } catch (IllegalArgumentException iae) {
            throw new CertificateException("Illegal given domain name: " + expectedName, iae);
        }
    }

    public static X500Name getSubjectX500Name(X509Certificate cert) throws CertificateParsingException {
        try {
            X500Name subjectDN = cert.getSubjectDN();
            if (subjectDN instanceof X500Name) {
                return subjectDN;
            }
            X500Principal subjectX500 = cert.getSubjectX500Principal();
            return new X500Name(subjectX500.getEncoded());
        } catch (IOException e) {
            throw ((CertificateParsingException) new CertificateParsingException().initCause(e));
        }
    }

    private boolean isMatched(String name, String template, boolean chainsToPublicCA) {
        try {
            String name2 = IDN.toUnicode(IDN.toASCII(name));
            String template2 = IDN.toUnicode(IDN.toASCII(template));
            if (hasIllegalWildcard(template2, chainsToPublicCA)) {
                return false;
            }
            try {
                new SNIHostName(template2.replace('*', 'z'));
                if (this.checkType == 1) {
                    return matchAllWildcards(name2, template2);
                }
                if (this.checkType == 2) {
                    return matchLeftmostWildcard(name2, template2);
                }
                return false;
            } catch (IllegalArgumentException e) {
                return false;
            }
        } catch (RuntimeException re) {
            if (SSLLogger.isOn) {
                SSLLogger.fine("Failed to normalize to Unicode: " + re, new Object[0]);
                return false;
            }
            return false;
        }
    }

    private static boolean hasIllegalWildcard(String template, boolean chainsToPublicCA) {
        if (template.equals("*") || template.equals("*.")) {
            if (SSLLogger.isOn) {
                SSLLogger.fine("Certificate domain name has illegal single wildcard character: " + template, new Object[0]);
                return true;
            }
            return true;
        }
        int lastWildcardIndex = template.lastIndexOf("*");
        if (lastWildcardIndex == -1) {
            return false;
        }
        String afterWildcard = template.substring(lastWildcardIndex);
        int firstDotIndex = afterWildcard.indexOf(".");
        if (firstDotIndex == -1) {
            if (SSLLogger.isOn) {
                SSLLogger.fine("Certificate domain name has illegal wildcard, no dot after wildcard character: " + template, new Object[0]);
                return true;
            }
            return true;
        } else if (!chainsToPublicCA) {
            return false;
        } else {
            String wildcardedDomain = afterWildcard.substring(firstDotIndex + 1);
            String templateDomainSuffix = (String) RegisteredDomain.from("z." + wildcardedDomain).filter(d -> {
                return d.type() == RegisteredDomain.Type.ICANN;
            }).map((v0) -> {
                return v0.publicSuffix();
            }).orElse(null);
            if (templateDomainSuffix != null && wildcardedDomain.equalsIgnoreCase(templateDomainSuffix)) {
                if (SSLLogger.isOn) {
                    SSLLogger.fine("Certificate domain name has illegal wildcard for top-level public suffix: " + template, new Object[0]);
                    return true;
                }
                return true;
            }
            return false;
        }
    }

    private static boolean matchAllWildcards(String name, String template) {
        String name2 = name.toLowerCase(Locale.ENGLISH);
        String template2 = template.toLowerCase(Locale.ENGLISH);
        StringTokenizer nameSt = new StringTokenizer(name2, ".");
        StringTokenizer templateSt = new StringTokenizer(template2, ".");
        if (nameSt.countTokens() != templateSt.countTokens()) {
            return false;
        }
        while (nameSt.hasMoreTokens()) {
            if (!matchWildCards(nameSt.nextToken(), templateSt.nextToken())) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchLeftmostWildcard(String name, String template) {
        String name2 = name.toLowerCase(Locale.ENGLISH);
        String template2 = template.toLowerCase(Locale.ENGLISH);
        int templateIdx = template2.indexOf(".");
        int nameIdx = name2.indexOf(".");
        if (templateIdx == -1) {
            templateIdx = template2.length();
        }
        if (nameIdx == -1) {
            nameIdx = name2.length();
        }
        if (matchWildCards(name2.substring(0, nameIdx), template2.substring(0, templateIdx))) {
            return template2.substring(templateIdx).equals(name2.substring(nameIdx));
        }
        return false;
    }

    private static boolean matchWildCards(String name, String template) {
        int wildcardIdx = template.indexOf("*");
        if (wildcardIdx == -1) {
            return name.equals(template);
        }
        boolean isBeginning = true;
        String afterWildcard = template;
        while (wildcardIdx != -1) {
            String beforeWildcard = afterWildcard.substring(0, wildcardIdx);
            afterWildcard = afterWildcard.substring(wildcardIdx + 1);
            int beforeStartIdx = name.indexOf(beforeWildcard);
            if (beforeStartIdx == -1) {
                return false;
            }
            if (isBeginning && beforeStartIdx != 0) {
                return false;
            }
            isBeginning = false;
            name = name.substring(beforeStartIdx + beforeWildcard.length());
            wildcardIdx = afterWildcard.indexOf("*");
        }
        return name.endsWith(afterWildcard);
    }
}