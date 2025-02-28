package org.openjsse.sun.security.ssl;

import java.lang.ref.Reference;
import java.lang.ref.SoftReference;
import java.net.Socket;
import java.security.AlgorithmConstraints;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;
import org.openjsse.javax.net.ssl.ExtendedSSLSession;
import org.openjsse.javax.net.ssl.SSLSocket;
import org.openjsse.sun.security.validator.Validator;
import sun.security.provider.certpath.AlgorithmChecker;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509KeyManagerImpl.class */
public final class X509KeyManagerImpl extends X509ExtendedKeyManager implements X509KeyManager {
    private static Date verificationDate;
    private final List<KeyStore.Builder> builders;
    private final AtomicLong uidCounter;
    private final Map<String, Reference<KeyStore.PrivateKeyEntry>> entryCacheMap;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509KeyManagerImpl$CheckResult.class */
    public enum CheckResult {
        OK,
        INSENSITIVE,
        EXPIRED,
        EXTENSION_MISMATCH
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509KeyManagerImpl(KeyStore.Builder builder) {
        this(Collections.singletonList(builder));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509KeyManagerImpl(List<KeyStore.Builder> builders) {
        this.builders = builders;
        this.uidCounter = new AtomicLong();
        this.entryCacheMap = Collections.synchronizedMap(new SizedMap());
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509KeyManagerImpl$SizedMap.class */
    private static class SizedMap<K, V> extends LinkedHashMap<K, V> {
        private static final long serialVersionUID = -8211222668790986062L;

        private SizedMap() {
        }

        @Override // java.util.LinkedHashMap
        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return size() > 10;
        }
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String alias) {
        KeyStore.PrivateKeyEntry entry = getEntry(alias);
        if (entry == null) {
            return null;
        }
        return (X509Certificate[]) entry.getCertificateChain();
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String alias) {
        KeyStore.PrivateKeyEntry entry = getEntry(alias);
        if (entry == null) {
            return null;
        }
        return entry.getPrivateKey();
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return chooseAlias(getKeyTypes(keyTypes), issuers, CheckType.CLIENT, getAlgorithmConstraints(socket));
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return chooseAlias(getKeyTypes(keyTypes), issuers, CheckType.CLIENT, getAlgorithmConstraints(engine));
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return chooseAlias(getKeyTypes(keyType), issuers, CheckType.SERVER, getAlgorithmConstraints(socket), getCertificateAuthorities(socket), X509TrustManagerImpl.getRequestedServerNames(socket), "HTTPS");
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return chooseAlias(getKeyTypes(keyType), issuers, CheckType.SERVER, getAlgorithmConstraints(engine), getCertificateAuthorities(engine), X509TrustManagerImpl.getRequestedServerNames(engine), "HTTPS");
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType, issuers, CheckType.CLIENT, null);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType, issuers, CheckType.SERVER, null);
    }

    private AlgorithmConstraints getAlgorithmConstraints(Socket socket) {
        if (socket != null && socket.isConnected() && (socket instanceof SSLSocket)) {
            SSLSocket sslSocket = (SSLSocket) socket;
            SSLSession session = sslSocket.getHandshakeSession();
            if (session != null && ProtocolVersion.useTLS12PlusSpec(session.getProtocol())) {
                String[] peerSupportedSignAlgs = null;
                if (session instanceof ExtendedSSLSession) {
                    ExtendedSSLSession extSession = (ExtendedSSLSession) session;
                    peerSupportedSignAlgs = extSession.getPeerSupportedSignatureAlgorithms();
                }
                return new SSLAlgorithmConstraints(sslSocket, peerSupportedSignAlgs, true);
            }
            return new SSLAlgorithmConstraints(sslSocket, true);
        }
        return new SSLAlgorithmConstraints((SSLSocket) null, true);
    }

    private AlgorithmConstraints getAlgorithmConstraints(SSLEngine engine) {
        SSLSession session;
        if (engine != null && (session = engine.getHandshakeSession()) != null && ProtocolVersion.useTLS12PlusSpec(session.getProtocol())) {
            String[] peerSupportedSignAlgs = null;
            if (session instanceof ExtendedSSLSession) {
                ExtendedSSLSession extSession = (ExtendedSSLSession) session;
                peerSupportedSignAlgs = extSession.getPeerSupportedSignatureAlgorithms();
            }
            return new SSLAlgorithmConstraints(engine, peerSupportedSignAlgs, true);
        }
        return new SSLAlgorithmConstraints(engine, true);
    }

    private X500Principal[] getCertificateAuthorities(Socket socket) {
        if (socket != null && socket.isConnected() && (socket instanceof SSLSocket)) {
            SSLSocket sslSocket = (SSLSocket) socket;
            return getCertificateAuthorities(sslSocket.getHandshakeSession());
        }
        return null;
    }

    private X500Principal[] getCertificateAuthorities(SSLEngine engine) {
        if (engine != null) {
            return getCertificateAuthorities(engine.getHandshakeSession());
        }
        return null;
    }

    private X500Principal[] getCertificateAuthorities(SSLSession session) {
        if (session != null && ProtocolVersion.useTLS12PlusSpec(session.getProtocol()) && (session instanceof SSLSessionImpl)) {
            return ((SSLSessionImpl) session).getCertificateAuthorities();
        }
        return null;
    }

    private String makeAlias(EntryStatus entry) {
        return this.uidCounter.incrementAndGet() + "." + entry.builderIndex + "." + entry.alias;
    }

    private KeyStore.PrivateKeyEntry getEntry(String alias) {
        if (alias == null) {
            return null;
        }
        Reference<KeyStore.PrivateKeyEntry> ref = this.entryCacheMap.get(alias);
        KeyStore.PrivateKeyEntry entry = ref != null ? ref.get() : null;
        if (entry != null) {
            return entry;
        }
        int firstDot = alias.indexOf(46);
        int secondDot = alias.indexOf(46, firstDot + 1);
        if (firstDot == -1 || secondDot == firstDot) {
            return null;
        }
        try {
            int builderIndex = Integer.parseInt(alias.substring(firstDot + 1, secondDot));
            String keyStoreAlias = alias.substring(secondDot + 1);
            KeyStore.Builder builder = this.builders.get(builderIndex);
            KeyStore ks = builder.getKeyStore();
            KeyStore.Entry newEntry = ks.getEntry(keyStoreAlias, builder.getProtectionParameter(alias));
            if (!(newEntry instanceof KeyStore.PrivateKeyEntry)) {
                return null;
            }
            KeyStore.PrivateKeyEntry entry2 = (KeyStore.PrivateKeyEntry) newEntry;
            this.entryCacheMap.put(alias, new SoftReference(entry2));
            return entry2;
        } catch (Exception e) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509KeyManagerImpl$KeyType.class */
    public static class KeyType {
        final String keyAlgorithm;
        final String sigKeyAlgorithm;

        KeyType(String algorithm) {
            int k = algorithm.indexOf(95);
            if (k == -1) {
                this.keyAlgorithm = algorithm;
                this.sigKeyAlgorithm = null;
                return;
            }
            this.keyAlgorithm = algorithm.substring(0, k);
            this.sigKeyAlgorithm = algorithm.substring(k + 1);
        }

        boolean matches(Certificate[] chain) {
            if (!chain[0].getPublicKey().getAlgorithm().equals(this.keyAlgorithm)) {
                return false;
            }
            if (this.sigKeyAlgorithm == null) {
                return true;
            }
            if (chain.length > 1) {
                return this.sigKeyAlgorithm.equals(chain[1].getPublicKey().getAlgorithm());
            }
            X509Certificate issuer = (X509Certificate) chain[0];
            String sigAlgName = issuer.getSigAlgName().toUpperCase(Locale.ENGLISH);
            String pattern = "WITH" + this.sigKeyAlgorithm.toUpperCase(Locale.ENGLISH);
            return sigAlgName.contains(pattern);
        }
    }

    private static List<KeyType> getKeyTypes(String... keyTypes) {
        if (keyTypes == null || keyTypes.length == 0 || keyTypes[0] == null) {
            return null;
        }
        List<KeyType> list = new ArrayList<>(keyTypes.length);
        for (String keyType : keyTypes) {
            list.add(new KeyType(keyType));
        }
        return list;
    }

    private String chooseAlias(List<KeyType> keyTypeList, Principal[] issuers, CheckType checkType, AlgorithmConstraints constraints) {
        return chooseAlias(keyTypeList, issuers, checkType, constraints, null, null, null);
    }

    private String chooseAlias(List<KeyType> keyTypeList, Principal[] issuers, CheckType checkType, AlgorithmConstraints constraints, X500Principal[] certificateAuthorities, List<SNIServerName> requestedServerNames, String idAlgorithm) {
        if (keyTypeList == null || keyTypeList.isEmpty()) {
            return null;
        }
        Set<Principal> issuerSet = getIssuerSet(issuers);
        List<EntryStatus> allResults = null;
        int n = this.builders.size();
        for (int i = 0; i < n; i++) {
            try {
                List<EntryStatus> results = getAliases(i, keyTypeList, issuerSet, false, checkType, constraints, certificateAuthorities, requestedServerNames, idAlgorithm);
                if (results != null) {
                    EntryStatus status = results.get(0);
                    if (status.checkResult == CheckResult.OK) {
                        if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                            SSLLogger.fine("KeyMgr: choosing key: " + status, new Object[0]);
                        }
                        return makeAlias(status);
                    }
                    if (allResults == null) {
                        allResults = new ArrayList<>();
                    }
                    allResults.addAll(results);
                }
            } catch (Exception e) {
            }
        }
        if (allResults == null) {
            if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                SSLLogger.fine("KeyMgr: no matching key found", new Object[0]);
                return null;
            }
            return null;
        }
        Collections.sort(allResults);
        if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
            SSLLogger.fine("KeyMgr: no good matching key found, returning best match out of", allResults);
        }
        return makeAlias(allResults.get(0));
    }

    public String[] getAliases(String keyType, Principal[] issuers, CheckType checkType, AlgorithmConstraints constraints) {
        if (keyType == null) {
            return null;
        }
        Set<Principal> issuerSet = getIssuerSet(issuers);
        List<KeyType> keyTypeList = getKeyTypes(keyType);
        List<EntryStatus> allResults = null;
        int n = this.builders.size();
        for (int i = 0; i < n; i++) {
            try {
                List<EntryStatus> results = getAliases(i, keyTypeList, issuerSet, true, checkType, constraints, null, null, null);
                if (results != null) {
                    if (allResults == null) {
                        allResults = new ArrayList<>();
                    }
                    allResults.addAll(results);
                }
            } catch (Exception e) {
            }
        }
        if (allResults == null || allResults.isEmpty()) {
            if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                SSLLogger.fine("KeyMgr: no matching alias found", new Object[0]);
                return null;
            }
            return null;
        }
        Collections.sort(allResults);
        if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
            SSLLogger.fine("KeyMgr: getting aliases", allResults);
        }
        return toAliases(allResults);
    }

    private String[] toAliases(List<EntryStatus> results) {
        String[] s = new String[results.size()];
        int i = 0;
        for (EntryStatus result : results) {
            int i2 = i;
            i++;
            s[i2] = makeAlias(result);
        }
        return s;
    }

    private Set<Principal> getIssuerSet(Principal[] issuers) {
        if (issuers != null && issuers.length != 0) {
            return new HashSet(Arrays.asList(issuers));
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509KeyManagerImpl$EntryStatus.class */
    public static class EntryStatus implements Comparable<EntryStatus> {
        final int builderIndex;
        final int keyIndex;
        final String alias;
        final CheckResult checkResult;

        EntryStatus(int builderIndex, int keyIndex, String alias, Certificate[] chain, CheckResult checkResult) {
            this.builderIndex = builderIndex;
            this.keyIndex = keyIndex;
            this.alias = alias;
            this.checkResult = checkResult;
        }

        @Override // java.lang.Comparable
        public int compareTo(EntryStatus other) {
            int result = this.checkResult.compareTo(other.checkResult);
            return result == 0 ? this.keyIndex - other.keyIndex : result;
        }

        public String toString() {
            String s = this.alias + " (verified: " + this.checkResult + ")";
            if (this.builderIndex == 0) {
                return s;
            }
            return "Builder #" + this.builderIndex + ", alias: " + s;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509KeyManagerImpl$CheckType.class */
    public enum CheckType {
        NONE(Collections.emptySet()),
        CLIENT(new HashSet(Arrays.asList("2.5.29.37.0", "1.3.6.1.5.5.7.3.2"))),
        SERVER(new HashSet(Arrays.asList("2.5.29.37.0", "1.3.6.1.5.5.7.3.1", "2.16.840.1.113730.4.1", "1.3.6.1.4.1.311.10.3.3")));
        
        final Set<String> validEku;

        CheckType(Set set) {
            this.validEku = set;
        }

        private static boolean getBit(boolean[] keyUsage, int bit) {
            return bit < keyUsage.length && keyUsage[bit];
        }

        CheckResult check(X509Certificate cert, Date date, List<SNIServerName> serverNames, String idAlgorithm) {
            if (this == NONE) {
                return CheckResult.OK;
            }
            try {
                List<String> certEku = cert.getExtendedKeyUsage();
                if (certEku != null && Collections.disjoint(this.validEku, certEku)) {
                    return CheckResult.EXTENSION_MISMATCH;
                }
                boolean[] ku = cert.getKeyUsage();
                if (ku != null) {
                    String algorithm = cert.getPublicKey().getAlgorithm();
                    boolean supportsDigitalSignature = getBit(ku, 0);
                    boolean z = true;
                    switch (algorithm.hashCode()) {
                        case 2180:
                            if (algorithm.equals("DH")) {
                                z = true;
                                break;
                            }
                            break;
                        case 2206:
                            if (algorithm.equals("EC")) {
                                z = true;
                                break;
                            }
                            break;
                        case 67986:
                            if (algorithm.equals("DSA")) {
                                z = true;
                                break;
                            }
                            break;
                        case 81440:
                            if (algorithm.equals("RSA")) {
                                z = false;
                                break;
                            }
                            break;
                        case 1775481508:
                            if (algorithm.equals("RSASSA-PSS")) {
                                z = true;
                                break;
                            }
                            break;
                    }
                    switch (z) {
                        case false:
                            if (!supportsDigitalSignature && (this == CLIENT || !getBit(ku, 2))) {
                                return CheckResult.EXTENSION_MISMATCH;
                            }
                            break;
                        case true:
                            if (!supportsDigitalSignature && this == SERVER) {
                                return CheckResult.EXTENSION_MISMATCH;
                            }
                            break;
                        case true:
                            if (!supportsDigitalSignature) {
                                return CheckResult.EXTENSION_MISMATCH;
                            }
                            break;
                        case true:
                            if (!getBit(ku, 4)) {
                                return CheckResult.EXTENSION_MISMATCH;
                            }
                            break;
                        case true:
                            if (!supportsDigitalSignature) {
                                return CheckResult.EXTENSION_MISMATCH;
                            }
                            if (this == SERVER && !getBit(ku, 4)) {
                                return CheckResult.EXTENSION_MISMATCH;
                            }
                            break;
                    }
                }
                try {
                    cert.checkValidity(date);
                    if (serverNames != null && !serverNames.isEmpty()) {
                        Iterator<SNIServerName> it = serverNames.iterator();
                        while (true) {
                            if (it.hasNext()) {
                                SNIServerName serverName = it.next();
                                if (serverName.getType() == 0) {
                                    if (!(serverName instanceof SNIHostName)) {
                                        try {
                                            serverName = new SNIHostName(serverName.getEncoded());
                                        } catch (IllegalArgumentException e) {
                                            if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                                                SSLLogger.fine("Illegal server name: " + serverName, new Object[0]);
                                            }
                                            return CheckResult.INSENSITIVE;
                                        }
                                    }
                                    String hostname = ((SNIHostName) serverName).getAsciiName();
                                    try {
                                        X509TrustManagerImpl.checkIdentity(hostname, cert, idAlgorithm);
                                    } catch (CertificateException e2) {
                                        if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                                            SSLLogger.fine("Certificate identity does not match Server Name Inidication (SNI): " + hostname, new Object[0]);
                                        }
                                        return CheckResult.INSENSITIVE;
                                    }
                                }
                            }
                        }
                    }
                    return CheckResult.OK;
                } catch (CertificateException e3) {
                    return CheckResult.EXPIRED;
                }
            } catch (CertificateException e4) {
                return CheckResult.EXTENSION_MISMATCH;
            }
        }

        public String getValidator() {
            if (this == CLIENT) {
                return Validator.VAR_TLS_CLIENT;
            }
            if (this == SERVER) {
                return Validator.VAR_TLS_SERVER;
            }
            return Validator.VAR_GENERIC;
        }
    }

    private List<EntryStatus> getAliases(int builderIndex, List<KeyType> keyTypes, Set<Principal> issuerSet, boolean findAll, CheckType checkType, AlgorithmConstraints constraints, X500Principal[] certificateAuthorities, List<SNIServerName> requestedServerNames, String idAlgorithm) throws Exception {
        Certificate[] chain;
        KeyStore.Builder builder = this.builders.get(builderIndex);
        KeyStore ks = builder.getKeyStore();
        List<EntryStatus> results = null;
        Date date = verificationDate;
        boolean preferred = false;
        Enumeration<String> e = ks.aliases();
        while (e.hasMoreElements()) {
            String alias = e.nextElement();
            if (ks.isKeyEntry(alias) && (chain = ks.getCertificateChain(alias)) != null && chain.length != 0) {
                boolean incompatible = false;
                int length = chain.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        break;
                    }
                    Certificate cert = chain[i];
                    if (cert instanceof X509Certificate) {
                        i++;
                    } else {
                        incompatible = true;
                        break;
                    }
                }
                if (incompatible) {
                    continue;
                } else {
                    int keyIndex = -1;
                    int j = 0;
                    Iterator<KeyType> it = keyTypes.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        KeyType keyType = it.next();
                        if (keyType.matches(chain)) {
                            keyIndex = j;
                            break;
                        }
                        j++;
                    }
                    if (keyIndex == -1) {
                        if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                            SSLLogger.fine("Ignore alias " + alias + ": key algorithm does not match", new Object[0]);
                        }
                    } else {
                        if (issuerSet != null) {
                            boolean found = false;
                            int length2 = chain.length;
                            int i2 = 0;
                            while (true) {
                                if (i2 >= length2) {
                                    break;
                                }
                                Certificate cert2 = chain[i2];
                                X509Certificate xcert = (X509Certificate) cert2;
                                if (!issuerSet.contains(xcert.getIssuerX500Principal())) {
                                    i2++;
                                } else {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                                    SSLLogger.fine("Ignore alias " + alias + ": issuers do not match", new Object[0]);
                                }
                            }
                        }
                        if (certificateAuthorities != null) {
                            boolean foundCertificateAuthority = false;
                            for (int i3 = chain.length - 1; i3 >= 0 && !foundCertificateAuthority; i3--) {
                                X509Certificate cert3 = (X509Certificate) chain[i3];
                                for (X500Principal ca : certificateAuthorities) {
                                    try {
                                        if (ca.equals(cert3.getSubjectX500Principal())) {
                                            foundCertificateAuthority = true;
                                        }
                                    } catch (Exception e2) {
                                    }
                                }
                            }
                            if (!foundCertificateAuthority) {
                                continue;
                            }
                        }
                        if (constraints != null && !conformsToAlgorithmConstraints(constraints, chain, checkType.getValidator())) {
                            if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                                SSLLogger.fine("Ignore alias " + alias + ": certificate list does not conform to algorithm constraints", new Object[0]);
                            }
                        } else {
                            if (date == null) {
                                date = new Date();
                            }
                            CheckResult checkResult = checkType.check((X509Certificate) chain[0], date, requestedServerNames, idAlgorithm);
                            EntryStatus status = new EntryStatus(builderIndex, keyIndex, alias, chain, checkResult);
                            if (!preferred && checkResult == CheckResult.OK && keyIndex == 0) {
                                preferred = true;
                            }
                            if (preferred && !findAll) {
                                return Collections.singletonList(status);
                            }
                            if (results == null) {
                                results = new ArrayList<>();
                            }
                            results.add(status);
                        }
                    }
                }
            }
        }
        return results;
    }

    private static boolean conformsToAlgorithmConstraints(AlgorithmConstraints constraints, Certificate[] chain, String variant) {
        AlgorithmChecker checker = new AlgorithmChecker(constraints, variant);
        try {
            checker.init(false);
            for (int i = chain.length - 1; i >= 0; i--) {
                Certificate cert = chain[i];
                try {
                    checker.check(cert, Collections.emptySet());
                } catch (CertPathValidatorException cpve) {
                    if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                        SSLLogger.fine("Certificate does not conform to algorithm constraints", cert, cpve);
                        return false;
                    }
                    return false;
                }
            }
            return true;
        } catch (CertPathValidatorException cpve2) {
            if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                SSLLogger.fine("Cannot initialize algorithm constraints checker", cpve2);
                return false;
            }
            return false;
        }
    }
}