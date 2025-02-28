package org.bouncycastle.jsse.provider;

import java.lang.ref.SoftReference;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.p009x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvX509KeyManager extends BCX509ExtendedKeyManager {
    private final List<KeyStore.Builder> builders;
    private final JcaJceHelper helper;
    private final boolean isInFipsMode;
    private static final Logger LOG = Logger.getLogger(ProvX509KeyManager.class.getName());
    private static final boolean provKeyManagerCheckEKU = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.keyManager.checkEKU", true);
    private static final Map<String, PublicKeyFilter> FILTERS_CLIENT = createFiltersClient();
    private static final Map<String, PublicKeyFilter> FILTERS_SERVER = createFiltersServer();
    private final AtomicLong versions = new AtomicLong();
    private final Map<String, SoftReference<KeyStore.PrivateKeyEntry>> cachedEntries = Collections.synchronizedMap(new LinkedHashMap<String, SoftReference<KeyStore.PrivateKeyEntry>>(16, 0.75f, true) { // from class: org.bouncycastle.jsse.provider.ProvX509KeyManager.1
        @Override // java.util.LinkedHashMap
        protected boolean removeEldestEntry(Map.Entry<String, SoftReference<KeyStore.PrivateKeyEntry>> entry) {
            return size() > 16;
        }
    });

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static final class DefaultPublicKeyFilter implements PublicKeyFilter {
        final String algorithm;
        final Class<? extends PublicKey> clazz;
        final int keyUsageBit;

        DefaultPublicKeyFilter(String str, Class<? extends PublicKey> cls, int i) {
            this.algorithm = str;
            this.clazz = cls;
            this.keyUsageBit = i;
        }

        private boolean appliesTo(PublicKey publicKey) {
            Class<? extends PublicKey> cls;
            String str = this.algorithm;
            return (str != null && str.equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(publicKey))) || ((cls = this.clazz) != null && cls.isInstance(publicKey));
        }

        @Override // org.bouncycastle.jsse.provider.ProvX509KeyManager.PublicKeyFilter
        public boolean accepts(PublicKey publicKey, boolean[] zArr, BCAlgorithmConstraints bCAlgorithmConstraints) {
            return appliesTo(publicKey) && ProvAlgorithmChecker.permitsKeyUsage(publicKey, zArr, this.keyUsageBit, bCAlgorithmConstraints);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static final class ECPublicKeyFilter13 implements PublicKeyFilter {
        final ASN1ObjectIdentifier standardOID;

        ECPublicKeyFilter13(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
            this.standardOID = aSN1ObjectIdentifier;
        }

        private boolean appliesTo(PublicKey publicKey) {
            if ("EC".equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(publicKey)) || ECPublicKey.class.isInstance(publicKey)) {
                return this.standardOID.equals((ASN1Primitive) JsseUtils.getNamedCurveOID(publicKey));
            }
            return false;
        }

        @Override // org.bouncycastle.jsse.provider.ProvX509KeyManager.PublicKeyFilter
        public boolean accepts(PublicKey publicKey, boolean[] zArr, BCAlgorithmConstraints bCAlgorithmConstraints) {
            return appliesTo(publicKey) && ProvAlgorithmChecker.permitsKeyUsage(publicKey, zArr, 0, bCAlgorithmConstraints);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static final class Match implements Comparable<Match> {
        static final MatchQuality INVALID = MatchQuality.MISMATCH_SNI;
        static final Match NOTHING = new Match(MatchQuality.NONE, Integer.MAX_VALUE, -1, null, null, null);
        final int builderIndex;
        final X509Certificate[] cachedCertificateChain;
        final KeyStore cachedKeyStore;
        final int keyTypeIndex;
        final String localAlias;
        final MatchQuality quality;

        Match(MatchQuality matchQuality, int i, int i2, String str, KeyStore keyStore, X509Certificate[] x509CertificateArr) {
            this.quality = matchQuality;
            this.keyTypeIndex = i;
            this.builderIndex = i2;
            this.localAlias = str;
            this.cachedKeyStore = keyStore;
            this.cachedCertificateChain = x509CertificateArr;
        }

        @Override // java.lang.Comparable
        public int compareTo(Match match) {
            boolean isValid = isValid();
            if (isValid != match.isValid()) {
                return isValid ? -1 : 1;
            }
            int i = this.keyTypeIndex;
            int i2 = match.keyTypeIndex;
            return i != i2 ? i < i2 ? -1 : 1 : this.quality.compareTo(match.quality);
        }

        boolean isIdeal() {
            return MatchQuality.OK == this.quality && this.keyTypeIndex == 0;
        }

        boolean isValid() {
            return this.quality.compareTo(INVALID) < 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public enum MatchQuality {
        OK,
        RSA_MULTI_USE,
        MISMATCH_SNI,
        EXPIRED,
        NONE
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public interface PublicKeyFilter {
        boolean accepts(PublicKey publicKey, boolean[] zArr, BCAlgorithmConstraints bCAlgorithmConstraints);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvX509KeyManager(boolean z, JcaJceHelper jcaJceHelper, List<KeyStore.Builder> list) {
        this.isInFipsMode = z;
        this.helper = jcaJceHelper;
        this.builders = list;
    }

    private static void addECFilter13(Map<String, PublicKeyFilter> map, int i) {
        ASN1ObjectIdentifier oid;
        if (!NamedGroup.canBeNegotiated(i, ProtocolVersion.TLSv13)) {
            throw new IllegalStateException("Invalid named group for TLS 1.3 EC filter");
        }
        String curveName = NamedGroup.getCurveName(i);
        if (curveName == null || (oid = ECNamedCurveTable.getOID(curveName)) == null) {
            LOG.warning("Failed to register public key filter for EC with " + NamedGroup.getText(i));
        } else {
            addFilterToMap(map, JsseUtils.getKeyType13("EC", i), new ECPublicKeyFilter13(oid));
        }
    }

    private static void addFilter(Map<String, PublicKeyFilter> map, int i, String str, Class<? extends PublicKey> cls, String... strArr) {
        DefaultPublicKeyFilter defaultPublicKeyFilter = new DefaultPublicKeyFilter(str, cls, i);
        for (String str2 : strArr) {
            addFilterToMap(map, str2, defaultPublicKeyFilter);
        }
    }

    private static void addFilter(Map<String, PublicKeyFilter> map, Class<? extends PublicKey> cls, String... strArr) {
        addFilter(map, 0, null, cls, strArr);
    }

    private static void addFilter(Map<String, PublicKeyFilter> map, String str) {
        addFilter(map, 0, str, null, str);
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> map, int i, String str, Class<? extends PublicKey> cls, int... iArr) {
        addFilter(map, i, str, cls, getKeyTypesLegacyServer(iArr));
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> map, int i, String str, int... iArr) {
        addFilterLegacyServer(map, i, str, null, iArr);
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> map, Class<? extends PublicKey> cls, int... iArr) {
        addFilterLegacyServer(map, 0, null, cls, iArr);
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> map, String str, int... iArr) {
        addFilterLegacyServer(map, 0, str, iArr);
    }

    private static void addFilterToMap(Map<String, PublicKeyFilter> map, String str, PublicKeyFilter publicKeyFilter) {
        if (map.put(str, publicKeyFilter) != null) {
            throw new IllegalStateException("Duplicate keys in filters");
        }
    }

    private static List<Match> addToMatches(List<Match> list, Match match) {
        if (list == null) {
            list = new ArrayList<>();
        }
        list.add(match);
        return list;
    }

    private String chooseAlias(List<String> list, Principal[] principalArr, TransportData transportData, boolean z) {
        Match bestMatch = getBestMatch(list, principalArr, transportData, z);
        if (bestMatch.compareTo(Match.NOTHING) >= 0) {
            LOG.fine("No matching key found");
            return null;
        }
        String str = list.get(bestMatch.keyTypeIndex);
        String alias = getAlias(bestMatch, getNextVersionSuffix());
        Logger logger = LOG;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine("Found matching key of type: " + str + ", returning alias: " + alias);
        }
        return alias;
    }

    private BCX509Key chooseKeyBC(List<String> list, Principal[] principalArr, TransportData transportData, boolean z) {
        Match bestMatch = getBestMatch(list, principalArr, transportData, z);
        if (bestMatch.compareTo(Match.NOTHING) < 0) {
            try {
                String str = list.get(bestMatch.keyTypeIndex);
                BCX509Key createKeyBC = createKeyBC(str, bestMatch.builderIndex, bestMatch.localAlias, bestMatch.cachedKeyStore, bestMatch.cachedCertificateChain);
                if (createKeyBC != null) {
                    Logger logger = LOG;
                    if (logger.isLoggable(Level.FINE)) {
                        logger.fine("Found matching key of type: " + str + ", from alias: " + bestMatch.builderIndex + "." + bestMatch.localAlias);
                    }
                    return createKeyBC;
                }
            } catch (Exception e) {
                LOG.log(Level.FINER, "Failed to load private key", (Throwable) e);
            }
        }
        LOG.fine("No matching key found");
        return null;
    }

    private static Map<String, PublicKeyFilter> createFiltersClient() {
        HashMap hashMap = new HashMap();
        addFilter(hashMap, EdDSAParameterSpec.Ed25519);
        addFilter(hashMap, EdDSAParameterSpec.Ed448);
        addECFilter13(hashMap, 31);
        addECFilter13(hashMap, 32);
        addECFilter13(hashMap, 33);
        addECFilter13(hashMap, 23);
        addECFilter13(hashMap, 24);
        addECFilter13(hashMap, 25);
        addFilter(hashMap, "RSA");
        addFilter(hashMap, "RSASSA-PSS");
        addFilter(hashMap, DSAPublicKey.class, "DSA");
        addFilter(hashMap, ECPublicKey.class, "EC");
        return Collections.unmodifiableMap(hashMap);
    }

    private static Map<String, PublicKeyFilter> createFiltersServer() {
        HashMap hashMap = new HashMap();
        addFilter(hashMap, EdDSAParameterSpec.Ed25519);
        addFilter(hashMap, EdDSAParameterSpec.Ed448);
        addECFilter13(hashMap, 31);
        addECFilter13(hashMap, 32);
        addECFilter13(hashMap, 33);
        addECFilter13(hashMap, 23);
        addECFilter13(hashMap, 24);
        addECFilter13(hashMap, 25);
        addFilter(hashMap, "RSA");
        addFilter(hashMap, "RSASSA-PSS");
        addFilterLegacyServer(hashMap, DSAPublicKey.class, 3, 22);
        addFilterLegacyServer(hashMap, ECPublicKey.class, 17);
        addFilterLegacyServer(hashMap, "RSA", 5, 19, 23);
        addFilterLegacyServer(hashMap, 2, "RSA", 1);
        return Collections.unmodifiableMap(hashMap);
    }

    private BCX509Key createKeyBC(String str, int i, String str2, KeyStore keyStore, X509Certificate[] x509CertificateArr) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Key key = KeyStoreUtil.getKey(keyStore, str2, this.builders.get(i).getProtectionParameter(str2));
        if (key instanceof PrivateKey) {
            return new ProvX509Key(str, (PrivateKey) key, x509CertificateArr);
        }
        return null;
    }

    private static String getAlias(Match match, String str) {
        return match.builderIndex + "." + match.localAlias + str;
    }

    private static String[] getAliases(List<Match> list, String str) {
        String[] strArr = new String[list.size()];
        int i = 0;
        for (Match match : list) {
            strArr[i] = getAlias(match, str);
            i++;
        }
        return strArr;
    }

    private String[] getAliases(List<String> list, Principal[] principalArr, TransportData transportData, boolean z) {
        int i;
        int i2;
        List<Match> list2;
        ProvX509KeyManager provX509KeyManager = this;
        if (provX509KeyManager.builders.isEmpty() || list.isEmpty()) {
            return null;
        }
        int size = list.size();
        Set<Principal> uniquePrincipals = getUniquePrincipals(principalArr);
        BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
        Date date = new Date();
        String requestedHostName = getRequestedHostName(transportData, z);
        int size2 = provX509KeyManager.builders.size();
        int i3 = 0;
        List<Match> list3 = null;
        while (i3 < size2) {
            try {
                KeyStore.Builder builder = provX509KeyManager.builders.get(i3);
                KeyStore keyStore = builder.getKeyStore();
                if (keyStore == null) {
                    i = i3;
                    i2 = size2;
                } else {
                    Enumeration<String> aliases = keyStore.aliases();
                    List<Match> list4 = list3;
                    while (aliases.hasMoreElements()) {
                        try {
                            list2 = list4;
                            i = i3;
                            i2 = size2;
                        } catch (KeyStoreException e) {
                            e = e;
                            list2 = list4;
                            i = i3;
                            i2 = size2;
                        }
                        try {
                            Match potentialMatch = getPotentialMatch(i3, builder, keyStore, aliases.nextElement(), list, size, uniquePrincipals, algorithmConstraints, z, date, requestedHostName);
                            list4 = potentialMatch.compareTo(Match.NOTHING) < 0 ? addToMatches(list2, potentialMatch) : list2;
                            i3 = i;
                            size2 = i2;
                        } catch (KeyStoreException e2) {
                            e = e2;
                            list3 = list2;
                            LOG.log(Level.WARNING, "Failed to fully process KeyStore.Builder at index " + i, (Throwable) e);
                            i3 = i + 1;
                            provX509KeyManager = this;
                            size2 = i2;
                        }
                    }
                    i = i3;
                    i2 = size2;
                    list3 = list4;
                }
            } catch (KeyStoreException e3) {
                e = e3;
                i = i3;
                i2 = size2;
            }
            i3 = i + 1;
            provX509KeyManager = this;
            size2 = i2;
        }
        if (list3 == null || list3.isEmpty()) {
            return null;
        }
        Collections.sort(list3);
        return getAliases(list3, getNextVersionSuffix());
    }

    private Match getBestMatch(List<String> list, Principal[] principalArr, TransportData transportData, boolean z) {
        int i;
        int i2;
        boolean z2;
        Match match;
        int i3;
        ProvX509KeyManager provX509KeyManager = this;
        Match match2 = Match.NOTHING;
        if (provX509KeyManager.builders.isEmpty() || list.isEmpty()) {
            return match2;
        }
        int size = list.size();
        Set<Principal> uniquePrincipals = getUniquePrincipals(principalArr);
        boolean z3 = true;
        BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
        Date date = new Date();
        String requestedHostName = getRequestedHostName(transportData, z);
        int size2 = provX509KeyManager.builders.size();
        int i4 = 0;
        int i5 = size;
        Match match3 = match2;
        while (i4 < size2) {
            try {
                KeyStore.Builder builder = provX509KeyManager.builders.get(i4);
                KeyStore keyStore = builder.getKeyStore();
                if (keyStore == null) {
                    i = i4;
                    i2 = size2;
                    z2 = z3;
                } else {
                    Enumeration<String> aliases = keyStore.aliases();
                    Match match4 = match3;
                    int i6 = i5;
                    while (aliases.hasMoreElements()) {
                        try {
                            i3 = i6;
                            match = match4;
                            i = i4;
                            i2 = size2;
                        } catch (KeyStoreException e) {
                            e = e;
                            i5 = i6;
                            i = i4;
                            i2 = size2;
                            z2 = z3;
                            match = match4;
                        }
                        try {
                            match4 = getPotentialMatch(i4, builder, keyStore, aliases.nextElement(), list, i6, uniquePrincipals, algorithmConstraints, z, date, requestedHostName);
                            if (match4.compareTo(match) < 0) {
                                try {
                                    if (match4.isIdeal()) {
                                        return match4;
                                    }
                                    if (match4.isValid()) {
                                        z2 = true;
                                        i5 = i3;
                                        try {
                                            i6 = Math.min(i5, match4.keyTypeIndex + 1);
                                        } catch (KeyStoreException e2) {
                                            e = e2;
                                            match3 = match4;
                                            LOG.log(Level.WARNING, "Failed to fully process KeyStore.Builder at index " + i, (Throwable) e);
                                            i4 = i + 1;
                                            provX509KeyManager = this;
                                            z3 = z2;
                                            size2 = i2;
                                        }
                                    } else {
                                        z2 = true;
                                        i6 = i3;
                                    }
                                } catch (KeyStoreException e3) {
                                    e = e3;
                                    i5 = i3;
                                    z2 = true;
                                }
                            } else {
                                z2 = true;
                                i6 = i3;
                                match4 = match;
                            }
                            z3 = z2;
                            i4 = i;
                            size2 = i2;
                        } catch (KeyStoreException e4) {
                            e = e4;
                            i5 = i3;
                            z2 = true;
                            match3 = match;
                            LOG.log(Level.WARNING, "Failed to fully process KeyStore.Builder at index " + i, (Throwable) e);
                            i4 = i + 1;
                            provX509KeyManager = this;
                            z3 = z2;
                            size2 = i2;
                        }
                    }
                    i5 = i6;
                    i = i4;
                    i2 = size2;
                    z2 = z3;
                    match3 = match4;
                }
            } catch (KeyStoreException e5) {
                e = e5;
                i = i4;
                i2 = size2;
                z2 = z3;
            }
            i4 = i + 1;
            provX509KeyManager = this;
            z3 = z2;
            size2 = i2;
        }
        return match3;
    }

    private static MatchQuality getCertificateQuality(X509Certificate x509Certificate, Date date, String str) {
        try {
            x509Certificate.checkValidity(date);
            if (str != null) {
                try {
                    ProvX509TrustManager.checkEndpointID(str, x509Certificate, "HTTPS");
                } catch (CertificateException unused) {
                    return MatchQuality.MISMATCH_SNI;
                }
            }
            if ("RSA".equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(x509Certificate.getPublicKey()))) {
                boolean[] keyUsage = x509Certificate.getKeyUsage();
                if (ProvAlgorithmChecker.supportsKeyUsage(keyUsage, 0) && ProvAlgorithmChecker.supportsKeyUsage(keyUsage, 2)) {
                    return MatchQuality.RSA_MULTI_USE;
                }
            }
            return MatchQuality.OK;
        } catch (CertificateException unused2) {
            return MatchQuality.EXPIRED;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MatchQuality getKeyTypeQuality(boolean z, JcaJceHelper jcaJceHelper, List<String> list, BCAlgorithmConstraints bCAlgorithmConstraints, boolean z2, Date date, String str, X509Certificate[] x509CertificateArr, int i) {
        String str2 = list.get(i);
        Logger logger = LOG;
        logger.finer("EE cert potentially usable for key type: " + str2);
        if (isSuitableChain(z, jcaJceHelper, x509CertificateArr, bCAlgorithmConstraints, z2)) {
            return getCertificateQuality(x509CertificateArr[0], date, str);
        }
        logger.finer("Unsuitable chain for key type: " + str2);
        return MatchQuality.NONE;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<String> getKeyTypes(String... strArr) {
        if (strArr == null || strArr.length <= 0) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList(strArr.length);
        for (String str : strArr) {
            if (str == null) {
                throw new IllegalArgumentException("Key types cannot be null");
            }
            if (!arrayList.contains(str)) {
                arrayList.add(str);
            }
        }
        return Collections.unmodifiableList(arrayList);
    }

    private static String[] getKeyTypesLegacyServer(int... iArr) {
        int length = iArr.length;
        String[] strArr = new String[length];
        for (int i = 0; i < length; i++) {
            strArr[i] = JsseUtils.getKeyTypeLegacyServer(iArr[i]);
        }
        return strArr;
    }

    private String getNextVersionSuffix() {
        return "." + this.versions.incrementAndGet();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getPotentialKeyType(List<String> list, int i, Set<Principal> set, BCAlgorithmConstraints bCAlgorithmConstraints, boolean z, X509Certificate[] x509CertificateArr) {
        if (isSuitableChainForIssuers(x509CertificateArr, set)) {
            return getSuitableKeyTypeForEECert(x509CertificateArr[0], list, i, bCAlgorithmConstraints, z);
        }
        return -1;
    }

    private Match getPotentialMatch(int i, KeyStore.Builder builder, KeyStore keyStore, String str, List<String> list, int i2, Set<Principal> set, BCAlgorithmConstraints bCAlgorithmConstraints, boolean z, Date date, String str2) throws KeyStoreException {
        X509Certificate[] x509CertificateChain;
        int potentialKeyType;
        MatchQuality keyTypeQuality;
        return (!keyStore.isKeyEntry(str) || (potentialKeyType = getPotentialKeyType(list, i2, set, bCAlgorithmConstraints, z, (x509CertificateChain = JsseUtils.getX509CertificateChain(keyStore.getCertificateChain(str))))) < 0 || MatchQuality.NONE == (keyTypeQuality = getKeyTypeQuality(this.isInFipsMode, this.helper, list, bCAlgorithmConstraints, z, date, str2, x509CertificateChain, potentialKeyType))) ? Match.NOTHING : new Match(keyTypeQuality, potentialKeyType, i, str, keyStore, x509CertificateChain);
    }

    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(String str) {
        KeyStore.PrivateKeyEntry privateKeyEntry;
        if (str == null) {
            return null;
        }
        SoftReference<KeyStore.PrivateKeyEntry> softReference = this.cachedEntries.get(str);
        if (softReference == null || (privateKeyEntry = softReference.get()) == null) {
            KeyStore.PrivateKeyEntry loadPrivateKeyEntry = loadPrivateKeyEntry(str);
            if (loadPrivateKeyEntry != null) {
                this.cachedEntries.put(str, new SoftReference<>(loadPrivateKeyEntry));
            }
            return loadPrivateKeyEntry;
        }
        return privateKeyEntry;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String getRequestedHostName(TransportData transportData, boolean z) {
        BCExtendedSSLSession handshakeSession;
        BCSNIHostName sNIHostName;
        if (transportData == null || !z || (handshakeSession = transportData.getHandshakeSession()) == null || (sNIHostName = JsseUtils.getSNIHostName(handshakeSession.getRequestedServerNames())) == null) {
            return null;
        }
        return sNIHostName.getAsciiName();
    }

    private static KeyPurposeId getRequiredExtendedKeyUsage(boolean z) {
        if (provKeyManagerCheckEKU) {
            return z ? KeyPurposeId.id_kp_serverAuth : KeyPurposeId.id_kp_clientAuth;
        }
        return null;
    }

    private static int getSuitableKeyTypeForEECert(X509Certificate x509Certificate, List<String> list, int i, BCAlgorithmConstraints bCAlgorithmConstraints, boolean z) {
        Map<String, PublicKeyFilter> map = z ? FILTERS_SERVER : FILTERS_CLIENT;
        PublicKey publicKey = x509Certificate.getPublicKey();
        boolean[] keyUsage = x509Certificate.getKeyUsage();
        for (int i2 = 0; i2 < i; i2++) {
            PublicKeyFilter publicKeyFilter = map.get(list.get(i2));
            if (publicKeyFilter != null && publicKeyFilter.accepts(publicKey, keyUsage, bCAlgorithmConstraints)) {
                return i2;
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Set<Principal> getUniquePrincipals(Principal[] principalArr) {
        if (principalArr == null) {
            return null;
        }
        if (principalArr.length > 0) {
            HashSet hashSet = new HashSet();
            for (Principal principal : principalArr) {
                if (principal != null) {
                    hashSet.add(principal);
                }
            }
            if (!hashSet.isEmpty()) {
                return Collections.unmodifiableSet(hashSet);
            }
        }
        return Collections.emptySet();
    }

    private static boolean isSuitableChain(boolean z, JcaJceHelper jcaJceHelper, X509Certificate[] x509CertificateArr, BCAlgorithmConstraints bCAlgorithmConstraints, boolean z2) {
        try {
            ProvAlgorithmChecker.checkChain(z, jcaJceHelper, bCAlgorithmConstraints, Collections.emptySet(), x509CertificateArr, getRequiredExtendedKeyUsage(z2), -1);
            return true;
        } catch (CertPathValidatorException e) {
            LOG.log(Level.FINEST, "Certificate chain check failed", (Throwable) e);
            return false;
        }
    }

    private static boolean isSuitableChainForIssuers(X509Certificate[] x509CertificateArr, Set<Principal> set) {
        if (TlsUtils.isNullOrEmpty(x509CertificateArr)) {
            return false;
        }
        if (set == null || set.isEmpty()) {
            return true;
        }
        int length = x509CertificateArr.length;
        do {
            length--;
            if (length < 0) {
                X509Certificate x509Certificate = x509CertificateArr[0];
                return x509Certificate.getBasicConstraints() >= 0 && set.contains(x509Certificate.getSubjectX500Principal());
            }
        } while (!set.contains(x509CertificateArr[length].getIssuerX500Principal()));
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSuitableKeyType(boolean z, String str, X509Certificate x509Certificate, TransportData transportData) {
        PublicKeyFilter publicKeyFilter = (z ? FILTERS_SERVER : FILTERS_CLIENT).get(str);
        if (publicKeyFilter == null) {
            return false;
        }
        return publicKeyFilter.accepts(x509Certificate.getPublicKey(), x509Certificate.getKeyUsage(), TransportData.getAlgorithmConstraints(transportData, true));
    }

    private KeyStore.PrivateKeyEntry loadPrivateKeyEntry(String str) {
        int i;
        int lastIndexOf;
        int parseInt;
        try {
            int indexOf = str.indexOf(46, 0);
            if (indexOf <= 0 || (lastIndexOf = str.lastIndexOf(46)) <= (i = indexOf + 1) || (parseInt = Integer.parseInt(str.substring(0, indexOf))) < 0 || parseInt >= this.builders.size()) {
                return null;
            }
            KeyStore.Builder builder = this.builders.get(parseInt);
            String substring = str.substring(i, lastIndexOf);
            KeyStore keyStore = builder.getKeyStore();
            if (keyStore != null) {
                KeyStore.Entry entry = keyStore.getEntry(substring, builder.getProtectionParameter(substring));
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    return (KeyStore.PrivateKeyEntry) entry;
                }
                return null;
            }
            return null;
        } catch (Exception e) {
            LOG.log(Level.FINER, "Failed to load PrivateKeyEntry: " + str, (Throwable) e);
            return null;
        }
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] strArr, Principal[] principalArr, Socket socket) {
        return chooseAlias(getKeyTypes(strArr), principalArr, TransportData.from(socket), false);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseClientKeyBC(String[] strArr, Principal[] principalArr, Socket socket) {
        return chooseKeyBC(getKeyTypes(strArr), principalArr, TransportData.from(socket), false);
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineClientAlias(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseAlias(getKeyTypes(strArr), principalArr, TransportData.from(sSLEngine), false);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseEngineClientKeyBC(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseKeyBC(getKeyTypes(strArr), principalArr, TransportData.from(sSLEngine), false);
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineServerAlias(String str, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseAlias(getKeyTypes(str), principalArr, TransportData.from(sSLEngine), true);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseEngineServerKeyBC(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseKeyBC(getKeyTypes(strArr), principalArr, TransportData.from(sSLEngine), true);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String str, Principal[] principalArr, Socket socket) {
        return chooseAlias(getKeyTypes(str), principalArr, TransportData.from(socket), true);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseServerKeyBC(String[] strArr, Principal[] principalArr, Socket socket) {
        return chooseKeyBC(getKeyTypes(strArr), principalArr, TransportData.from(socket), true);
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String str) {
        KeyStore.PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(str);
        if (privateKeyEntry == null) {
            return null;
        }
        return (X509Certificate[]) privateKeyEntry.getCertificateChain();
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String str, Principal[] principalArr) {
        return getAliases(getKeyTypes(str), principalArr, null, false);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    protected BCX509Key getKeyBC(String str, String str2) {
        PrivateKey privateKey;
        KeyStore.PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(str2);
        if (privateKeyEntry == null || (privateKey = privateKeyEntry.getPrivateKey()) == null) {
            return null;
        }
        X509Certificate[] x509CertificateChain = JsseUtils.getX509CertificateChain(privateKeyEntry.getCertificateChain());
        if (TlsUtils.isNullOrEmpty(x509CertificateChain)) {
            return null;
        }
        return new ProvX509Key(str, privateKey, x509CertificateChain);
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String str) {
        KeyStore.PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(str);
        if (privateKeyEntry == null) {
            return null;
        }
        return privateKeyEntry.getPrivateKey();
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String str, Principal[] principalArr) {
        return getAliases(getKeyTypes(str), principalArr, null, true);
    }
}