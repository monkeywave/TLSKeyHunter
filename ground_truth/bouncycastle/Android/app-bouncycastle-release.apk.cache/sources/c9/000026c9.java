package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.provider.ProvX509KeyManager;
import org.bouncycastle.tls.TlsUtils;

/* loaded from: classes2.dex */
class ProvX509KeyManagerSimple extends BCX509ExtendedKeyManager {
    private static final Logger LOG = Logger.getLogger(ProvX509KeyManagerSimple.class.getName());
    private final Map<String, Credential> credentials;
    private final JcaJceHelper helper;
    private final boolean isInFipsMode;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static class Credential {
        private final String alias;
        private final X509Certificate[] certificateChain;
        private final PrivateKey privateKey;

        Credential(String str, PrivateKey privateKey, X509Certificate[] x509CertificateArr) {
            this.alias = str;
            this.privateKey = privateKey;
            this.certificateChain = x509CertificateArr;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static final class Match implements Comparable<Match> {
        static final ProvX509KeyManager.MatchQuality INVALID = ProvX509KeyManager.MatchQuality.MISMATCH_SNI;
        static final Match NOTHING = new Match(ProvX509KeyManager.MatchQuality.NONE, Integer.MAX_VALUE, null);
        final Credential credential;
        final int keyTypeIndex;
        final ProvX509KeyManager.MatchQuality quality;

        Match(ProvX509KeyManager.MatchQuality matchQuality, int i, Credential credential) {
            this.quality = matchQuality;
            this.keyTypeIndex = i;
            this.credential = credential;
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
            return ProvX509KeyManager.MatchQuality.OK == this.quality && this.keyTypeIndex == 0;
        }

        boolean isValid() {
            return this.quality.compareTo(INVALID) < 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvX509KeyManagerSimple(boolean z, JcaJceHelper jcaJceHelper, KeyStore keyStore, char[] cArr) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.isInFipsMode = z;
        this.helper = jcaJceHelper;
        this.credentials = loadCredentials(keyStore, cArr);
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
        String alias = getAlias(bestMatch);
        Logger logger = LOG;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine("Found matching key of type: " + str + ", returning alias: " + alias);
        }
        return alias;
    }

    private BCX509Key chooseKeyBC(List<String> list, Principal[] principalArr, TransportData transportData, boolean z) {
        String str;
        BCX509Key createKeyBC;
        Match bestMatch = getBestMatch(list, principalArr, transportData, z);
        if (bestMatch.compareTo(Match.NOTHING) >= 0 || (createKeyBC = createKeyBC((str = list.get(bestMatch.keyTypeIndex)), bestMatch.credential)) == null) {
            LOG.fine("No matching key found");
            return null;
        }
        Logger logger = LOG;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine("Found matching key of type: " + str + ", from alias: " + getAlias(bestMatch));
        }
        return createKeyBC;
    }

    private BCX509Key createKeyBC(String str, Credential credential) {
        if (credential == null) {
            return null;
        }
        return new ProvX509Key(str, credential.privateKey, credential.certificateChain);
    }

    private static String getAlias(Match match) {
        return match.credential.alias;
    }

    private static String[] getAliases(List<Match> list) {
        String[] strArr = new String[list.size()];
        int i = 0;
        for (Match match : list) {
            strArr[i] = getAlias(match);
            i++;
        }
        return strArr;
    }

    private String[] getAliases(List<String> list, Principal[] principalArr, TransportData transportData, boolean z) {
        if (this.credentials.isEmpty() || list.isEmpty()) {
            return null;
        }
        int size = list.size();
        Set<Principal> uniquePrincipals = ProvX509KeyManager.getUniquePrincipals(principalArr);
        BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
        Date date = new Date();
        String requestedHostName = ProvX509KeyManager.getRequestedHostName(transportData, z);
        List<Match> list2 = null;
        for (Credential credential : this.credentials.values()) {
            List<Match> list3 = list2;
            Match potentialMatch = getPotentialMatch(credential, list, size, uniquePrincipals, algorithmConstraints, z, date, requestedHostName);
            list2 = potentialMatch.compareTo(Match.NOTHING) < 0 ? addToMatches(list3, potentialMatch) : list3;
        }
        List<Match> list4 = list2;
        if (list4 == null || list4.isEmpty()) {
            return null;
        }
        Collections.sort(list4);
        return getAliases(list4);
    }

    private Match getBestMatch(List<String> list, Principal[] principalArr, TransportData transportData, boolean z) {
        boolean z2;
        Match match = Match.NOTHING;
        if (this.credentials.isEmpty() || list.isEmpty()) {
            return match;
        }
        int size = list.size();
        Set<Principal> uniquePrincipals = ProvX509KeyManager.getUniquePrincipals(principalArr);
        BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
        Date date = new Date();
        String requestedHostName = ProvX509KeyManager.getRequestedHostName(transportData, z);
        Match match2 = match;
        int i = size;
        for (Credential credential : this.credentials.values()) {
            int i2 = i;
            Match match3 = match2;
            match2 = getPotentialMatch(credential, list, i, uniquePrincipals, algorithmConstraints, z, date, requestedHostName);
            if (match2.compareTo(match3) >= 0) {
                z2 = true;
                i = i2;
                match2 = match3;
            } else if (match2.isIdeal()) {
                return match2;
            } else {
                if (match2.isValid()) {
                    z2 = true;
                    i = Math.min(i2, match2.keyTypeIndex + 1);
                } else {
                    z2 = true;
                    i = i2;
                }
            }
        }
        return match2;
    }

    private Credential getCredential(String str) {
        if (str == null) {
            return null;
        }
        return this.credentials.get(str);
    }

    private Match getPotentialMatch(Credential credential, List<String> list, int i, Set<Principal> set, BCAlgorithmConstraints bCAlgorithmConstraints, boolean z, Date date, String str) {
        ProvX509KeyManager.MatchQuality keyTypeQuality;
        X509Certificate[] x509CertificateArr = credential.certificateChain;
        int potentialKeyType = ProvX509KeyManager.getPotentialKeyType(list, i, set, bCAlgorithmConstraints, z, x509CertificateArr);
        return (potentialKeyType < 0 || ProvX509KeyManager.MatchQuality.NONE == (keyTypeQuality = ProvX509KeyManager.getKeyTypeQuality(this.isInFipsMode, this.helper, list, bCAlgorithmConstraints, z, date, str, x509CertificateArr, potentialKeyType))) ? Match.NOTHING : new Match(keyTypeQuality, potentialKeyType, credential);
    }

    private static Map<String, Credential> loadCredentials(KeyStore keyStore, char[] cArr) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        PrivateKey privateKey;
        HashMap hashMap = new HashMap(4);
        if (keyStore != null) {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String nextElement = aliases.nextElement();
                if (keyStore.entryInstanceOf(nextElement, KeyStore.PrivateKeyEntry.class) && (privateKey = (PrivateKey) keyStore.getKey(nextElement, cArr)) != null) {
                    X509Certificate[] x509CertificateChain = JsseUtils.getX509CertificateChain(keyStore.getCertificateChain(nextElement));
                    if (!TlsUtils.isNullOrEmpty(x509CertificateChain)) {
                        hashMap.put(nextElement, new Credential(nextElement, privateKey, x509CertificateChain));
                    }
                }
            }
        }
        return Collections.unmodifiableMap(hashMap);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] strArr, Principal[] principalArr, Socket socket) {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(strArr), principalArr, TransportData.from(socket), false);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseClientKeyBC(String[] strArr, Principal[] principalArr, Socket socket) {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(strArr), principalArr, TransportData.from(socket), false);
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineClientAlias(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(strArr), principalArr, TransportData.from(sSLEngine), false);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseEngineClientKeyBC(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(strArr), principalArr, TransportData.from(sSLEngine), false);
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineServerAlias(String str, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(str), principalArr, TransportData.from(sSLEngine), true);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseEngineServerKeyBC(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(strArr), principalArr, TransportData.from(sSLEngine), true);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String str, Principal[] principalArr, Socket socket) {
        return chooseAlias(ProvX509KeyManager.getKeyTypes(str), principalArr, TransportData.from(socket), true);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    public BCX509Key chooseServerKeyBC(String[] strArr, Principal[] principalArr, Socket socket) {
        return chooseKeyBC(ProvX509KeyManager.getKeyTypes(strArr), principalArr, TransportData.from(socket), true);
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String str) {
        Credential credential = getCredential(str);
        if (credential == null) {
            return null;
        }
        return (X509Certificate[]) credential.certificateChain.clone();
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String str, Principal[] principalArr) {
        return getAliases(ProvX509KeyManager.getKeyTypes(str), principalArr, null, false);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedKeyManager
    protected BCX509Key getKeyBC(String str, String str2) {
        return createKeyBC(str, getCredential(str2));
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String str) {
        Credential credential = getCredential(str);
        if (credential == null) {
            return null;
        }
        return credential.privateKey;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String str, Principal[] principalArr) {
        return getAliases(ProvX509KeyManager.getKeyTypes(str), principalArr, null, true);
    }
}