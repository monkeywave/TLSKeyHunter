package org.openjsse.sun.security.ssl;

import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SunX509KeyManagerImpl.class */
final class SunX509KeyManagerImpl extends X509ExtendedKeyManager {
    private static final String[] STRING0 = new String[0];
    private Map<String, X509Credentials> credentialsMap = new HashMap();
    private final Map<String, String[]> serverAliasCache = Collections.synchronizedMap(new HashMap());

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SunX509KeyManagerImpl$X509Credentials.class */
    public static class X509Credentials {
        PrivateKey privateKey;
        X509Certificate[] certificates;
        private Set<X500Principal> issuerX500Principals;

        X509Credentials(PrivateKey privateKey, X509Certificate[] certificates) {
            this.privateKey = privateKey;
            this.certificates = certificates;
        }

        synchronized Set<X500Principal> getIssuerX500Principals() {
            if (this.issuerX500Principals == null) {
                this.issuerX500Principals = new HashSet();
                for (int i = 0; i < this.certificates.length; i++) {
                    this.issuerX500Principals.add(this.certificates[i].getIssuerX500Principal());
                }
            }
            return this.issuerX500Principals;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SunX509KeyManagerImpl(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (ks == null) {
            return;
        }
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                Key key = ks.getKey(alias, password);
                if (key instanceof PrivateKey) {
                    Certificate[] certs = ks.getCertificateChain(alias);
                    if (certs != null && certs.length != 0 && (certs[0] instanceof X509Certificate)) {
                        if (!(certs instanceof X509Certificate[])) {
                            Certificate[] certificateArr = new X509Certificate[certs.length];
                            System.arraycopy(certs, 0, certificateArr, 0, certs.length);
                            certs = certificateArr;
                        }
                        X509Credentials cred = new X509Credentials((PrivateKey) key, (X509Certificate[]) certs);
                        this.credentialsMap.put(alias, cred);
                        if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                            SSLLogger.fine("found key for : " + alias, certs);
                        }
                    }
                }
            }
        }
    }

    @Override // javax.net.ssl.X509KeyManager
    public X509Certificate[] getCertificateChain(String alias) {
        X509Credentials cred;
        if (alias == null || (cred = this.credentialsMap.get(alias)) == null) {
            return null;
        }
        return (X509Certificate[]) cred.certificates.clone();
    }

    @Override // javax.net.ssl.X509KeyManager
    public PrivateKey getPrivateKey(String alias) {
        X509Credentials cred;
        if (alias == null || (cred = this.credentialsMap.get(alias)) == null) {
            return null;
        }
        return cred.privateKey;
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        if (keyTypes == null) {
            return null;
        }
        for (String str : keyTypes) {
            String[] aliases = getClientAliases(str, issuers);
            if (aliases != null && aliases.length > 0) {
                return aliases[0];
            }
        }
        return null;
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return chooseClientAlias(keyType, issuers, null);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        String[] aliases;
        if (keyType == null) {
            return null;
        }
        if (issuers == null || issuers.length == 0) {
            aliases = this.serverAliasCache.get(keyType);
            if (aliases == null) {
                aliases = getServerAliases(keyType, issuers);
                if (aliases == null) {
                    aliases = STRING0;
                }
                this.serverAliasCache.put(keyType, aliases);
            }
        } else {
            aliases = getServerAliases(keyType, issuers);
        }
        if (aliases != null && aliases.length > 0) {
            return aliases[0];
        }
        return null;
    }

    @Override // javax.net.ssl.X509ExtendedKeyManager
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return chooseServerAlias(keyType, issuers, null);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType, issuers);
    }

    @Override // javax.net.ssl.X509KeyManager
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAliases(keyType, issuers);
    }

    private String[] getAliases(String keyType, Principal[] issuers) {
        String sigType;
        if (keyType == null) {
            return null;
        }
        if (issuers == null) {
            issuers = new X500Principal[0];
        }
        if (!(issuers instanceof X500Principal[])) {
            issuers = convertPrincipals(issuers);
        }
        if (keyType.contains("_")) {
            int k = keyType.indexOf(95);
            sigType = keyType.substring(k + 1);
            keyType = keyType.substring(0, k);
        } else {
            sigType = null;
        }
        X500Principal[] x500Issuers = (X500Principal[]) issuers;
        List<String> aliases = new ArrayList<>();
        for (Map.Entry<String, X509Credentials> entry : this.credentialsMap.entrySet()) {
            String alias = entry.getKey();
            X509Credentials credentials = entry.getValue();
            X509Certificate[] certs = credentials.certificates;
            if (keyType.equals(certs[0].getPublicKey().getAlgorithm())) {
                if (sigType != null) {
                    if (certs.length > 1) {
                        if (!sigType.equals(certs[1].getPublicKey().getAlgorithm())) {
                        }
                    } else {
                        String sigAlgName = certs[0].getSigAlgName().toUpperCase(Locale.ENGLISH);
                        String pattern = "WITH" + sigType.toUpperCase(Locale.ENGLISH);
                        if (!sigAlgName.contains(pattern)) {
                        }
                    }
                }
                if (issuers.length == 0) {
                    aliases.add(alias);
                    if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                        SSLLogger.fine("matching alias: " + alias, new Object[0]);
                    }
                } else {
                    Set<X500Principal> certIssuers = credentials.getIssuerX500Principals();
                    int i = 0;
                    while (true) {
                        if (i >= x500Issuers.length) {
                            break;
                        } else if (!certIssuers.contains(issuers[i])) {
                            i++;
                        } else {
                            aliases.add(alias);
                            if (SSLLogger.isOn && SSLLogger.isOn("keymanager")) {
                                SSLLogger.fine("matching alias: " + alias, new Object[0]);
                            }
                        }
                    }
                }
            }
        }
        String[] aliasStrings = (String[]) aliases.toArray(STRING0);
        if (aliasStrings.length == 0) {
            return null;
        }
        return aliasStrings;
    }

    private static X500Principal[] convertPrincipals(Principal[] principals) {
        List<X500Principal> list = new ArrayList<>(principals.length);
        for (Principal p : principals) {
            if (p instanceof X500Principal) {
                list.add((X500Principal) p);
            } else {
                try {
                    list.add(new X500Principal(p.getName()));
                } catch (IllegalArgumentException e) {
                }
            }
        }
        return (X500Principal[]) list.toArray(new X500Principal[list.size()]);
    }
}