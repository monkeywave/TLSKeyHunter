package org.bouncycastle.jsse;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.TlsUtils;

/* loaded from: classes2.dex */
public final class BCSSLParameters {
    private BCAlgorithmConstraints algorithmConstraints;
    private String[] cipherSuites;
    private String endpointIdentificationAlgorithm;
    private boolean needClientAuth;
    private String[] protocols;
    private List<BCSNIServerName> serverNames;
    private List<BCSNIMatcher> sniMatchers;
    private boolean useCipherSuitesOrder;
    private boolean wantClientAuth;
    private boolean enableRetransmissions = true;
    private int maximumPacketSize = 0;
    private String[] applicationProtocols = TlsUtils.EMPTY_STRINGS;
    private String[] signatureSchemes = null;
    private String[] signatureSchemesCert = null;
    private String[] namedGroups = null;

    public BCSSLParameters() {
    }

    public BCSSLParameters(String[] strArr) {
        setCipherSuites(strArr);
    }

    public BCSSLParameters(String[] strArr, String[] strArr2) {
        setCipherSuites(strArr);
        setProtocols(strArr2);
    }

    private static <T> List<T> copyList(Collection<T> collection) {
        if (collection == null) {
            return null;
        }
        return collection.isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList(collection));
    }

    public BCAlgorithmConstraints getAlgorithmConstraints() {
        return this.algorithmConstraints;
    }

    public String[] getApplicationProtocols() {
        return TlsUtils.clone(this.applicationProtocols);
    }

    public String[] getCipherSuites() {
        return TlsUtils.clone(this.cipherSuites);
    }

    public boolean getEnableRetransmissions() {
        return this.enableRetransmissions;
    }

    public String getEndpointIdentificationAlgorithm() {
        return this.endpointIdentificationAlgorithm;
    }

    public int getMaximumPacketSize() {
        return this.maximumPacketSize;
    }

    public String[] getNamedGroups() {
        return TlsUtils.clone(this.namedGroups);
    }

    public boolean getNeedClientAuth() {
        return this.needClientAuth;
    }

    public String[] getProtocols() {
        return TlsUtils.clone(this.protocols);
    }

    public Collection<BCSNIMatcher> getSNIMatchers() {
        return copyList(this.sniMatchers);
    }

    public List<BCSNIServerName> getServerNames() {
        return copyList(this.serverNames);
    }

    public String[] getSignatureSchemes() {
        return TlsUtils.clone(this.signatureSchemes);
    }

    public String[] getSignatureSchemesCert() {
        return TlsUtils.clone(this.signatureSchemesCert);
    }

    public boolean getUseCipherSuitesOrder() {
        return this.useCipherSuitesOrder;
    }

    public boolean getWantClientAuth() {
        return this.wantClientAuth;
    }

    public void setAlgorithmConstraints(BCAlgorithmConstraints bCAlgorithmConstraints) {
        this.algorithmConstraints = bCAlgorithmConstraints;
    }

    public void setApplicationProtocols(String[] strArr) {
        if (strArr == null) {
            throw new NullPointerException("'applicationProtocols' cannot be null");
        }
        String[] clone = TlsUtils.clone(strArr);
        for (String str : clone) {
            if (TlsUtils.isNullOrEmpty(str)) {
                throw new IllegalArgumentException("'applicationProtocols' entries cannot be null or empty strings");
            }
        }
        this.applicationProtocols = clone;
    }

    public void setCipherSuites(String[] strArr) {
        this.cipherSuites = TlsUtils.clone(strArr);
    }

    public void setEnableRetransmissions(boolean z) {
        this.enableRetransmissions = z;
    }

    public void setEndpointIdentificationAlgorithm(String str) {
        this.endpointIdentificationAlgorithm = str;
    }

    public void setMaximumPacketSize(int i) {
        if (i < 0) {
            throw new IllegalArgumentException("The maximum packet size cannot be negative");
        }
        this.maximumPacketSize = i;
    }

    public void setNamedGroups(String[] strArr) {
        String[] strArr2;
        if (strArr != null) {
            strArr2 = TlsUtils.clone(strArr);
            HashSet hashSet = new HashSet();
            for (String str : strArr2) {
                if (TlsUtils.isNullOrEmpty(str)) {
                    throw new IllegalArgumentException("'namedGroups' entries cannot be null or empty strings");
                }
                if (!hashSet.add(str)) {
                    throw new IllegalArgumentException("'namedGroups' contains duplicate entry: " + str);
                }
            }
        } else {
            strArr2 = null;
        }
        this.namedGroups = strArr2;
    }

    public void setNeedClientAuth(boolean z) {
        this.needClientAuth = z;
        this.wantClientAuth = false;
    }

    public void setProtocols(String[] strArr) {
        this.protocols = TlsUtils.clone(strArr);
    }

    public void setSNIMatchers(Collection<BCSNIMatcher> collection) {
        List<BCSNIMatcher> copyList;
        if (collection == null) {
            copyList = null;
        } else {
            copyList = copyList(collection);
            HashSet hashSet = new HashSet();
            for (BCSNIMatcher bCSNIMatcher : copyList) {
                int type = bCSNIMatcher.getType();
                if (!hashSet.add(Integer.valueOf(type))) {
                    throw new IllegalArgumentException("Found duplicate SNI matcher entry of type " + type);
                }
            }
        }
        this.sniMatchers = copyList;
    }

    public void setServerNames(List<BCSNIServerName> list) {
        List<BCSNIServerName> copyList;
        if (list == null) {
            copyList = null;
        } else {
            copyList = copyList(list);
            HashSet hashSet = new HashSet();
            for (BCSNIServerName bCSNIServerName : copyList) {
                int type = bCSNIServerName.getType();
                if (!hashSet.add(Integer.valueOf(type))) {
                    throw new IllegalArgumentException("Found duplicate SNI server name entry of type " + type);
                }
            }
        }
        this.serverNames = copyList;
    }

    public void setSignatureSchemes(String[] strArr) {
        String[] strArr2;
        if (strArr != null) {
            strArr2 = TlsUtils.clone(strArr);
            for (String str : strArr2) {
                if (TlsUtils.isNullOrEmpty(str)) {
                    throw new IllegalArgumentException("'signatureSchemes' entries cannot be null or empty strings");
                }
            }
        } else {
            strArr2 = null;
        }
        this.signatureSchemes = strArr2;
    }

    public void setSignatureSchemesCert(String[] strArr) {
        String[] strArr2;
        if (strArr != null) {
            strArr2 = TlsUtils.clone(strArr);
            for (String str : strArr2) {
                if (TlsUtils.isNullOrEmpty(str)) {
                    throw new IllegalArgumentException("'signatureSchemesCert' entries cannot be null or empty strings");
                }
            }
        } else {
            strArr2 = null;
        }
        this.signatureSchemesCert = strArr2;
    }

    public void setUseCipherSuitesOrder(boolean z) {
        this.useCipherSuitesOrder = z;
    }

    public void setWantClientAuth(boolean z) {
        this.wantClientAuth = z;
        this.needClientAuth = false;
    }
}