package org.bouncycastle.jsse;

import java.net.Socket;
import java.security.Principal;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/* loaded from: classes2.dex */
public abstract class BCX509ExtendedKeyManager extends X509ExtendedKeyManager {
    public BCX509Key chooseClientKeyBC(String[] strArr, Principal[] principalArr, Socket socket) {
        BCX509Key validateKeyBC;
        if (strArr != null) {
            for (String str : strArr) {
                String chooseClientAlias = chooseClientAlias(new String[]{str}, principalArr, socket);
                if (chooseClientAlias != null && (validateKeyBC = validateKeyBC(false, str, chooseClientAlias, socket)) != null) {
                    return validateKeyBC;
                }
            }
            return null;
        }
        return null;
    }

    public BCX509Key chooseEngineClientKeyBC(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        BCX509Key validateKeyBC;
        if (strArr != null) {
            for (String str : strArr) {
                String chooseEngineClientAlias = chooseEngineClientAlias(new String[]{str}, principalArr, sSLEngine);
                if (chooseEngineClientAlias != null && (validateKeyBC = validateKeyBC(false, str, chooseEngineClientAlias, sSLEngine)) != null) {
                    return validateKeyBC;
                }
            }
            return null;
        }
        return null;
    }

    public BCX509Key chooseEngineServerKeyBC(String[] strArr, Principal[] principalArr, SSLEngine sSLEngine) {
        BCX509Key validateKeyBC;
        if (strArr != null) {
            for (String str : strArr) {
                String chooseEngineServerAlias = chooseEngineServerAlias(str, principalArr, sSLEngine);
                if (chooseEngineServerAlias != null && (validateKeyBC = validateKeyBC(true, str, chooseEngineServerAlias, sSLEngine)) != null) {
                    return validateKeyBC;
                }
            }
            return null;
        }
        return null;
    }

    public BCX509Key chooseServerKeyBC(String[] strArr, Principal[] principalArr, Socket socket) {
        BCX509Key validateKeyBC;
        if (strArr != null) {
            for (String str : strArr) {
                String chooseServerAlias = chooseServerAlias(str, principalArr, socket);
                if (chooseServerAlias != null && (validateKeyBC = validateKeyBC(true, str, chooseServerAlias, socket)) != null) {
                    return validateKeyBC;
                }
            }
            return null;
        }
        return null;
    }

    protected abstract BCX509Key getKeyBC(String str, String str2);

    protected BCX509Key validateKeyBC(boolean z, String str, String str2, Socket socket) {
        return getKeyBC(str, str2);
    }

    protected BCX509Key validateKeyBC(boolean z, String str, String str2, SSLEngine sSLEngine) {
        return getKeyBC(str, str2);
    }
}