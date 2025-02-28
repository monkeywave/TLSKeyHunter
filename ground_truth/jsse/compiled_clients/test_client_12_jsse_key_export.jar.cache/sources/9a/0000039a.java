package org.bouncycastle.crypto;

import java.security.Permission;
import java.util.HashSet;
import java.util.Set;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/CryptoServicesPermission.class */
public class CryptoServicesPermission extends Permission {
    public static final String GLOBAL_CONFIG = "globalConfig";
    public static final String THREAD_LOCAL_CONFIG = "threadLocalConfig";
    public static final String DEFAULT_RANDOM = "defaultRandomConfig";
    private final Set<String> actions;

    public CryptoServicesPermission(String str) {
        super(str);
        this.actions = new HashSet();
        this.actions.add(str);
    }

    @Override // java.security.Permission
    public boolean implies(Permission permission) {
        if (permission instanceof CryptoServicesPermission) {
            CryptoServicesPermission cryptoServicesPermission = (CryptoServicesPermission) permission;
            return getName().equals(cryptoServicesPermission.getName()) || this.actions.containsAll(cryptoServicesPermission.actions);
        }
        return false;
    }

    public boolean equals(Object obj) {
        return (obj instanceof CryptoServicesPermission) && this.actions.equals(((CryptoServicesPermission) obj).actions);
    }

    public int hashCode() {
        return this.actions.hashCode();
    }

    @Override // java.security.Permission
    public String getActions() {
        return this.actions.toString();
    }
}