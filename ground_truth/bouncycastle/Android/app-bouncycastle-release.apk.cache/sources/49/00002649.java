package org.bouncycastle.jsse.provider;

import java.security.Key;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

/* loaded from: classes2.dex */
abstract class AbstractAlgorithmConstraints implements BCAlgorithmConstraints {
    protected final AlgorithmDecomposer decomposer;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AbstractAlgorithmConstraints(AlgorithmDecomposer algorithmDecomposer) {
        this.decomposer = algorithmDecomposer;
    }

    protected static Set<String> asSet(String[] strArr) {
        HashSet hashSet = new HashSet();
        if (strArr != null) {
            for (String str : strArr) {
                if (str != null) {
                    hashSet.add(str);
                }
            }
        }
        return hashSet;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static Set<String> asUnmodifiableSet(String[] strArr) {
        if (strArr != null && strArr.length > 0) {
            Set<String> asSet = asSet(strArr);
            if (!asSet.isEmpty()) {
                return Collections.unmodifiableSet(asSet);
            }
        }
        return Collections.emptySet();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void checkAlgorithmName(String str) {
        if (!JsseUtils.isNameSpecified(str)) {
            throw new IllegalArgumentException("No algorithm name specified");
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void checkKey(Key key) {
        if (key == null) {
            throw new NullPointerException("'key' cannot be null");
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void checkPrimitives(Set<BCCryptoPrimitive> set) {
        if (!isPrimitivesSpecified(set)) {
            throw new IllegalArgumentException("No cryptographic primitive specified");
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean containsAnyPartIgnoreCase(Set<String> set, String str) {
        if (set.isEmpty()) {
            return false;
        }
        if (containsIgnoreCase(set, str)) {
            return true;
        }
        AlgorithmDecomposer algorithmDecomposer = this.decomposer;
        if (algorithmDecomposer != null) {
            for (String str2 : algorithmDecomposer.decompose(str)) {
                if (containsIgnoreCase(set, str2)) {
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean containsIgnoreCase(Set<String> set, String str) {
        for (String str2 : set) {
            if (str2.equalsIgnoreCase(str)) {
                return true;
            }
        }
        return false;
    }

    protected boolean isPrimitivesSpecified(Set<BCCryptoPrimitive> set) {
        return (set == null || set.isEmpty()) ? false : true;
    }
}