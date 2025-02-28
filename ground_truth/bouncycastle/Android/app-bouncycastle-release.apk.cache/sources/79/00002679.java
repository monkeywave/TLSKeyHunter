package org.bouncycastle.jsse.provider;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;

/* loaded from: classes2.dex */
class JcaAlgorithmDecomposer implements AlgorithmDecomposer {
    private static final Pattern PATTERN = Pattern.compile("with|and|(?<!padd)in", 2);
    static final JcaAlgorithmDecomposer INSTANCE_JCA = new JcaAlgorithmDecomposer();

    private static void ensureBothIfEither(Set<String> set, String str, String str2) {
        boolean contains = set.contains(str);
        if (set.contains(str2) ^ contains) {
            if (contains) {
                str = str2;
            }
            set.add(str);
        }
    }

    @Override // org.bouncycastle.jsse.provider.AlgorithmDecomposer
    public Set<String> decompose(String str) {
        String[] split;
        String[] split2;
        if (str.indexOf(47) < 0) {
            return Collections.emptySet();
        }
        HashSet hashSet = new HashSet();
        for (String str2 : str.split("/")) {
            if (str2.length() > 0) {
                for (String str3 : PATTERN.split(str2)) {
                    if (str3.length() > 0) {
                        hashSet.add(str3);
                    }
                }
            }
        }
        ensureBothIfEither(hashSet, "SHA1", McElieceCCA2KeyGenParameterSpec.SHA1);
        ensureBothIfEither(hashSet, "SHA224", McElieceCCA2KeyGenParameterSpec.SHA224);
        ensureBothIfEither(hashSet, "SHA256", "SHA-256");
        ensureBothIfEither(hashSet, "SHA384", McElieceCCA2KeyGenParameterSpec.SHA384);
        ensureBothIfEither(hashSet, "SHA512", "SHA-512");
        return hashSet;
    }
}