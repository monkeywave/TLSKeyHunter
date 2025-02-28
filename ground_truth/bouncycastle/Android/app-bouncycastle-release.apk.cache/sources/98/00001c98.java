package org.bouncycastle.crypto.constraints;

import java.util.Set;

/* loaded from: classes2.dex */
class Utils {
    Utils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void addAliases(Set<String> set) {
        if (set.contains("RC4")) {
            set.add("ARC4");
        } else if (set.contains("ARC4")) {
            set.add("RC4");
        }
    }
}