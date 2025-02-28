package org.bouncycastle.util;

/* loaded from: classes2.dex */
public class Objects {
    public static boolean areEqual(Object obj, Object obj2) {
        return obj == obj2 || !(obj == null || obj2 == null || !obj.equals(obj2));
    }

    public static int hashCode(Object obj) {
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }
}