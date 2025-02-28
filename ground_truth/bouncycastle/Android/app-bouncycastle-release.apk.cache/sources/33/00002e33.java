package org.bouncycastle.tls.crypto.impl.jcajce;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Integers;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class GCMUtil {
    static final Constructor<AlgorithmParameterSpec> gcmParameterSpec = getConstructor();

    GCMUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AlgorithmParameterSpec createGCMParameterSpec(final int i, final byte[] bArr) throws Exception {
        if (gcmParameterSpec != null) {
            return (AlgorithmParameterSpec) AccessController.doPrivileged(new PrivilegedExceptionAction<AlgorithmParameterSpec>() { // from class: org.bouncycastle.tls.crypto.impl.jcajce.GCMUtil.1
                @Override // java.security.PrivilegedExceptionAction
                public AlgorithmParameterSpec run() throws Exception {
                    return GCMUtil.gcmParameterSpec.newInstance(Integers.valueOf(i), bArr);
                }
            });
        }
        throw new IllegalStateException();
    }

    private static Constructor<AlgorithmParameterSpec> getConstructor() {
        return (Constructor) AccessController.doPrivileged(new PrivilegedAction<Constructor<AlgorithmParameterSpec>>() { // from class: org.bouncycastle.tls.crypto.impl.jcajce.GCMUtil.2
            @Override // java.security.PrivilegedAction
            public Constructor<AlgorithmParameterSpec> run() {
                try {
                    ClassLoader classLoader = GCMUtil.class.getClassLoader();
                    if (classLoader == null) {
                        classLoader = ClassLoader.getSystemClassLoader();
                    }
                    Class<?> loadClass = classLoader.loadClass("javax.crypto.spec.GCMParameterSpec");
                    if (loadClass == null || !AlgorithmParameterSpec.class.isAssignableFrom(loadClass)) {
                        return null;
                    }
                    return loadClass.getConstructor(Integer.TYPE, byte[].class);
                } catch (Exception unused) {
                    return null;
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isGCMParameterSpecAvailable() {
        return gcmParameterSpec != null;
    }
}