package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.util.logging.Logger;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class X509TrustManagerUtil {
    private static final Logger LOG = Logger.getLogger(X509TrustManagerUtil.class.getName());
    private static final Constructor<? extends X509TrustManager> exportX509TrustManagerConstructor;
    private static final Constructor<? extends BCX509ExtendedTrustManager> importX509TrustManagerConstructor;
    private static final Class<?> x509ExtendedTrustManagerClass;

    /* JADX WARN: Removed duplicated region for block: B:19:0x0033 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    static {
        /*
            java.lang.String r0 = "javax.net.ssl.X509ExtendedTrustManager"
            java.lang.Class<org.bouncycastle.jsse.provider.X509TrustManagerUtil> r1 = org.bouncycastle.jsse.provider.X509TrustManagerUtil.class
            java.lang.String r1 = r1.getName()
            java.util.logging.Logger r1 = java.util.logging.Logger.getLogger(r1)
            org.bouncycastle.jsse.provider.X509TrustManagerUtil.LOG = r1
            r1 = 0
            java.lang.Class r2 = org.bouncycastle.jsse.provider.ReflectionUtil.getClass(r0)     // Catch: java.lang.Exception -> L14
            goto L15
        L14:
            r2 = r1
        L15:
            org.bouncycastle.jsse.provider.X509TrustManagerUtil.x509ExtendedTrustManagerClass = r2
            r2 = 0
            r3 = 1
            java.lang.reflect.Method[] r0 = org.bouncycastle.jsse.provider.ReflectionUtil.getMethods(r0)     // Catch: java.lang.Exception -> L2c
            if (r0 == 0) goto L2c
            java.lang.String r0 = "org.bouncycastle.jsse.provider.ExportX509TrustManager_7"
            java.lang.Class[] r4 = new java.lang.Class[r3]     // Catch: java.lang.Exception -> L2c
            java.lang.Class<org.bouncycastle.jsse.BCX509ExtendedTrustManager> r5 = org.bouncycastle.jsse.BCX509ExtendedTrustManager.class
            r4[r2] = r5     // Catch: java.lang.Exception -> L2c
            java.lang.reflect.Constructor r0 = org.bouncycastle.jsse.provider.ReflectionUtil.getDeclaredConstructor(r0, r4)     // Catch: java.lang.Exception -> L2c
            goto L2d
        L2c:
            r0 = r1
        L2d:
            org.bouncycastle.jsse.provider.X509TrustManagerUtil.exportX509TrustManagerConstructor = r0
            java.lang.Class<?> r0 = org.bouncycastle.jsse.provider.X509TrustManagerUtil.x509ExtendedTrustManagerClass
            if (r0 == 0) goto L3d
            java.lang.String r4 = "org.bouncycastle.jsse.provider.ImportX509TrustManager_7"
            java.lang.Class[] r3 = new java.lang.Class[r3]     // Catch: java.lang.Exception -> L3d
            r3[r2] = r0     // Catch: java.lang.Exception -> L3d
            java.lang.reflect.Constructor r1 = org.bouncycastle.jsse.provider.ReflectionUtil.getDeclaredConstructor(r4, r3)     // Catch: java.lang.Exception -> L3d
        L3d:
            org.bouncycastle.jsse.provider.X509TrustManagerUtil.importX509TrustManagerConstructor = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jsse.provider.X509TrustManagerUtil.<clinit>():void");
    }

    X509TrustManagerUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static X509TrustManager exportX509TrustManager(BCX509ExtendedTrustManager bCX509ExtendedTrustManager) {
        if (bCX509ExtendedTrustManager instanceof ImportX509TrustManager) {
            return ((ImportX509TrustManager) bCX509ExtendedTrustManager).unwrap();
        }
        Constructor<? extends X509TrustManager> constructor = exportX509TrustManagerConstructor;
        if (constructor != null) {
            try {
                return constructor.newInstance(bCX509ExtendedTrustManager);
            } catch (Exception unused) {
            }
        }
        return new ExportX509TrustManager_5(bCX509ExtendedTrustManager);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BCX509ExtendedTrustManager importX509TrustManager(boolean z, JcaJceHelper jcaJceHelper, X509TrustManager x509TrustManager) {
        LOG.fine("Importing X509TrustManager implementation: " + x509TrustManager.getClass().getName());
        if (x509TrustManager instanceof BCX509ExtendedTrustManager) {
            return (BCX509ExtendedTrustManager) x509TrustManager;
        }
        if (x509TrustManager instanceof ExportX509TrustManager) {
            return ((ExportX509TrustManager) x509TrustManager).unwrap();
        }
        Constructor<? extends BCX509ExtendedTrustManager> constructor = importX509TrustManagerConstructor;
        if (constructor != null && x509ExtendedTrustManagerClass.isInstance(x509TrustManager)) {
            try {
                return constructor.newInstance(x509TrustManager);
            } catch (Exception unused) {
            }
        }
        return new ImportX509TrustManager_5(z, jcaJceHelper, x509TrustManager);
    }
}