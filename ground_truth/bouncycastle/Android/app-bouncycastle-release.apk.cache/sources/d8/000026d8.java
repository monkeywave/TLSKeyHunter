package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import javax.net.ssl.SSLSession;
import org.bouncycastle.jsse.BCExtendedSSLSession;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class SSLSessionUtil {
    private static final Constructor<? extends SSLSession> exportSSLSessionConstructor;
    private static final Class<?> extendedSSLSessionClass;
    private static final Constructor<? extends BCExtendedSSLSession> importSSLSessionConstructor;

    /* JADX WARN: Removed duplicated region for block: B:30:0x0032 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    static {
        /*
            java.lang.String r0 = "getRequestedServerNames"
            java.lang.String r1 = "javax.net.ssl.ExtendedSSLSession"
            r2 = 0
            java.lang.Class r3 = org.bouncycastle.jsse.provider.ReflectionUtil.getClass(r1)     // Catch: java.lang.Exception -> La
            goto Lb
        La:
            r3 = r2
        Lb:
            org.bouncycastle.jsse.provider.SSLSessionUtil.extendedSSLSessionClass = r3
            r3 = 0
            r4 = 1
            java.lang.reflect.Method[] r5 = org.bouncycastle.jsse.provider.ReflectionUtil.getMethods(r1)     // Catch: java.lang.Exception -> L2b
            if (r5 == 0) goto L2b
            boolean r5 = org.bouncycastle.jsse.provider.ReflectionUtil.hasMethod(r5, r0)     // Catch: java.lang.Exception -> L2b
            if (r5 == 0) goto L1e
            java.lang.String r5 = "org.bouncycastle.jsse.provider.ExportSSLSession_8"
            goto L20
        L1e:
            java.lang.String r5 = "org.bouncycastle.jsse.provider.ExportSSLSession_7"
        L20:
            java.lang.Class[] r6 = new java.lang.Class[r4]     // Catch: java.lang.Exception -> L2b
            java.lang.Class<org.bouncycastle.jsse.BCExtendedSSLSession> r7 = org.bouncycastle.jsse.BCExtendedSSLSession.class
            r6[r3] = r7     // Catch: java.lang.Exception -> L2b
            java.lang.reflect.Constructor r5 = org.bouncycastle.jsse.provider.ReflectionUtil.getDeclaredConstructor(r5, r6)     // Catch: java.lang.Exception -> L2b
            goto L2c
        L2b:
            r5 = r2
        L2c:
            org.bouncycastle.jsse.provider.SSLSessionUtil.exportSSLSessionConstructor = r5
            java.lang.Class<?> r5 = org.bouncycastle.jsse.provider.SSLSessionUtil.extendedSSLSessionClass
            if (r5 == 0) goto L4c
            java.lang.reflect.Method[] r1 = org.bouncycastle.jsse.provider.ReflectionUtil.getMethods(r1)     // Catch: java.lang.Exception -> L4c
            if (r1 == 0) goto L4c
            boolean r0 = org.bouncycastle.jsse.provider.ReflectionUtil.hasMethod(r1, r0)     // Catch: java.lang.Exception -> L4c
            if (r0 == 0) goto L41
            java.lang.String r0 = "org.bouncycastle.jsse.provider.ImportSSLSession_8"
            goto L43
        L41:
            java.lang.String r0 = "org.bouncycastle.jsse.provider.ImportSSLSession_7"
        L43:
            java.lang.Class[] r1 = new java.lang.Class[r4]     // Catch: java.lang.Exception -> L4c
            r1[r3] = r5     // Catch: java.lang.Exception -> L4c
            java.lang.reflect.Constructor r0 = org.bouncycastle.jsse.provider.ReflectionUtil.getDeclaredConstructor(r0, r1)     // Catch: java.lang.Exception -> L4c
            r2 = r0
        L4c:
            org.bouncycastle.jsse.provider.SSLSessionUtil.importSSLSessionConstructor = r2
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.jsse.provider.SSLSessionUtil.<clinit>():void");
    }

    SSLSessionUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SSLSession exportSSLSession(BCExtendedSSLSession bCExtendedSSLSession) {
        if (bCExtendedSSLSession instanceof ImportSSLSession) {
            return ((ImportSSLSession) bCExtendedSSLSession).unwrap();
        }
        Constructor<? extends SSLSession> constructor = exportSSLSessionConstructor;
        if (constructor != null) {
            try {
                return constructor.newInstance(bCExtendedSSLSession);
            } catch (Exception unused) {
            }
        }
        return new ExportSSLSession_5(bCExtendedSSLSession);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BCExtendedSSLSession importSSLSession(SSLSession sSLSession) {
        if (sSLSession instanceof BCExtendedSSLSession) {
            return (BCExtendedSSLSession) sSLSession;
        }
        if (sSLSession instanceof ExportSSLSession) {
            return ((ExportSSLSession) sSLSession).unwrap();
        }
        Constructor<? extends BCExtendedSSLSession> constructor = importSSLSessionConstructor;
        if (constructor != null && extendedSSLSessionClass.isInstance(sSLSession)) {
            try {
                return constructor.newInstance(sSLSession);
            } catch (Exception unused) {
            }
        }
        return new ImportSSLSession_5(sSLSession);
    }
}