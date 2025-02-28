package org.openjsse.sun.security.util;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.ECParameterSpec;
import java.util.Optional;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/CurveDB.class */
public class CurveDB {
    private static Optional<Method> lookupByName = null;
    private static Optional<Method> lookupByParam = null;
    private static Object lookupByNameLock = new Object();
    private static Object lookupByParamLock = new Object();

    /* JADX INFO: Access modifiers changed from: private */
    public static void makeAccessible(final AccessibleObject o) {
        AccessController.doPrivileged(new PrivilegedAction<Object>() { // from class: org.openjsse.sun.security.util.CurveDB.1
            @Override // java.security.PrivilegedAction
            public Object run() {
                o.setAccessible(true);
                return null;
            }
        });
    }

    public static ECParameterSpec lookup(String name) {
        synchronized (lookupByNameLock) {
            if (lookupByName == null) {
                lookupByName = (Optional) AccessController.doPrivileged(new PrivilegedAction<Object>() { // from class: org.openjsse.sun.security.util.CurveDB.2
                    @Override // java.security.PrivilegedAction
                    /* renamed from: run */
                    public Object run2() {
                        Class clazz;
                        try {
                            try {
                                clazz = Class.forName("sun.security.ec.CurveDB");
                            } catch (ClassNotFoundException e) {
                                clazz = Class.forName("sun.security.util.CurveDB");
                            }
                            Optional<Method> lookupByName2 = Optional.ofNullable(clazz.getDeclaredMethod("lookup", String.class));
                            CurveDB.makeAccessible(lookupByName2.get());
                            return lookupByName2;
                        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException e2) {
                            return Optional.empty();
                        }
                    }
                });
            }
        }
        if (lookupByName.isPresent()) {
            try {
                return (ECParameterSpec) lookupByName.get().invoke(null, name);
            } catch (IllegalAccessException | InvocationTargetException e) {
                return null;
            }
        }
        return null;
    }

    public static ECParameterSpec lookup(ECParameterSpec params) {
        synchronized (lookupByParamLock) {
            if (lookupByParam == null) {
                lookupByParam = (Optional) AccessController.doPrivileged(new PrivilegedAction<Object>() { // from class: org.openjsse.sun.security.util.CurveDB.3
                    @Override // java.security.PrivilegedAction
                    /* renamed from: run */
                    public Object run2() {
                        Class clazz;
                        Optional<Method> lookupByParam2;
                        try {
                            try {
                                clazz = Class.forName("sun.security.ec.CurveDB");
                            } catch (ClassNotFoundException e) {
                                clazz = Class.forName("sun.security.util.CurveDB");
                            }
                            lookupByParam2 = Optional.ofNullable(clazz.getDeclaredMethod("lookup", ECParameterSpec.class));
                            CurveDB.makeAccessible(lookupByParam2.get());
                        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException e2) {
                            lookupByParam2 = Optional.empty();
                        }
                        return lookupByParam2;
                    }
                });
            }
        }
        if (lookupByParam.isPresent()) {
            try {
                return (ECParameterSpec) lookupByParam.get().invoke(null, params);
            } catch (IllegalAccessException | InvocationTargetException e) {
                return null;
            }
        }
        return null;
    }
}