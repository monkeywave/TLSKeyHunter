package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ReflectionUtil {
    ReflectionUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Method findMethod(Method[] methodArr, String str) {
        if (methodArr != null) {
            for (Method method : methodArr) {
                if (method.getName().equals(str)) {
                    return method;
                }
            }
            return null;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Class<?> getClass(final String str) {
        if (str == null) {
            return null;
        }
        return (Class) AccessController.doPrivileged(new PrivilegedAction<Class<?>>() { // from class: org.bouncycastle.jsse.provider.ReflectionUtil.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public Class<?> run() {
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    return classLoader == null ? Class.forName(str) : classLoader.loadClass(str);
                } catch (Exception unused) {
                    return null;
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static <T> Constructor<T> getDeclaredConstructor(final String str, final Class<?>... clsArr) {
        if (str == null) {
            return null;
        }
        return (Constructor) AccessController.doPrivileged(new PrivilegedAction<Constructor<T>>() { // from class: org.bouncycastle.jsse.provider.ReflectionUtil.2
            @Override // java.security.PrivilegedAction
            public Constructor<T> run() {
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> cls = classLoader == null ? Class.forName(str) : classLoader.loadClass(str);
                    if (cls != null) {
                        return (Constructor<T>) cls.getDeclaredConstructor(clsArr);
                    }
                    return null;
                } catch (Exception unused) {
                    return null;
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Method getMethod(final String str, final String str2, final Class<?>... clsArr) {
        if (str == null || str2 == null) {
            return null;
        }
        return (Method) AccessController.doPrivileged(new PrivilegedAction<Method>() { // from class: org.bouncycastle.jsse.provider.ReflectionUtil.3
            @Override // java.security.PrivilegedAction
            public Method run() {
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> cls = classLoader == null ? Class.forName(str) : classLoader.loadClass(str);
                    if (cls != null) {
                        return cls.getMethod(str2, clsArr);
                    }
                    return null;
                } catch (Exception unused) {
                    return null;
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Method[] getMethods(final String str) {
        if (str == null) {
            return null;
        }
        return (Method[]) AccessController.doPrivileged(new PrivilegedAction<Method[]>() { // from class: org.bouncycastle.jsse.provider.ReflectionUtil.4
            @Override // java.security.PrivilegedAction
            public Method[] run() {
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> cls = classLoader == null ? Class.forName(str) : classLoader.loadClass(str);
                    if (cls != null) {
                        return cls.getMethods();
                    }
                    return null;
                } catch (Exception unused) {
                    return null;
                }
            }
        });
    }

    static Integer getStaticInt(final String str, final String str2) {
        return (Integer) AccessController.doPrivileged(new PrivilegedAction<Integer>() { // from class: org.bouncycastle.jsse.provider.ReflectionUtil.5
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public Integer run() {
                Field field;
                try {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> cls = classLoader == null ? Class.forName(str) : classLoader.loadClass(str);
                    if (cls == null || (field = cls.getField(str2)) == null) {
                        return null;
                    }
                    if (Integer.TYPE == field.getType()) {
                        return Integer.valueOf(field.getInt(null));
                    }
                    return null;
                } catch (Exception unused) {
                    return null;
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Integer getStaticIntOrDefault(String str, String str2, int i) {
        Integer staticInt = getStaticInt(str, str2);
        if (staticInt != null) {
            i = staticInt.intValue();
        }
        return Integer.valueOf(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean hasMethod(Method[] methodArr, String str) {
        return findMethod(methodArr, str) != null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object invokeGetter(Object obj, Method method) {
        return invokeMethod(obj, method, new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object invokeMethod(final Object obj, final Method method, final Object... objArr) {
        return AccessController.doPrivileged(new PrivilegedAction<Object>() { // from class: org.bouncycastle.jsse.provider.ReflectionUtil.6
            @Override // java.security.PrivilegedAction
            public Object run() {
                try {
                    return method.invoke(obj, objArr);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                } catch (InvocationTargetException e2) {
                    throw new RuntimeException(e2);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void invokeSetter(Object obj, Method method, Object obj2) {
        invokeMethod(obj, method, obj2);
    }
}