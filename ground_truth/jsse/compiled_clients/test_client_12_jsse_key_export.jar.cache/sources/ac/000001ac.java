package javassist.util.proxy;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javassist.bytecode.ClassFile;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/SecurityActions.class */
public class SecurityActions extends SecurityManager {
    public static final SecurityActions stack = new SecurityActions();

    SecurityActions() {
    }

    public Class<?> getCallerClass() {
        return getClassContext()[2];
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Method[] getDeclaredMethods(final Class<?> clazz) {
        if (System.getSecurityManager() == null) {
            return clazz.getDeclaredMethods();
        }
        return (Method[]) AccessController.doPrivileged(new PrivilegedAction<Method[]>() { // from class: javassist.util.proxy.SecurityActions.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public Method[] run() {
                return clazz.getDeclaredMethods();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Constructor<?>[] getDeclaredConstructors(final Class<?> clazz) {
        if (System.getSecurityManager() == null) {
            return clazz.getDeclaredConstructors();
        }
        return (Constructor[]) AccessController.doPrivileged(new PrivilegedAction<Constructor<?>[]>() { // from class: javassist.util.proxy.SecurityActions.2
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public Constructor<?>[] run() {
                return clazz.getDeclaredConstructors();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MethodHandle getMethodHandle(final Class<?> clazz, final String name, final Class<?>[] params) throws NoSuchMethodException {
        try {
            return (MethodHandle) AccessController.doPrivileged(new PrivilegedExceptionAction<MethodHandle>() { // from class: javassist.util.proxy.SecurityActions.3
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedExceptionAction
                public MethodHandle run() throws IllegalAccessException, NoSuchMethodException, SecurityException {
                    Method rmet = clazz.getDeclaredMethod(name, params);
                    rmet.setAccessible(true);
                    MethodHandle meth = MethodHandles.lookup().unreflect(rmet);
                    rmet.setAccessible(false);
                    return meth;
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof NoSuchMethodException) {
                throw ((NoSuchMethodException) e.getCause());
            }
            throw new RuntimeException(e.getCause());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Method getDeclaredMethod(final Class<?> clazz, final String name, final Class<?>[] types) throws NoSuchMethodException {
        if (System.getSecurityManager() == null) {
            return clazz.getDeclaredMethod(name, types);
        }
        try {
            return (Method) AccessController.doPrivileged(new PrivilegedExceptionAction<Method>() { // from class: javassist.util.proxy.SecurityActions.4
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedExceptionAction
                public Method run() throws Exception {
                    return clazz.getDeclaredMethod(name, types);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof NoSuchMethodException) {
                throw ((NoSuchMethodException) e.getCause());
            }
            throw new RuntimeException(e.getCause());
        }
    }

    static Constructor<?> getDeclaredConstructor(final Class<?> clazz, final Class<?>[] types) throws NoSuchMethodException {
        if (System.getSecurityManager() == null) {
            return clazz.getDeclaredConstructor(types);
        }
        try {
            return (Constructor) AccessController.doPrivileged(new PrivilegedExceptionAction<Constructor<?>>() { // from class: javassist.util.proxy.SecurityActions.5
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedExceptionAction
                public Constructor<?> run() throws Exception {
                    return clazz.getDeclaredConstructor(types);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof NoSuchMethodException) {
                throw ((NoSuchMethodException) e.getCause());
            }
            throw new RuntimeException(e.getCause());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void setAccessible(final AccessibleObject ao, final boolean accessible) {
        if (System.getSecurityManager() == null) {
            ao.setAccessible(accessible);
        } else {
            AccessController.doPrivileged(new PrivilegedAction<Void>() { // from class: javassist.util.proxy.SecurityActions.6
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedAction
                public Void run() {
                    ao.setAccessible(accessible);
                    return null;
                }
            });
        }
    }

    static void set(final Field fld, final Object target, final Object value) throws IllegalAccessException {
        if (System.getSecurityManager() == null) {
            fld.set(target, value);
            return;
        }
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() { // from class: javassist.util.proxy.SecurityActions.7
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedExceptionAction
                public Void run() throws Exception {
                    fld.set(target, value);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof NoSuchMethodException) {
                throw ((IllegalAccessException) e.getCause());
            }
            throw new RuntimeException(e.getCause());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static TheUnsafe getSunMiscUnsafeAnonymously() throws ClassNotFoundException {
        try {
            return (TheUnsafe) AccessController.doPrivileged(new PrivilegedExceptionAction<TheUnsafe>() { // from class: javassist.util.proxy.SecurityActions.8
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedExceptionAction
                public TheUnsafe run() throws ClassNotFoundException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
                    Class<?> unsafe = Class.forName("sun.misc.Unsafe");
                    Field theUnsafe = unsafe.getDeclaredField("theUnsafe");
                    theUnsafe.setAccessible(true);
                    SecurityActions securityActions = SecurityActions.stack;
                    Objects.requireNonNull(securityActions);
                    TheUnsafe usf = new TheUnsafe(unsafe, theUnsafe.get(null));
                    theUnsafe.setAccessible(false);
                    SecurityActions.disableWarning(usf);
                    return usf;
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof ClassNotFoundException) {
                throw ((ClassNotFoundException) e.getCause());
            }
            if (e.getCause() instanceof NoSuchFieldException) {
                throw new ClassNotFoundException("No such instance.", e.getCause());
            }
            if ((e.getCause() instanceof IllegalAccessException) || (e.getCause() instanceof IllegalAccessException) || (e.getCause() instanceof SecurityException)) {
                throw new ClassNotFoundException("Security denied access.", e.getCause());
            }
            throw new RuntimeException(e.getCause());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/SecurityActions$TheUnsafe.class */
    public class TheUnsafe {
        final Class<?> unsafe;
        final Object theUnsafe;
        final Map<String, List<Method>> methods = new HashMap();

        TheUnsafe(Class<?> c, Object o) {
            Method[] declaredMethods;
            this.unsafe = c;
            this.theUnsafe = o;
            for (Method m : this.unsafe.getDeclaredMethods()) {
                if (!this.methods.containsKey(m.getName())) {
                    this.methods.put(m.getName(), Collections.singletonList(m));
                } else {
                    if (this.methods.get(m.getName()).size() == 1) {
                        this.methods.put(m.getName(), new ArrayList(this.methods.get(m.getName())));
                    }
                    this.methods.get(m.getName()).add(m);
                }
            }
        }

        private Method getM(String name, Object[] o) {
            return this.methods.get(name).get(0);
        }

        public Object call(String name, Object... args) {
            try {
                return getM(name, args).invoke(this.theUnsafe, args);
            } catch (Throwable t) {
                t.printStackTrace();
                return null;
            }
        }
    }

    static void disableWarning(TheUnsafe tu) {
        try {
            if (ClassFile.MAJOR_VERSION < 53) {
                return;
            }
            Class<?> cls = Class.forName("jdk.internal.module.IllegalAccessLogger");
            Field logger = cls.getDeclaredField("logger");
            tu.call("putObjectVolatile", cls, tu.call("staticFieldOffset", logger), null);
        } catch (Exception e) {
        }
    }
}