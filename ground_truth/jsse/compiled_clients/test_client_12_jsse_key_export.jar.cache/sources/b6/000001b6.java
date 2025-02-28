package javassist.util.proxy;

import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/SerializedProxy.class */
class SerializedProxy implements Serializable {
    private static final long serialVersionUID = 1;
    private String superClass;
    private String[] interfaces;
    private byte[] filterSignature;
    private MethodHandler handler;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SerializedProxy(Class<?> proxy, byte[] sig, MethodHandler h) {
        this.filterSignature = sig;
        this.handler = h;
        this.superClass = proxy.getSuperclass().getName();
        Class<?>[] infs = proxy.getInterfaces();
        int n = infs.length;
        this.interfaces = new String[n - 1];
        String setterInf = ProxyObject.class.getName();
        String setterInf2 = Proxy.class.getName();
        for (int i = 0; i < n; i++) {
            String name = infs[i].getName();
            if (!name.equals(setterInf) && !name.equals(setterInf2)) {
                this.interfaces[i] = name;
            }
        }
    }

    protected Class<?> loadClass(final String className) throws ClassNotFoundException {
        try {
            return (Class) AccessController.doPrivileged(new PrivilegedExceptionAction<Class<?>>() { // from class: javassist.util.proxy.SerializedProxy.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedExceptionAction
                public Class<?> run() throws Exception {
                    ClassLoader cl = Thread.currentThread().getContextClassLoader();
                    return Class.forName(className, true, cl);
                }
            });
        } catch (PrivilegedActionException pae) {
            throw new RuntimeException("cannot load the class: " + className, pae.getException());
        }
    }

    Object readResolve() throws ObjectStreamException {
        try {
            int n = this.interfaces.length;
            Class<?>[] infs = new Class[n];
            for (int i = 0; i < n; i++) {
                infs[i] = loadClass(this.interfaces[i]);
            }
            ProxyFactory f = new ProxyFactory();
            f.setSuperclass(loadClass(this.superClass));
            f.setInterfaces(infs);
            Proxy proxy = (Proxy) f.createClass(this.filterSignature).getConstructor(new Class[0]).newInstance(new Object[0]);
            proxy.setHandler(this.handler);
            return proxy;
        } catch (ClassNotFoundException e) {
            throw new InvalidClassException(e.getMessage());
        } catch (IllegalAccessException e3) {
            throw new InvalidClassException(e3.getMessage());
        } catch (InstantiationException e2) {
            throw new InvalidObjectException(e2.getMessage());
        } catch (NoSuchMethodException e4) {
            throw new InvalidClassException(e4.getMessage());
        } catch (InvocationTargetException e5) {
            throw new InvalidClassException(e5.getMessage());
        }
    }
}