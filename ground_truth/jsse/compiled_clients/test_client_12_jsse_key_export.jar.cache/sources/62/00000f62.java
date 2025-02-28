package org.openjsse.com.sun.net.ssl;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/SSLSecurity.class */
final class SSLSecurity {
    private SSLSecurity() {
    }

    private static Provider.Service getService(String type, String alg) {
        ProviderList list = Providers.getProviderList();
        for (Provider p : list.providers()) {
            Provider.Service s = p.getService(type, alg);
            if (s != null) {
                return s;
            }
        }
        return null;
    }

    private static Object[] getImpl1(String algName, String engineType, Provider.Service service) throws NoSuchAlgorithmException {
        Class<?> implClass;
        Provider provider = service.getProvider();
        String className = service.getClassName();
        try {
            ClassLoader cl = provider.getClass().getClassLoader();
            if (cl == null) {
                implClass = Class.forName(className);
            } else {
                implClass = cl.loadClass(className);
            }
            try {
                Object obj = null;
                Class<?> typeClassJavax = Class.forName("javax.net.ssl." + engineType + "Spi");
                if (typeClassJavax != null && checkSuperclass(implClass, typeClassJavax)) {
                    if (engineType.equals("SSLContext")) {
                        obj = new SSLContextSpiWrapper(algName, provider);
                    } else if (engineType.equals("TrustManagerFactory")) {
                        obj = new TrustManagerFactorySpiWrapper(algName, provider);
                    } else if (engineType.equals("KeyManagerFactory")) {
                        obj = new KeyManagerFactorySpiWrapper(algName, provider);
                    } else {
                        throw new IllegalStateException("Class " + implClass.getName() + " unknown engineType wrapper:" + engineType);
                    }
                } else {
                    Class<?> typeClassCom = Class.forName("org.openjsse.com.sun.net.ssl." + engineType + "Spi");
                    if (typeClassCom != null && checkSuperclass(implClass, typeClassCom)) {
                        obj = service.newInstance(null);
                    }
                }
                if (obj != null) {
                    return new Object[]{obj, provider};
                }
                throw new NoSuchAlgorithmException("Couldn't locate correct object or wrapper: " + engineType + " " + algName);
            } catch (ClassNotFoundException e) {
                IllegalStateException exc = new IllegalStateException("Engine Class Not Found for " + engineType);
                exc.initCause(e);
                throw exc;
            }
        } catch (ClassNotFoundException e2) {
            throw new NoSuchAlgorithmException("Class " + className + " configured for " + engineType + " not found: " + e2.getMessage());
        } catch (SecurityException e3) {
            throw new NoSuchAlgorithmException("Class " + className + " configured for " + engineType + " cannot be accessed: " + e3.getMessage());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object[] getImpl(String algName, String engineType, String provName) throws NoSuchAlgorithmException, NoSuchProviderException {
        Provider.Service service;
        if (provName != null) {
            ProviderList list = Providers.getProviderList();
            Provider prov = list.getProvider(provName);
            if (prov == null) {
                throw new NoSuchProviderException("No such provider: " + provName);
            }
            service = prov.getService(engineType, algName);
        } else {
            service = getService(engineType, algName);
        }
        if (service == null) {
            throw new NoSuchAlgorithmException("Algorithm " + algName + " not available");
        }
        return getImpl1(algName, engineType, service);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object[] getImpl(String algName, String engineType, Provider prov) throws NoSuchAlgorithmException {
        Provider.Service service = prov.getService(engineType, algName);
        if (service == null) {
            throw new NoSuchAlgorithmException("No such algorithm: " + algName);
        }
        return getImpl1(algName, engineType, service);
    }

    private static boolean checkSuperclass(Class<?> subclass, Class<?> superclass) {
        if (subclass == null || superclass == null) {
            return false;
        }
        while (!subclass.equals(superclass)) {
            subclass = subclass.getSuperclass();
            if (subclass == null) {
                return false;
            }
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Object[] truncateArray(Object[] oldArray, Object[] newArray) {
        for (int i = 0; i < newArray.length; i++) {
            newArray[i] = oldArray[i];
        }
        return newArray;
    }
}