package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.SSLParameters;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class SSLParametersUtil {
    private static final Method getAlgorithmConstraints;
    private static final Method getApplicationProtocols;
    private static final Method getEnableRetransmissions;
    private static final Method getEndpointIdentificationAlgorithm;
    private static final Method getMaximumPacketSize;
    private static final Method getNamedGroups;
    private static final Method getSNIMatchers;
    private static final Method getServerNames;
    private static final Method getSignatureSchemes;
    private static final Method getUseCipherSuitesOrder;
    private static final Method setAlgorithmConstraints;
    private static final Method setApplicationProtocols;
    private static final Method setEnableRetransmissions;
    private static final Method setEndpointIdentificationAlgorithm;
    private static final Method setMaximumPacketSize;
    private static final Method setNamedGroups;
    private static final Method setSNIMatchers;
    private static final Method setServerNames;
    private static final Method setSignatureSchemes;
    private static final Method setUseCipherSuitesOrder;

    static {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLParameters");
        getAlgorithmConstraints = ReflectionUtil.findMethod(methods, "getAlgorithmConstraints");
        setAlgorithmConstraints = ReflectionUtil.findMethod(methods, "setAlgorithmConstraints");
        getApplicationProtocols = ReflectionUtil.findMethod(methods, "getApplicationProtocols");
        setApplicationProtocols = ReflectionUtil.findMethod(methods, "setApplicationProtocols");
        getEnableRetransmissions = ReflectionUtil.findMethod(methods, "getEnableRetransmissions");
        setEnableRetransmissions = ReflectionUtil.findMethod(methods, "setEnableRetransmissions");
        getEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "getEndpointIdentificationAlgorithm");
        setEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "setEndpointIdentificationAlgorithm");
        getMaximumPacketSize = ReflectionUtil.findMethod(methods, "getMaximumPacketSize");
        setMaximumPacketSize = ReflectionUtil.findMethod(methods, "setMaximumPacketSize");
        getNamedGroups = ReflectionUtil.findMethod(methods, "getNamedGroups");
        setNamedGroups = ReflectionUtil.findMethod(methods, "setNamedGroups");
        getServerNames = ReflectionUtil.findMethod(methods, "getServerNames");
        setServerNames = ReflectionUtil.findMethod(methods, "setServerNames");
        getSignatureSchemes = ReflectionUtil.findMethod(methods, "getSignatureSchemes");
        setSignatureSchemes = ReflectionUtil.findMethod(methods, "setSignatureSchemes");
        getSNIMatchers = ReflectionUtil.findMethod(methods, "getSNIMatchers");
        setSNIMatchers = ReflectionUtil.findMethod(methods, "setSNIMatchers");
        getUseCipherSuitesOrder = ReflectionUtil.findMethod(methods, "getUseCipherSuitesOrder");
        setUseCipherSuitesOrder = ReflectionUtil.findMethod(methods, "setUseCipherSuitesOrder");
    }

    SSLParametersUtil() {
    }

    private static Object get(Object obj, Method method) {
        return ReflectionUtil.invokeGetter(obj, method);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BCSSLParameters getParameters(ProvSSLParameters provSSLParameters) {
        BCSSLParameters bCSSLParameters = new BCSSLParameters(provSSLParameters.getCipherSuites(), provSSLParameters.getProtocols());
        if (provSSLParameters.getNeedClientAuth()) {
            bCSSLParameters.setNeedClientAuth(true);
        } else {
            bCSSLParameters.setWantClientAuth(provSSLParameters.getWantClientAuth());
        }
        bCSSLParameters.setEndpointIdentificationAlgorithm(provSSLParameters.getEndpointIdentificationAlgorithm());
        bCSSLParameters.setAlgorithmConstraints(provSSLParameters.getAlgorithmConstraints());
        bCSSLParameters.setServerNames(provSSLParameters.getServerNames());
        bCSSLParameters.setSNIMatchers(provSSLParameters.getSNIMatchers());
        bCSSLParameters.setUseCipherSuitesOrder(provSSLParameters.getUseCipherSuitesOrder());
        bCSSLParameters.setApplicationProtocols(provSSLParameters.getApplicationProtocols());
        bCSSLParameters.setEnableRetransmissions(provSSLParameters.getEnableRetransmissions());
        bCSSLParameters.setMaximumPacketSize(provSSLParameters.getMaximumPacketSize());
        bCSSLParameters.setSignatureSchemes(provSSLParameters.getSignatureSchemes());
        bCSSLParameters.setSignatureSchemesCert(provSSLParameters.getSignatureSchemesCert());
        bCSSLParameters.setNamedGroups(provSSLParameters.getNamedGroups());
        return bCSSLParameters;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SSLParameters getSSLParameters(ProvSSLParameters provSSLParameters) {
        String[] applicationProtocols;
        Collection<BCSNIMatcher> sNIMatchers;
        List<BCSNIServerName> serverNames;
        SSLParameters sSLParameters = new SSLParameters(provSSLParameters.getCipherSuites(), provSSLParameters.getProtocols());
        if (provSSLParameters.getNeedClientAuth()) {
            sSLParameters.setNeedClientAuth(true);
        } else {
            sSLParameters.setWantClientAuth(provSSLParameters.getWantClientAuth());
        }
        Method method = setAlgorithmConstraints;
        if (method != null) {
            set(sSLParameters, method, JsseUtils_7.exportAlgorithmConstraintsDynamic(provSSLParameters.getAlgorithmConstraints()));
        }
        Method method2 = setEndpointIdentificationAlgorithm;
        if (method2 != null) {
            set(sSLParameters, method2, provSSLParameters.getEndpointIdentificationAlgorithm());
        }
        Method method3 = setServerNames;
        if (method3 != null && (serverNames = provSSLParameters.getServerNames()) != null) {
            set(sSLParameters, method3, JsseUtils_8.exportSNIServerNamesDynamic(serverNames));
        }
        Method method4 = setSNIMatchers;
        if (method4 != null && (sNIMatchers = provSSLParameters.getSNIMatchers()) != null) {
            set(sSLParameters, method4, JsseUtils_8.exportSNIMatchersDynamic(sNIMatchers));
        }
        Method method5 = setUseCipherSuitesOrder;
        if (method5 != null) {
            set(sSLParameters, method5, Boolean.valueOf(provSSLParameters.getUseCipherSuitesOrder()));
        }
        Method method6 = setApplicationProtocols;
        if (method6 != null && (applicationProtocols = provSSLParameters.getApplicationProtocols()) != null) {
            set(sSLParameters, method6, applicationProtocols);
        }
        Method method7 = setEnableRetransmissions;
        if (method7 != null) {
            set(sSLParameters, method7, Boolean.valueOf(provSSLParameters.getEnableRetransmissions()));
        }
        Method method8 = setMaximumPacketSize;
        if (method8 != null) {
            set(sSLParameters, method8, Integer.valueOf(provSSLParameters.getMaximumPacketSize()));
        }
        Method method9 = setSignatureSchemes;
        if (method9 != null) {
            set(sSLParameters, method9, provSSLParameters.getSignatureSchemes());
        }
        Method method10 = setNamedGroups;
        if (method10 != null) {
            set(sSLParameters, method10, provSSLParameters.getNamedGroups());
        }
        return sSLParameters;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BCSSLParameters importSSLParameters(SSLParameters sSLParameters) {
        String[] strArr;
        Object obj;
        Object obj2;
        Object obj3;
        String str;
        BCSSLParameters bCSSLParameters = new BCSSLParameters(sSLParameters.getCipherSuites(), sSLParameters.getProtocols());
        if (sSLParameters.getNeedClientAuth()) {
            bCSSLParameters.setNeedClientAuth(true);
        } else {
            bCSSLParameters.setWantClientAuth(sSLParameters.getWantClientAuth());
        }
        Method method = getEndpointIdentificationAlgorithm;
        if (method != null && (str = (String) get(sSLParameters, method)) != null) {
            bCSSLParameters.setEndpointIdentificationAlgorithm(str);
        }
        Method method2 = getAlgorithmConstraints;
        if (method2 != null && (obj3 = get(sSLParameters, method2)) != null) {
            bCSSLParameters.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraintsDynamic(obj3));
        }
        Method method3 = getServerNames;
        if (method3 != null && (obj2 = get(sSLParameters, method3)) != null) {
            bCSSLParameters.setServerNames(JsseUtils_8.importSNIServerNamesDynamic(obj2));
        }
        Method method4 = getSNIMatchers;
        if (method4 != null && (obj = get(sSLParameters, method4)) != null) {
            bCSSLParameters.setSNIMatchers(JsseUtils_8.importSNIMatchersDynamic(obj));
        }
        Method method5 = getUseCipherSuitesOrder;
        if (method5 != null) {
            bCSSLParameters.setUseCipherSuitesOrder(((Boolean) get(sSLParameters, method5)).booleanValue());
        }
        Method method6 = getApplicationProtocols;
        if (method6 != null && (strArr = (String[]) get(sSLParameters, method6)) != null) {
            bCSSLParameters.setApplicationProtocols(strArr);
        }
        Method method7 = getEnableRetransmissions;
        if (method7 != null) {
            bCSSLParameters.setEnableRetransmissions(((Boolean) get(sSLParameters, method7)).booleanValue());
        }
        Method method8 = getMaximumPacketSize;
        if (method8 != null) {
            bCSSLParameters.setMaximumPacketSize(((Integer) get(sSLParameters, method8)).intValue());
        }
        Method method9 = getSignatureSchemes;
        if (method9 != null) {
            bCSSLParameters.setSignatureSchemes((String[]) get(sSLParameters, method9));
        }
        Method method10 = getNamedGroups;
        if (method10 != null) {
            bCSSLParameters.setNamedGroups((String[]) get(sSLParameters, method10));
        }
        return bCSSLParameters;
    }

    private static void set(Object obj, Method method, Object obj2) {
        ReflectionUtil.invokeSetter(obj, method, obj2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void setParameters(ProvSSLParameters provSSLParameters, BCSSLParameters bCSSLParameters) {
        String[] cipherSuites = bCSSLParameters.getCipherSuites();
        if (cipherSuites != null) {
            provSSLParameters.setCipherSuites(cipherSuites);
        }
        String[] protocols = bCSSLParameters.getProtocols();
        if (protocols != null) {
            provSSLParameters.setProtocols(protocols);
        }
        if (bCSSLParameters.getNeedClientAuth()) {
            provSSLParameters.setNeedClientAuth(true);
        } else {
            provSSLParameters.setWantClientAuth(bCSSLParameters.getWantClientAuth());
        }
        String endpointIdentificationAlgorithm = bCSSLParameters.getEndpointIdentificationAlgorithm();
        if (endpointIdentificationAlgorithm != null) {
            provSSLParameters.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }
        BCAlgorithmConstraints algorithmConstraints = bCSSLParameters.getAlgorithmConstraints();
        if (algorithmConstraints != null) {
            provSSLParameters.setAlgorithmConstraints(algorithmConstraints);
        }
        List<BCSNIServerName> serverNames = bCSSLParameters.getServerNames();
        if (serverNames != null) {
            provSSLParameters.setServerNames(serverNames);
        }
        Collection<BCSNIMatcher> sNIMatchers = bCSSLParameters.getSNIMatchers();
        if (sNIMatchers != null) {
            provSSLParameters.setSNIMatchers(sNIMatchers);
        }
        provSSLParameters.setUseCipherSuitesOrder(bCSSLParameters.getUseCipherSuitesOrder());
        String[] applicationProtocols = bCSSLParameters.getApplicationProtocols();
        if (applicationProtocols != null) {
            provSSLParameters.setApplicationProtocols(applicationProtocols);
        }
        provSSLParameters.setEnableRetransmissions(bCSSLParameters.getEnableRetransmissions());
        provSSLParameters.setMaximumPacketSize(bCSSLParameters.getMaximumPacketSize());
        provSSLParameters.setSignatureSchemes(bCSSLParameters.getSignatureSchemes());
        provSSLParameters.setNamedGroups(bCSSLParameters.getNamedGroups());
        provSSLParameters.setSignatureSchemesCert(bCSSLParameters.getSignatureSchemesCert());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void setSSLParameters(ProvSSLParameters provSSLParameters, SSLParameters sSLParameters) {
        String[] strArr;
        Object obj;
        Object obj2;
        Object obj3;
        String str;
        String[] cipherSuites = sSLParameters.getCipherSuites();
        if (cipherSuites != null) {
            provSSLParameters.setCipherSuites(cipherSuites);
        }
        String[] protocols = sSLParameters.getProtocols();
        if (protocols != null) {
            provSSLParameters.setProtocols(protocols);
        }
        if (sSLParameters.getNeedClientAuth()) {
            provSSLParameters.setNeedClientAuth(true);
        } else {
            provSSLParameters.setWantClientAuth(sSLParameters.getWantClientAuth());
        }
        Method method = getEndpointIdentificationAlgorithm;
        if (method != null && (str = (String) get(sSLParameters, method)) != null) {
            provSSLParameters.setEndpointIdentificationAlgorithm(str);
        }
        Method method2 = getAlgorithmConstraints;
        if (method2 != null && (obj3 = get(sSLParameters, method2)) != null) {
            provSSLParameters.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraintsDynamic(obj3));
        }
        Method method3 = getServerNames;
        if (method3 != null && (obj2 = get(sSLParameters, method3)) != null) {
            provSSLParameters.setServerNames(JsseUtils_8.importSNIServerNamesDynamic(obj2));
        }
        Method method4 = getSNIMatchers;
        if (method4 != null && (obj = get(sSLParameters, method4)) != null) {
            provSSLParameters.setSNIMatchers(JsseUtils_8.importSNIMatchersDynamic(obj));
        }
        Method method5 = getUseCipherSuitesOrder;
        if (method5 != null) {
            provSSLParameters.setUseCipherSuitesOrder(((Boolean) get(sSLParameters, method5)).booleanValue());
        }
        Method method6 = getApplicationProtocols;
        if (method6 != null && (strArr = (String[]) get(sSLParameters, method6)) != null) {
            provSSLParameters.setApplicationProtocols(strArr);
        }
        Method method7 = getEnableRetransmissions;
        if (method7 != null) {
            provSSLParameters.setEnableRetransmissions(((Boolean) get(sSLParameters, method7)).booleanValue());
        }
        Method method8 = getMaximumPacketSize;
        if (method8 != null) {
            provSSLParameters.setMaximumPacketSize(((Integer) get(sSLParameters, method8)).intValue());
        }
        Method method9 = getSignatureSchemes;
        if (method9 != null) {
            provSSLParameters.setSignatureSchemes((String[]) get(sSLParameters, method9));
        }
        Method method10 = getNamedGroups;
        if (method10 != null) {
            provSSLParameters.setNamedGroups((String[]) get(sSLParameters, method10));
        }
    }
}