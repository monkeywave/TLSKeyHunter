package javassist.util.proxy;

import java.lang.reflect.Method;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/MethodHandler.class */
public interface MethodHandler {
    Object invoke(Object obj, Method method, Method method2, Object[] objArr) throws Throwable;
}