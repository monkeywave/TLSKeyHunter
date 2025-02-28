package javassist.util.proxy;

import java.lang.reflect.Method;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/MethodFilter.class */
public interface MethodFilter {
    boolean isHandled(Method method);
}