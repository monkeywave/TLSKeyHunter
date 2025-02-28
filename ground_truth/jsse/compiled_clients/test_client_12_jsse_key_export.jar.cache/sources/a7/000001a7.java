package javassist.util.proxy;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/util/proxy/ProxyObject.class */
public interface ProxyObject extends Proxy {
    @Override // javassist.util.proxy.Proxy
    void setHandler(MethodHandler methodHandler);

    MethodHandler getHandler();
}