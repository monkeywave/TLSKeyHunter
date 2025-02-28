package javassist.runtime;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/runtime/DotClass.class */
public class DotClass {
    public static NoClassDefFoundError fail(ClassNotFoundException e) {
        return new NoClassDefFoundError(e.getMessage());
    }
}