package javassist.tools.reflect;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/reflect/CannotCreateException.class */
public class CannotCreateException extends Exception {
    private static final long serialVersionUID = 1;

    public CannotCreateException(String s) {
        super(s);
    }

    public CannotCreateException(Exception e) {
        super("by " + e.toString());
    }
}