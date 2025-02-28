package javassist.bytecode.annotation;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/NoSuchClassError.class */
public class NoSuchClassError extends Error {
    private static final long serialVersionUID = 1;
    private String className;

    public NoSuchClassError(String className, Error cause) {
        super(cause.toString(), cause);
        this.className = className;
    }

    public String getClassName() {
        return this.className;
    }
}