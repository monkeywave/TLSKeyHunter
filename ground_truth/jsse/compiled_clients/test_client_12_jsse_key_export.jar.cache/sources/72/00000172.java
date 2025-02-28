package javassist.tools.reflect;

import java.lang.reflect.InvocationTargetException;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/reflect/CannotInvokeException.class */
public class CannotInvokeException extends RuntimeException {
    private static final long serialVersionUID = 1;
    private Throwable err;

    public Throwable getReason() {
        return this.err;
    }

    public CannotInvokeException(String reason) {
        super(reason);
        this.err = null;
    }

    public CannotInvokeException(InvocationTargetException e) {
        super("by " + e.getTargetException().toString());
        this.err = null;
        this.err = e.getTargetException();
    }

    public CannotInvokeException(IllegalAccessException e) {
        super("by " + e.toString());
        this.err = null;
        this.err = e;
    }

    public CannotInvokeException(ClassNotFoundException e) {
        super("by " + e.toString());
        this.err = null;
        this.err = e;
    }
}