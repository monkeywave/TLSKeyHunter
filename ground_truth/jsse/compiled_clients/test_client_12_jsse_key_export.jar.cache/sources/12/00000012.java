package javassist;

import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/CannotCompileException.class */
public class CannotCompileException extends Exception {
    private static final long serialVersionUID = 1;
    private Throwable myCause;
    private String message;

    @Override // java.lang.Throwable
    public synchronized Throwable getCause() {
        if (this.myCause == this) {
            return null;
        }
        return this.myCause;
    }

    @Override // java.lang.Throwable
    public synchronized Throwable initCause(Throwable cause) {
        this.myCause = cause;
        return this;
    }

    public String getReason() {
        if (this.message != null) {
            return this.message;
        }
        return toString();
    }

    public CannotCompileException(String msg) {
        super(msg);
        this.message = msg;
        initCause(null);
    }

    public CannotCompileException(Throwable e) {
        super("by " + e.toString());
        this.message = null;
        initCause(e);
    }

    public CannotCompileException(String msg, Throwable e) {
        this(msg);
        initCause(e);
    }

    public CannotCompileException(NotFoundException e) {
        this("cannot find " + e.getMessage(), e);
    }

    public CannotCompileException(CompileError e) {
        this("[source error] " + e.getMessage(), e);
    }

    public CannotCompileException(ClassNotFoundException e, String name) {
        this("cannot find " + name, e);
    }

    public CannotCompileException(ClassFormatError e, String name) {
        this("invalid class format: " + name, e);
    }
}