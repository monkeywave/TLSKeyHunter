package javassist.compiler;

import javassist.compiler.ast.ASTree;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/NoFieldException.class */
public class NoFieldException extends CompileError {
    private static final long serialVersionUID = 1;
    private String fieldName;
    private ASTree expr;

    public NoFieldException(String name, ASTree e) {
        super("no such field: " + name);
        this.fieldName = name;
        this.expr = e;
    }

    public String getField() {
        return this.fieldName;
    }

    public ASTree getExpr() {
        return this.expr;
    }
}