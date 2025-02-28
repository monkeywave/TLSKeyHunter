package javassist.compiler.ast;

import java.io.Serializable;
import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/ASTree.class */
public abstract class ASTree implements Serializable {
    private static final long serialVersionUID = 1;

    public abstract void accept(Visitor visitor) throws CompileError;

    public ASTree getLeft() {
        return null;
    }

    public ASTree getRight() {
        return null;
    }

    public void setLeft(ASTree _left) {
    }

    public void setRight(ASTree _right) {
    }

    public String toString() {
        StringBuffer sbuf = new StringBuffer();
        sbuf.append('<');
        sbuf.append(getTag());
        sbuf.append('>');
        return sbuf.toString();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String getTag() {
        String name = getClass().getName();
        return name.substring(name.lastIndexOf(46) + 1);
    }
}