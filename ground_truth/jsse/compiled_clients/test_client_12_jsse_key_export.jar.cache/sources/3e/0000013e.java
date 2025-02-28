package javassist.compiler.ast;

import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/Pair.class */
public class Pair extends ASTree {
    private static final long serialVersionUID = 1;
    protected ASTree left;
    protected ASTree right;

    public Pair(ASTree _left, ASTree _right) {
        this.left = _left;
        this.right = _right;
    }

    @Override // javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atPair(this);
    }

    @Override // javassist.compiler.ast.ASTree
    public String toString() {
        StringBuffer sbuf = new StringBuffer();
        sbuf.append("(<Pair> ");
        sbuf.append(this.left == null ? "<null>" : this.left.toString());
        sbuf.append(" . ");
        sbuf.append(this.right == null ? "<null>" : this.right.toString());
        sbuf.append(')');
        return sbuf.toString();
    }

    @Override // javassist.compiler.ast.ASTree
    public ASTree getLeft() {
        return this.left;
    }

    @Override // javassist.compiler.ast.ASTree
    public ASTree getRight() {
        return this.right;
    }

    @Override // javassist.compiler.ast.ASTree
    public void setLeft(ASTree _left) {
        this.left = _left;
    }

    @Override // javassist.compiler.ast.ASTree
    public void setRight(ASTree _right) {
        this.right = _right;
    }
}