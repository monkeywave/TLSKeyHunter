package javassist.compiler.ast;

import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/FieldDecl.class */
public class FieldDecl extends ASTList {
    private static final long serialVersionUID = 1;

    public FieldDecl(ASTree _head, ASTList _tail) {
        super(_head, _tail);
    }

    public ASTList getModifiers() {
        return (ASTList) getLeft();
    }

    public Declarator getDeclarator() {
        return (Declarator) tail().head();
    }

    public ASTree getInit() {
        return sublist(2).head();
    }

    @Override // javassist.compiler.ast.ASTList, javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atFieldDecl(this);
    }
}