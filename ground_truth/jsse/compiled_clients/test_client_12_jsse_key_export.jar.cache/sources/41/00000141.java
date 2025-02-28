package javassist.compiler.ast;

import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/Symbol.class */
public class Symbol extends ASTree {
    private static final long serialVersionUID = 1;
    protected String identifier;

    public Symbol(String sym) {
        this.identifier = sym;
    }

    public String get() {
        return this.identifier;
    }

    @Override // javassist.compiler.ast.ASTree
    public String toString() {
        return this.identifier;
    }

    @Override // javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atSymbol(this);
    }
}