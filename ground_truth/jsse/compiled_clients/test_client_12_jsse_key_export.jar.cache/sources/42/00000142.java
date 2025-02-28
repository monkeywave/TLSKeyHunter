package javassist.compiler.ast;

import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/Variable.class */
public class Variable extends Symbol {
    private static final long serialVersionUID = 1;
    protected Declarator declarator;

    public Variable(String sym, Declarator d) {
        super(sym);
        this.declarator = d;
    }

    public Declarator getDeclarator() {
        return this.declarator;
    }

    @Override // javassist.compiler.ast.Symbol, javassist.compiler.ast.ASTree
    public String toString() {
        return this.identifier + ":" + this.declarator.getType();
    }

    @Override // javassist.compiler.ast.Symbol, javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atVariable(this);
    }
}