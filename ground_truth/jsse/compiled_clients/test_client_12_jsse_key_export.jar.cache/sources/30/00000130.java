package javassist.compiler.ast;

import javassist.compiler.CompileError;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/BinExpr.class */
public class BinExpr extends Expr {
    private static final long serialVersionUID = 1;

    private BinExpr(int op, ASTree _head, ASTList _tail) {
        super(op, _head, _tail);
    }

    public static BinExpr makeBin(int op, ASTree oprand1, ASTree oprand2) {
        return new BinExpr(op, oprand1, new ASTList(oprand2));
    }

    @Override // javassist.compiler.ast.Expr, javassist.compiler.ast.ASTList, javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atBinExpr(this);
    }
}