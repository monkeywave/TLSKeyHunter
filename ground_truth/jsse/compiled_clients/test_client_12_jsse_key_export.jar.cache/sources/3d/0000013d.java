package javassist.compiler.ast;

import javassist.compiler.CompileError;
import javassist.compiler.TokenId;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/NewExpr.class */
public class NewExpr extends ASTList implements TokenId {
    private static final long serialVersionUID = 1;
    protected boolean newArray;
    protected int arrayType;

    public NewExpr(ASTList className, ASTList args) {
        super(className, new ASTList(args));
        this.newArray = false;
        this.arrayType = TokenId.CLASS;
    }

    public NewExpr(int type, ASTList arraySize, ArrayInit init) {
        super(null, new ASTList(arraySize));
        this.newArray = true;
        this.arrayType = type;
        if (init != null) {
            append(this, init);
        }
    }

    public static NewExpr makeObjectArray(ASTList className, ASTList arraySize, ArrayInit init) {
        NewExpr e = new NewExpr(className, arraySize);
        e.newArray = true;
        if (init != null) {
            append(e, init);
        }
        return e;
    }

    public boolean isArray() {
        return this.newArray;
    }

    public int getArrayType() {
        return this.arrayType;
    }

    public ASTList getClassName() {
        return (ASTList) getLeft();
    }

    public ASTList getArguments() {
        return (ASTList) getRight().getLeft();
    }

    public ASTList getArraySize() {
        return getArguments();
    }

    public ArrayInit getInitializer() {
        ASTree t = getRight().getRight();
        if (t == null) {
            return null;
        }
        return (ArrayInit) t.getLeft();
    }

    @Override // javassist.compiler.ast.ASTList, javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atNewExpr(this);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javassist.compiler.ast.ASTree
    public String getTag() {
        return this.newArray ? "new[]" : "new";
    }
}