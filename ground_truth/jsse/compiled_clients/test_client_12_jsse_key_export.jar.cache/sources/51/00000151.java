package javassist.expr;

import javassist.CtClass;
import javassist.CtConstructor;
import javassist.CtMethod;
import javassist.NotFoundException;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.MethodInfo;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/ConstructorCall.class */
public class ConstructorCall extends MethodCall {
    /* JADX INFO: Access modifiers changed from: protected */
    public ConstructorCall(int pos, CodeIterator i, CtClass decl, MethodInfo m) {
        super(pos, i, decl, m);
    }

    @Override // javassist.expr.MethodCall
    public String getMethodName() {
        return isSuper() ? "super" : "this";
    }

    @Override // javassist.expr.MethodCall
    public CtMethod getMethod() throws NotFoundException {
        throw new NotFoundException("this is a constructor call.  Call getConstructor().");
    }

    public CtConstructor getConstructor() throws NotFoundException {
        return getCtClass().getConstructor(getSignature());
    }

    @Override // javassist.expr.MethodCall
    public boolean isSuper() {
        return super.isSuper();
    }
}