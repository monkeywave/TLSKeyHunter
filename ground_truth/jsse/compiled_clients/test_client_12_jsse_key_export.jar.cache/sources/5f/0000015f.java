package javassist.expr;

import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtBehavior;
import javassist.CtClass;
import javassist.CtConstructor;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.Bytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.compiler.CompileError;
import javassist.compiler.Javac;
import javassist.compiler.JvstCodeGen;
import javassist.compiler.JvstTypeChecker;
import javassist.compiler.ProceedHandler;
import javassist.compiler.ast.ASTList;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/NewExpr.class */
public class NewExpr extends Expr {
    String newTypeName;
    int newPos;

    /* JADX INFO: Access modifiers changed from: protected */
    public NewExpr(int pos, CodeIterator i, CtClass declaring, MethodInfo m, String type, int np) {
        super(pos, i, declaring, m);
        this.newTypeName = type;
        this.newPos = np;
    }

    @Override // javassist.expr.Expr
    public CtBehavior where() {
        return super.where();
    }

    @Override // javassist.expr.Expr
    public int getLineNumber() {
        return super.getLineNumber();
    }

    @Override // javassist.expr.Expr
    public String getFileName() {
        return super.getFileName();
    }

    private CtClass getCtClass() throws NotFoundException {
        return this.thisClass.getClassPool().get(this.newTypeName);
    }

    public String getClassName() {
        return this.newTypeName;
    }

    public String getSignature() {
        ConstPool constPool = getConstPool();
        int methodIndex = this.iterator.u16bitAt(this.currentPos + 1);
        return constPool.getMethodrefType(methodIndex);
    }

    public CtConstructor getConstructor() throws NotFoundException {
        ConstPool cp = getConstPool();
        int index = this.iterator.u16bitAt(this.currentPos + 1);
        String desc = cp.getMethodrefType(index);
        return getCtClass().getConstructor(desc);
    }

    @Override // javassist.expr.Expr
    public CtClass[] mayThrow() {
        return super.mayThrow();
    }

    private int canReplace() throws CannotCompileException {
        int op = this.iterator.byteAt(this.newPos + 3);
        if (op == 89) {
            return (this.iterator.byteAt(this.newPos + 4) == 94 && this.iterator.byteAt(this.newPos + 5) == 88) ? 6 : 4;
        } else if (op == 90 && this.iterator.byteAt(this.newPos + 4) == 95) {
            return 5;
        } else {
            return 3;
        }
    }

    @Override // javassist.expr.Expr
    public void replace(String statement) throws CannotCompileException {
        this.thisClass.getClassFile();
        int pos = this.newPos;
        int newIndex = this.iterator.u16bitAt(pos + 1);
        int codeSize = canReplace();
        int end = pos + codeSize;
        for (int i = pos; i < end; i++) {
            this.iterator.writeByte(0, i);
        }
        ConstPool constPool = getConstPool();
        int pos2 = this.currentPos;
        int methodIndex = this.iterator.u16bitAt(pos2 + 1);
        String signature = constPool.getMethodrefType(methodIndex);
        Javac jc = new Javac(this.thisClass);
        ClassPool cp = this.thisClass.getClassPool();
        CodeAttribute ca = this.iterator.get();
        try {
            CtClass[] params = Descriptor.getParameterTypes(signature, cp);
            CtClass newType = cp.get(this.newTypeName);
            int paramVar = ca.getMaxLocals();
            jc.recordParams(this.newTypeName, params, true, paramVar, withinStatic());
            int retVar = jc.recordReturnType(newType, true);
            jc.recordProceed(new ProceedForNew(newType, newIndex, methodIndex));
            checkResultValue(newType, statement);
            Bytecode bytecode = jc.getBytecode();
            storeStack(params, true, paramVar, bytecode);
            jc.recordLocalVariables(ca, pos2);
            bytecode.addConstZero(newType);
            bytecode.addStore(retVar, newType);
            jc.compileStmnt(statement);
            if (codeSize > 3) {
                bytecode.addAload(retVar);
            }
            replace0(pos2, bytecode, 3);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        } catch (BadBytecode e2) {
            throw new CannotCompileException("broken method");
        } catch (CompileError e3) {
            throw new CannotCompileException(e3);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/NewExpr$ProceedForNew.class */
    static class ProceedForNew implements ProceedHandler {
        CtClass newType;
        int newIndex;
        int methodIndex;

        ProceedForNew(CtClass nt, int ni, int mi) {
            this.newType = nt;
            this.newIndex = ni;
            this.methodIndex = mi;
        }

        @Override // javassist.compiler.ProceedHandler
        public void doit(JvstCodeGen gen, Bytecode bytecode, ASTList args) throws CompileError {
            bytecode.addOpcode(Opcode.NEW);
            bytecode.addIndex(this.newIndex);
            bytecode.addOpcode(89);
            gen.atMethodCallCore(this.newType, "<init>", args, false, true, -1, null);
            gen.setType(this.newType);
        }

        @Override // javassist.compiler.ProceedHandler
        public void setReturnType(JvstTypeChecker c, ASTList args) throws CompileError {
            c.atMethodCallCore(this.newType, "<init>", args);
            c.setType(this.newType);
        }
    }
}