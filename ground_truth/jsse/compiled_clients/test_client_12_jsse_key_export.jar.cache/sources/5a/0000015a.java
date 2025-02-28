package javassist.expr;

import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtBehavior;
import javassist.CtClass;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.Bytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.compiler.CompileError;
import javassist.compiler.Javac;
import javassist.compiler.JvstCodeGen;
import javassist.compiler.JvstTypeChecker;
import javassist.compiler.ProceedHandler;
import javassist.compiler.ast.ASTList;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/Instanceof.class */
public class Instanceof extends Expr {
    /* JADX INFO: Access modifiers changed from: protected */
    public Instanceof(int pos, CodeIterator i, CtClass declaring, MethodInfo m) {
        super(pos, i, declaring, m);
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

    public CtClass getType() throws NotFoundException {
        ConstPool cp = getConstPool();
        int pos = this.currentPos;
        int index = this.iterator.u16bitAt(pos + 1);
        String name = cp.getClassInfo(index);
        return this.thisClass.getClassPool().getCtClass(name);
    }

    @Override // javassist.expr.Expr
    public CtClass[] mayThrow() {
        return super.mayThrow();
    }

    @Override // javassist.expr.Expr
    public void replace(String statement) throws CannotCompileException {
        this.thisClass.getClassFile();
        getConstPool();
        int pos = this.currentPos;
        int index = this.iterator.u16bitAt(pos + 1);
        Javac jc = new Javac(this.thisClass);
        ClassPool cp = this.thisClass.getClassPool();
        CodeAttribute ca = this.iterator.get();
        try {
            CtClass[] params = {cp.get("java.lang.Object")};
            CtClass retType = CtClass.booleanType;
            int paramVar = ca.getMaxLocals();
            jc.recordParams("java.lang.Object", params, true, paramVar, withinStatic());
            int retVar = jc.recordReturnType(retType, true);
            jc.recordProceed(new ProceedForInstanceof(index));
            jc.recordType(getType());
            checkResultValue(retType, statement);
            Bytecode bytecode = jc.getBytecode();
            storeStack(params, true, paramVar, bytecode);
            jc.recordLocalVariables(ca, pos);
            bytecode.addConstZero(retType);
            bytecode.addStore(retVar, retType);
            jc.compileStmnt(statement);
            bytecode.addLoad(retVar, retType);
            replace0(pos, bytecode, 3);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        } catch (BadBytecode e2) {
            throw new CannotCompileException("broken method");
        } catch (CompileError e3) {
            throw new CannotCompileException(e3);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/Instanceof$ProceedForInstanceof.class */
    static class ProceedForInstanceof implements ProceedHandler {
        int index;

        ProceedForInstanceof(int i) {
            this.index = i;
        }

        @Override // javassist.compiler.ProceedHandler
        public void doit(JvstCodeGen gen, Bytecode bytecode, ASTList args) throws CompileError {
            if (gen.getMethodArgsLength(args) != 1) {
                throw new CompileError("$proceed() cannot take more than one parameter for instanceof");
            }
            gen.atMethodArgs(args, new int[1], new int[1], new String[1]);
            bytecode.addOpcode(Opcode.INSTANCEOF);
            bytecode.addIndex(this.index);
            gen.setType(CtClass.booleanType);
        }

        @Override // javassist.compiler.ProceedHandler
        public void setReturnType(JvstTypeChecker c, ASTList args) throws CompileError {
            c.atMethodArgs(args, new int[1], new int[1], new String[1]);
            c.setType(CtClass.booleanType);
        }
    }
}