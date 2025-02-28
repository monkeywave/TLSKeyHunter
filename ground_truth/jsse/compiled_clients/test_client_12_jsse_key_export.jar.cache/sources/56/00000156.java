package javassist.expr;

import javassist.CannotCompileException;
import javassist.CtBehavior;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtPrimitiveType;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.Bytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.MethodInfo;
import javassist.compiler.CompileError;
import javassist.compiler.Javac;
import javassist.compiler.JvstCodeGen;
import javassist.compiler.JvstTypeChecker;
import javassist.compiler.ProceedHandler;
import javassist.compiler.ast.ASTList;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/FieldAccess.class */
public class FieldAccess extends Expr {
    int opcode;

    /* JADX INFO: Access modifiers changed from: protected */
    public FieldAccess(int pos, CodeIterator i, CtClass declaring, MethodInfo m, int op) {
        super(pos, i, declaring, m);
        this.opcode = op;
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

    public boolean isStatic() {
        return isStatic(this.opcode);
    }

    static boolean isStatic(int c) {
        return c == 178 || c == 179;
    }

    public boolean isReader() {
        return this.opcode == 180 || this.opcode == 178;
    }

    public boolean isWriter() {
        return this.opcode == 181 || this.opcode == 179;
    }

    private CtClass getCtClass() throws NotFoundException {
        return this.thisClass.getClassPool().get(getClassName());
    }

    public String getClassName() {
        int index = this.iterator.u16bitAt(this.currentPos + 1);
        return getConstPool().getFieldrefClassName(index);
    }

    public String getFieldName() {
        int index = this.iterator.u16bitAt(this.currentPos + 1);
        return getConstPool().getFieldrefName(index);
    }

    public CtField getField() throws NotFoundException {
        CtClass cc = getCtClass();
        int index = this.iterator.u16bitAt(this.currentPos + 1);
        ConstPool cp = getConstPool();
        return cc.getField(cp.getFieldrefName(index), cp.getFieldrefType(index));
    }

    @Override // javassist.expr.Expr
    public CtClass[] mayThrow() {
        return super.mayThrow();
    }

    public String getSignature() {
        int index = this.iterator.u16bitAt(this.currentPos + 1);
        return getConstPool().getFieldrefType(index);
    }

    @Override // javassist.expr.Expr
    public void replace(String statement) throws CannotCompileException {
        CtClass[] params;
        CtClass retType;
        this.thisClass.getClassFile();
        ConstPool constPool = getConstPool();
        int pos = this.currentPos;
        int index = this.iterator.u16bitAt(pos + 1);
        Javac jc = new Javac(this.thisClass);
        CodeAttribute ca = this.iterator.get();
        try {
            CtClass fieldType = Descriptor.toCtClass(constPool.getFieldrefType(index), this.thisClass.getClassPool());
            boolean read = isReader();
            if (read) {
                params = new CtClass[0];
                retType = fieldType;
            } else {
                params = new CtClass[]{fieldType};
                retType = CtClass.voidType;
            }
            int paramVar = ca.getMaxLocals();
            jc.recordParams(constPool.getFieldrefClassName(index), params, true, paramVar, withinStatic());
            boolean included = checkResultValue(retType, statement);
            if (read) {
                included = true;
            }
            int retVar = jc.recordReturnType(retType, included);
            if (read) {
                jc.recordProceed(new ProceedForRead(retType, this.opcode, index, paramVar));
            } else {
                jc.recordType(fieldType);
                jc.recordProceed(new ProceedForWrite(params[0], this.opcode, index, paramVar));
            }
            Bytecode bytecode = jc.getBytecode();
            storeStack(params, isStatic(), paramVar, bytecode);
            jc.recordLocalVariables(ca, pos);
            if (included) {
                if (retType == CtClass.voidType) {
                    bytecode.addOpcode(1);
                    bytecode.addAstore(retVar);
                } else {
                    bytecode.addConstZero(retType);
                    bytecode.addStore(retVar, retType);
                }
            }
            jc.compileStmnt(statement);
            if (read) {
                bytecode.addLoad(retVar, retType);
            }
            replace0(pos, bytecode, 3);
        } catch (NotFoundException e) {
            throw new CannotCompileException(e);
        } catch (BadBytecode e2) {
            throw new CannotCompileException("broken method");
        } catch (CompileError e3) {
            throw new CannotCompileException(e3);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/FieldAccess$ProceedForRead.class */
    static class ProceedForRead implements ProceedHandler {
        CtClass fieldType;
        int opcode;
        int targetVar;
        int index;

        ProceedForRead(CtClass type, int op, int i, int var) {
            this.fieldType = type;
            this.targetVar = var;
            this.opcode = op;
            this.index = i;
        }

        @Override // javassist.compiler.ProceedHandler
        public void doit(JvstCodeGen gen, Bytecode bytecode, ASTList args) throws CompileError {
            int stack;
            int stack2;
            if (args != null && !gen.isParamListName(args)) {
                throw new CompileError("$proceed() cannot take a parameter for field reading");
            }
            if (FieldAccess.isStatic(this.opcode)) {
                stack = 0;
            } else {
                stack = -1;
                bytecode.addAload(this.targetVar);
            }
            if (this.fieldType instanceof CtPrimitiveType) {
                stack2 = stack + ((CtPrimitiveType) this.fieldType).getDataSize();
            } else {
                stack2 = stack + 1;
            }
            bytecode.add(this.opcode);
            bytecode.addIndex(this.index);
            bytecode.growStack(stack2);
            gen.setType(this.fieldType);
        }

        @Override // javassist.compiler.ProceedHandler
        public void setReturnType(JvstTypeChecker c, ASTList args) throws CompileError {
            c.setType(this.fieldType);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/FieldAccess$ProceedForWrite.class */
    static class ProceedForWrite implements ProceedHandler {
        CtClass fieldType;
        int opcode;
        int targetVar;
        int index;

        ProceedForWrite(CtClass type, int op, int i, int var) {
            this.fieldType = type;
            this.targetVar = var;
            this.opcode = op;
            this.index = i;
        }

        @Override // javassist.compiler.ProceedHandler
        public void doit(JvstCodeGen gen, Bytecode bytecode, ASTList args) throws CompileError {
            int stack;
            int stack2;
            if (gen.getMethodArgsLength(args) != 1) {
                throw new CompileError("$proceed() cannot take more than one parameter for field writing");
            }
            if (FieldAccess.isStatic(this.opcode)) {
                stack = 0;
            } else {
                stack = -1;
                bytecode.addAload(this.targetVar);
            }
            gen.atMethodArgs(args, new int[1], new int[1], new String[1]);
            gen.doNumCast(this.fieldType);
            if (this.fieldType instanceof CtPrimitiveType) {
                stack2 = stack - ((CtPrimitiveType) this.fieldType).getDataSize();
            } else {
                stack2 = stack - 1;
            }
            bytecode.add(this.opcode);
            bytecode.addIndex(this.index);
            bytecode.growStack(stack2);
            gen.setType(CtClass.voidType);
            gen.addNullIfVoid();
        }

        @Override // javassist.compiler.ProceedHandler
        public void setReturnType(JvstTypeChecker c, ASTList args) throws CompileError {
            c.atMethodArgs(args, new int[1], new int[1], new String[1]);
            c.setType(CtClass.voidType);
            c.addNullIfVoid();
        }
    }
}