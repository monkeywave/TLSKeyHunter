package javassist.expr;

import java.util.LinkedList;
import java.util.List;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtBehavior;
import javassist.CtClass;
import javassist.CtConstructor;
import javassist.CtPrimitiveType;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.Bytecode;
import javassist.bytecode.ClassFile;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.ExceptionTable;
import javassist.bytecode.ExceptionsAttribute;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.compiler.Javac;
import javassist.expr.ExprEditor;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/expr/Expr.class */
public abstract class Expr implements Opcode {
    int currentPos;
    CodeIterator iterator;
    CtClass thisClass;
    MethodInfo thisMethod;
    boolean edited;
    int maxLocals;
    int maxStack;
    static final String javaLangObject = "java.lang.Object";

    public abstract void replace(String str) throws CannotCompileException;

    /* JADX INFO: Access modifiers changed from: protected */
    public Expr(int pos, CodeIterator i, CtClass declaring, MethodInfo m) {
        this.currentPos = pos;
        this.iterator = i;
        this.thisClass = declaring;
        this.thisMethod = m;
    }

    public CtClass getEnclosingClass() {
        return this.thisClass;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final ConstPool getConstPool() {
        return this.thisMethod.getConstPool();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final boolean edited() {
        return this.edited;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final int locals() {
        return this.maxLocals;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final int stack() {
        return this.maxStack;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final boolean withinStatic() {
        return (this.thisMethod.getAccessFlags() & 8) != 0;
    }

    public CtBehavior where() {
        MethodInfo mi = this.thisMethod;
        CtBehavior[] cb = this.thisClass.getDeclaredBehaviors();
        for (int i = cb.length - 1; i >= 0; i--) {
            if (cb[i].getMethodInfo2() == mi) {
                return cb[i];
            }
        }
        CtConstructor init = this.thisClass.getClassInitializer();
        if (init != null && init.getMethodInfo2() == mi) {
            return init;
        }
        for (int i2 = cb.length - 1; i2 >= 0; i2--) {
            if (this.thisMethod.getName().equals(cb[i2].getMethodInfo2().getName()) && this.thisMethod.getDescriptor().equals(cb[i2].getMethodInfo2().getDescriptor())) {
                return cb[i2];
            }
        }
        throw new RuntimeException("fatal: not found");
    }

    public CtClass[] mayThrow() {
        String[] exceptions;
        int t;
        ClassPool pool = this.thisClass.getClassPool();
        ConstPool cp = this.thisMethod.getConstPool();
        List<CtClass> list = new LinkedList<>();
        try {
            CodeAttribute ca = this.thisMethod.getCodeAttribute();
            ExceptionTable et = ca.getExceptionTable();
            int pos = this.currentPos;
            int n = et.size();
            for (int i = 0; i < n; i++) {
                if (et.startPc(i) <= pos && pos < et.endPc(i) && (t = et.catchType(i)) > 0) {
                    try {
                        addClass(list, pool.get(cp.getClassInfo(t)));
                    } catch (NotFoundException e) {
                    }
                }
            }
        } catch (NullPointerException e2) {
        }
        ExceptionsAttribute ea = this.thisMethod.getExceptionsAttribute();
        if (ea != null && (exceptions = ea.getExceptions()) != null) {
            for (String str : exceptions) {
                try {
                    addClass(list, pool.get(str));
                } catch (NotFoundException e3) {
                }
            }
        }
        return (CtClass[]) list.toArray(new CtClass[list.size()]);
    }

    private static void addClass(List<CtClass> list, CtClass c) {
        if (list.contains(c)) {
            return;
        }
        list.add(c);
    }

    public int indexOfBytecode() {
        return this.currentPos;
    }

    public int getLineNumber() {
        return this.thisMethod.getLineNumber(this.currentPos);
    }

    public String getFileName() {
        ClassFile cf = this.thisClass.getClassFile2();
        if (cf == null) {
            return null;
        }
        return cf.getSourceFile();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static final boolean checkResultValue(CtClass retType, String prog) throws CannotCompileException {
        boolean hasIt = prog.indexOf(Javac.resultVarName) >= 0;
        if (!hasIt && retType != CtClass.voidType) {
            throw new CannotCompileException("the resulting value is not stored in $_");
        }
        return hasIt;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static final void storeStack(CtClass[] params, boolean isStaticCall, int regno, Bytecode bytecode) {
        storeStack0(0, params.length, params, regno + 1, bytecode);
        if (isStaticCall) {
            bytecode.addOpcode(1);
        }
        bytecode.addAstore(regno);
    }

    private static void storeStack0(int i, int n, CtClass[] params, int regno, Bytecode bytecode) {
        int size;
        if (i >= n) {
            return;
        }
        CtClass c = params[i];
        if (c instanceof CtPrimitiveType) {
            size = ((CtPrimitiveType) c).getDataSize();
        } else {
            size = 1;
        }
        storeStack0(i + 1, n, params, regno + size, bytecode);
        bytecode.addStore(regno, c);
    }

    public void replace(String statement, ExprEditor recursive) throws CannotCompileException {
        replace(statement);
        if (recursive != null) {
            runEditor(recursive, this.iterator);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void replace0(int pos, Bytecode bytecode, int size) throws BadBytecode {
        byte[] code = bytecode.get();
        this.edited = true;
        int gap = code.length - size;
        for (int i = 0; i < size; i++) {
            this.iterator.writeByte(0, pos + i);
        }
        if (gap > 0) {
            pos = this.iterator.insertGapAt(pos, gap, false).position;
        }
        this.iterator.write(code, pos);
        this.iterator.insert(bytecode.getExceptionTable(), pos);
        this.maxLocals = bytecode.getMaxLocals();
        this.maxStack = bytecode.getMaxStack();
    }

    protected void runEditor(ExprEditor ed, CodeIterator oldIterator) throws CannotCompileException {
        CodeAttribute codeAttr = oldIterator.get();
        int orgLocals = codeAttr.getMaxLocals();
        int orgStack = codeAttr.getMaxStack();
        int newLocals = locals();
        codeAttr.setMaxStack(stack());
        codeAttr.setMaxLocals(newLocals);
        ExprEditor.LoopContext context = new ExprEditor.LoopContext(newLocals);
        int size = oldIterator.getCodeLength();
        int endPos = oldIterator.lookAhead();
        oldIterator.move(this.currentPos);
        if (ed.doit(this.thisClass, this.thisMethod, context, oldIterator, endPos)) {
            this.edited = true;
        }
        oldIterator.move((endPos + oldIterator.getCodeLength()) - size);
        codeAttr.setMaxLocals(orgLocals);
        codeAttr.setMaxStack(orgStack);
        this.maxLocals = context.maxLocals;
        this.maxStack += context.maxStack;
    }
}