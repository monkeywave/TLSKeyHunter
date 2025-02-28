package javassist.convert;

import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/convert/Transformer.class */
public abstract class Transformer implements Opcode {
    private Transformer next;

    public abstract int transform(CtClass ctClass, int i, CodeIterator codeIterator, ConstPool constPool) throws CannotCompileException, BadBytecode;

    public Transformer(Transformer t) {
        this.next = t;
    }

    public Transformer getNext() {
        return this.next;
    }

    public void initialize(ConstPool cp, CodeAttribute attr) {
    }

    public void initialize(ConstPool cp, CtClass clazz, MethodInfo minfo) throws CannotCompileException {
        initialize(cp, minfo.getCodeAttribute());
    }

    public void clean() {
    }

    public int extraLocals() {
        return 0;
    }

    public int extraStack() {
        return 0;
    }
}