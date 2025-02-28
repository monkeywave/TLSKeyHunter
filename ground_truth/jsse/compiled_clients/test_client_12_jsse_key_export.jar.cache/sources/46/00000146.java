package javassist.convert;

import javassist.CtClass;
import javassist.CtMethod;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.Bytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/convert/TransformBefore.class */
public class TransformBefore extends TransformCall {
    protected CtClass[] parameterTypes;
    protected int locals;
    protected int maxLocals;
    protected byte[] saveCode;
    protected byte[] loadCode;

    public TransformBefore(Transformer next, CtMethod origMethod, CtMethod beforeMethod) throws NotFoundException {
        super(next, origMethod, beforeMethod);
        this.methodDescriptor = origMethod.getMethodInfo2().getDescriptor();
        this.parameterTypes = origMethod.getParameterTypes();
        this.locals = 0;
        this.maxLocals = 0;
        this.loadCode = null;
        this.saveCode = null;
    }

    @Override // javassist.convert.TransformCall, javassist.convert.Transformer
    public void initialize(ConstPool cp, CodeAttribute attr) {
        super.initialize(cp, attr);
        this.locals = 0;
        this.maxLocals = attr.getMaxLocals();
        this.loadCode = null;
        this.saveCode = null;
    }

    @Override // javassist.convert.TransformCall
    protected int match(int c, int pos, CodeIterator iterator, int typedesc, ConstPool cp) throws BadBytecode {
        if (this.newIndex == 0) {
            String desc = Descriptor.ofParameters(this.parameterTypes) + 'V';
            int nt = cp.addNameAndTypeInfo(this.newMethodname, Descriptor.insertParameter(this.classname, desc));
            int ci = cp.addClassInfo(this.newClassname);
            this.newIndex = cp.addMethodrefInfo(ci, nt);
            this.constPool = cp;
        }
        if (this.saveCode == null) {
            makeCode(this.parameterTypes, cp);
        }
        return match2(pos, iterator);
    }

    protected int match2(int pos, CodeIterator iterator) throws BadBytecode {
        iterator.move(pos);
        iterator.insert(this.saveCode);
        iterator.insert(this.loadCode);
        int p = iterator.insertGap(3);
        iterator.writeByte(Opcode.INVOKESTATIC, p);
        iterator.write16bit(this.newIndex, p + 1);
        iterator.insert(this.loadCode);
        return iterator.next();
    }

    @Override // javassist.convert.Transformer
    public int extraLocals() {
        return this.locals;
    }

    protected void makeCode(CtClass[] paramTypes, ConstPool cp) {
        Bytecode save = new Bytecode(cp, 0, 0);
        Bytecode load = new Bytecode(cp, 0, 0);
        int var = this.maxLocals;
        int len = paramTypes == null ? 0 : paramTypes.length;
        load.addAload(var);
        makeCode2(save, load, 0, len, paramTypes, var + 1);
        save.addAstore(var);
        this.saveCode = save.get();
        this.loadCode = load.get();
    }

    private void makeCode2(Bytecode save, Bytecode load, int i, int n, CtClass[] paramTypes, int var) {
        if (i < n) {
            int size = load.addLoad(var, paramTypes[i]);
            makeCode2(save, load, i + 1, n, paramTypes, var + size);
            save.addStore(var, paramTypes[i]);
            return;
        }
        this.locals = var - this.maxLocals;
    }
}