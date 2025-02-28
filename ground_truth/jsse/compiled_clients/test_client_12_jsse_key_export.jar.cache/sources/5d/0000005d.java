package javassist.bytecode;

import javassist.CtClass;
import javassist.CtPrimitiveType;
import org.bouncycastle.crypto.digests.Blake2xsDigest;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/Bytecode.class */
public class Bytecode extends ByteVector implements Cloneable, Opcode {
    public static final CtClass THIS = ConstPool.THIS;
    ConstPool constPool;
    int maxStack;
    int maxLocals;
    ExceptionTable tryblocks;
    private int stackDepth;

    @Override // javassist.bytecode.ByteVector
    public /* bridge */ /* synthetic */ void add(int i, int i2, int i3, int i4) {
        super.add(i, i2, i3, i4);
    }

    @Override // javassist.bytecode.ByteVector
    public /* bridge */ /* synthetic */ void add(int i, int i2) {
        super.add(i, i2);
    }

    public Bytecode(ConstPool cp, int stacksize, int localvars) {
        this.constPool = cp;
        this.maxStack = stacksize;
        this.maxLocals = localvars;
        this.tryblocks = new ExceptionTable(cp);
        this.stackDepth = 0;
    }

    public Bytecode(ConstPool cp) {
        this(cp, 0, 0);
    }

    @Override // javassist.bytecode.ByteVector
    public Object clone() {
        try {
            Bytecode bc = (Bytecode) super.clone();
            bc.tryblocks = (ExceptionTable) this.tryblocks.clone();
            return bc;
        } catch (CloneNotSupportedException cnse) {
            throw new RuntimeException(cnse);
        }
    }

    public ConstPool getConstPool() {
        return this.constPool;
    }

    public ExceptionTable getExceptionTable() {
        return this.tryblocks;
    }

    public CodeAttribute toCodeAttribute() {
        return new CodeAttribute(this.constPool, this.maxStack, this.maxLocals, get(), this.tryblocks);
    }

    public int length() {
        return getSize();
    }

    public byte[] get() {
        return copy();
    }

    public int getMaxStack() {
        return this.maxStack;
    }

    public void setMaxStack(int size) {
        this.maxStack = size;
    }

    public int getMaxLocals() {
        return this.maxLocals;
    }

    public void setMaxLocals(int size) {
        this.maxLocals = size;
    }

    public void setMaxLocals(boolean isStatic, CtClass[] params, int locals) {
        if (!isStatic) {
            locals++;
        }
        if (params != null) {
            CtClass doubleType = CtClass.doubleType;
            CtClass longType = CtClass.longType;
            for (CtClass type : params) {
                if (type == doubleType || type == longType) {
                    locals += 2;
                } else {
                    locals++;
                }
            }
        }
        this.maxLocals = locals;
    }

    public void incMaxLocals(int diff) {
        this.maxLocals += diff;
    }

    public void addExceptionHandler(int start, int end, int handler, CtClass type) {
        addExceptionHandler(start, end, handler, this.constPool.addClassInfo(type));
    }

    public void addExceptionHandler(int start, int end, int handler, String type) {
        addExceptionHandler(start, end, handler, this.constPool.addClassInfo(type));
    }

    public void addExceptionHandler(int start, int end, int handler, int type) {
        this.tryblocks.add(start, end, handler, type);
    }

    public int currentPc() {
        return getSize();
    }

    @Override // javassist.bytecode.ByteVector
    public int read(int offset) {
        return super.read(offset);
    }

    public int read16bit(int offset) {
        int v1 = read(offset);
        int v2 = read(offset + 1);
        return (v1 << 8) + (v2 & GF2Field.MASK);
    }

    public int read32bit(int offset) {
        int v1 = read16bit(offset);
        int v2 = read16bit(offset + 2);
        return (v1 << 16) + (v2 & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH);
    }

    @Override // javassist.bytecode.ByteVector
    public void write(int offset, int value) {
        super.write(offset, value);
    }

    public void write16bit(int offset, int value) {
        write(offset, value >> 8);
        write(offset + 1, value);
    }

    public void write32bit(int offset, int value) {
        write16bit(offset, value >> 16);
        write16bit(offset + 2, value);
    }

    @Override // javassist.bytecode.ByteVector
    public void add(int code) {
        super.add(code);
    }

    public void add32bit(int value) {
        add(value >> 24, value >> 16, value >> 8, value);
    }

    @Override // javassist.bytecode.ByteVector
    public void addGap(int length) {
        super.addGap(length);
    }

    public void addOpcode(int code) {
        add(code);
        growStack(STACK_GROW[code]);
    }

    public void growStack(int diff) {
        setStackDepth(this.stackDepth + diff);
    }

    public int getStackDepth() {
        return this.stackDepth;
    }

    public void setStackDepth(int depth) {
        this.stackDepth = depth;
        if (this.stackDepth > this.maxStack) {
            this.maxStack = this.stackDepth;
        }
    }

    public void addIndex(int index) {
        add(index >> 8, index);
    }

    public void addAload(int n) {
        if (n < 4) {
            addOpcode(42 + n);
        } else if (n < 256) {
            addOpcode(25);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(25);
            addIndex(n);
        }
    }

    public void addAstore(int n) {
        if (n < 4) {
            addOpcode(75 + n);
        } else if (n < 256) {
            addOpcode(58);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(58);
            addIndex(n);
        }
    }

    public void addIconst(int n) {
        if (n < 6 && -2 < n) {
            addOpcode(3 + n);
        } else if (n <= 127 && -128 <= n) {
            addOpcode(16);
            add(n);
        } else if (n <= 32767 && -32768 <= n) {
            addOpcode(17);
            add(n >> 8);
            add(n);
        } else {
            addLdc(this.constPool.addIntegerInfo(n));
        }
    }

    public void addConstZero(CtClass type) {
        if (type.isPrimitive()) {
            if (type == CtClass.longType) {
                addOpcode(9);
                return;
            } else if (type == CtClass.floatType) {
                addOpcode(11);
                return;
            } else if (type == CtClass.doubleType) {
                addOpcode(14);
                return;
            } else if (type == CtClass.voidType) {
                throw new RuntimeException("void type?");
            } else {
                addOpcode(3);
                return;
            }
        }
        addOpcode(1);
    }

    public void addIload(int n) {
        if (n < 4) {
            addOpcode(26 + n);
        } else if (n < 256) {
            addOpcode(21);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(21);
            addIndex(n);
        }
    }

    public void addIstore(int n) {
        if (n < 4) {
            addOpcode(59 + n);
        } else if (n < 256) {
            addOpcode(54);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(54);
            addIndex(n);
        }
    }

    public void addLconst(long n) {
        if (n == 0 || n == 1) {
            addOpcode(9 + ((int) n));
        } else {
            addLdc2w(n);
        }
    }

    public void addLload(int n) {
        if (n < 4) {
            addOpcode(30 + n);
        } else if (n < 256) {
            addOpcode(22);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(22);
            addIndex(n);
        }
    }

    public void addLstore(int n) {
        if (n < 4) {
            addOpcode(63 + n);
        } else if (n < 256) {
            addOpcode(55);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(55);
            addIndex(n);
        }
    }

    public void addDconst(double d) {
        if (d == 0.0d || d == 1.0d) {
            addOpcode(14 + ((int) d));
        } else {
            addLdc2w(d);
        }
    }

    public void addDload(int n) {
        if (n < 4) {
            addOpcode(38 + n);
        } else if (n < 256) {
            addOpcode(24);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(24);
            addIndex(n);
        }
    }

    public void addDstore(int n) {
        if (n < 4) {
            addOpcode(71 + n);
        } else if (n < 256) {
            addOpcode(57);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(57);
            addIndex(n);
        }
    }

    public void addFconst(float f) {
        if (f == 0.0f || f == 1.0f || f == 2.0f) {
            addOpcode(11 + ((int) f));
        } else {
            addLdc(this.constPool.addFloatInfo(f));
        }
    }

    public void addFload(int n) {
        if (n < 4) {
            addOpcode(34 + n);
        } else if (n < 256) {
            addOpcode(23);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(23);
            addIndex(n);
        }
    }

    public void addFstore(int n) {
        if (n < 4) {
            addOpcode(67 + n);
        } else if (n < 256) {
            addOpcode(56);
            add(n);
        } else {
            addOpcode(Opcode.WIDE);
            addOpcode(56);
            addIndex(n);
        }
    }

    public int addLoad(int n, CtClass type) {
        if (type.isPrimitive()) {
            if (type == CtClass.booleanType || type == CtClass.charType || type == CtClass.byteType || type == CtClass.shortType || type == CtClass.intType) {
                addIload(n);
                return 1;
            } else if (type == CtClass.longType) {
                addLload(n);
                return 2;
            } else if (type == CtClass.floatType) {
                addFload(n);
                return 1;
            } else if (type == CtClass.doubleType) {
                addDload(n);
                return 2;
            } else {
                throw new RuntimeException("void type?");
            }
        }
        addAload(n);
        return 1;
    }

    public int addStore(int n, CtClass type) {
        if (type.isPrimitive()) {
            if (type == CtClass.booleanType || type == CtClass.charType || type == CtClass.byteType || type == CtClass.shortType || type == CtClass.intType) {
                addIstore(n);
                return 1;
            } else if (type == CtClass.longType) {
                addLstore(n);
                return 2;
            } else if (type == CtClass.floatType) {
                addFstore(n);
                return 1;
            } else if (type == CtClass.doubleType) {
                addDstore(n);
                return 2;
            } else {
                throw new RuntimeException("void type?");
            }
        }
        addAstore(n);
        return 1;
    }

    public int addLoadParameters(CtClass[] params, int offset) {
        int stacksize = 0;
        if (params != null) {
            for (CtClass ctClass : params) {
                stacksize += addLoad(stacksize + offset, ctClass);
            }
        }
        return stacksize;
    }

    public void addCheckcast(CtClass c) {
        addOpcode(192);
        addIndex(this.constPool.addClassInfo(c));
    }

    public void addCheckcast(String classname) {
        addOpcode(192);
        addIndex(this.constPool.addClassInfo(classname));
    }

    public void addInstanceof(String classname) {
        addOpcode(Opcode.INSTANCEOF);
        addIndex(this.constPool.addClassInfo(classname));
    }

    public void addGetfield(CtClass c, String name, String type) {
        add(Opcode.GETFIELD);
        int ci = this.constPool.addClassInfo(c);
        addIndex(this.constPool.addFieldrefInfo(ci, name, type));
        growStack(Descriptor.dataSize(type) - 1);
    }

    public void addGetfield(String c, String name, String type) {
        add(Opcode.GETFIELD);
        int ci = this.constPool.addClassInfo(c);
        addIndex(this.constPool.addFieldrefInfo(ci, name, type));
        growStack(Descriptor.dataSize(type) - 1);
    }

    public void addGetstatic(CtClass c, String name, String type) {
        add(Opcode.GETSTATIC);
        int ci = this.constPool.addClassInfo(c);
        addIndex(this.constPool.addFieldrefInfo(ci, name, type));
        growStack(Descriptor.dataSize(type));
    }

    public void addGetstatic(String c, String name, String type) {
        add(Opcode.GETSTATIC);
        int ci = this.constPool.addClassInfo(c);
        addIndex(this.constPool.addFieldrefInfo(ci, name, type));
        growStack(Descriptor.dataSize(type));
    }

    public void addInvokespecial(CtClass clazz, String name, CtClass returnType, CtClass[] paramTypes) {
        String desc = Descriptor.ofMethod(returnType, paramTypes);
        addInvokespecial(clazz, name, desc);
    }

    public void addInvokespecial(CtClass clazz, String name, String desc) {
        boolean isInterface = clazz == null ? false : clazz.isInterface();
        addInvokespecial(isInterface, this.constPool.addClassInfo(clazz), name, desc);
    }

    public void addInvokespecial(String clazz, String name, String desc) {
        addInvokespecial(false, this.constPool.addClassInfo(clazz), name, desc);
    }

    public void addInvokespecial(int clazz, String name, String desc) {
        addInvokespecial(false, clazz, name, desc);
    }

    public void addInvokespecial(boolean isInterface, int clazz, String name, String desc) {
        int index;
        if (isInterface) {
            index = this.constPool.addInterfaceMethodrefInfo(clazz, name, desc);
        } else {
            index = this.constPool.addMethodrefInfo(clazz, name, desc);
        }
        addInvokespecial(index, desc);
    }

    public void addInvokespecial(int index, String desc) {
        add(Opcode.INVOKESPECIAL);
        addIndex(index);
        growStack(Descriptor.dataSize(desc) - 1);
    }

    public void addInvokestatic(CtClass clazz, String name, CtClass returnType, CtClass[] paramTypes) {
        String desc = Descriptor.ofMethod(returnType, paramTypes);
        addInvokestatic(clazz, name, desc);
    }

    public void addInvokestatic(CtClass clazz, String name, String desc) {
        boolean isInterface;
        if (clazz == THIS) {
            isInterface = false;
        } else {
            isInterface = clazz.isInterface();
        }
        addInvokestatic(this.constPool.addClassInfo(clazz), name, desc, isInterface);
    }

    public void addInvokestatic(String classname, String name, String desc) {
        addInvokestatic(this.constPool.addClassInfo(classname), name, desc);
    }

    public void addInvokestatic(int clazz, String name, String desc) {
        addInvokestatic(clazz, name, desc, false);
    }

    private void addInvokestatic(int clazz, String name, String desc, boolean isInterface) {
        int index;
        add(Opcode.INVOKESTATIC);
        if (isInterface) {
            index = this.constPool.addInterfaceMethodrefInfo(clazz, name, desc);
        } else {
            index = this.constPool.addMethodrefInfo(clazz, name, desc);
        }
        addIndex(index);
        growStack(Descriptor.dataSize(desc));
    }

    public void addInvokevirtual(CtClass clazz, String name, CtClass returnType, CtClass[] paramTypes) {
        String desc = Descriptor.ofMethod(returnType, paramTypes);
        addInvokevirtual(clazz, name, desc);
    }

    public void addInvokevirtual(CtClass clazz, String name, String desc) {
        addInvokevirtual(this.constPool.addClassInfo(clazz), name, desc);
    }

    public void addInvokevirtual(String classname, String name, String desc) {
        addInvokevirtual(this.constPool.addClassInfo(classname), name, desc);
    }

    public void addInvokevirtual(int clazz, String name, String desc) {
        add(Opcode.INVOKEVIRTUAL);
        addIndex(this.constPool.addMethodrefInfo(clazz, name, desc));
        growStack(Descriptor.dataSize(desc) - 1);
    }

    public void addInvokeinterface(CtClass clazz, String name, CtClass returnType, CtClass[] paramTypes, int count) {
        String desc = Descriptor.ofMethod(returnType, paramTypes);
        addInvokeinterface(clazz, name, desc, count);
    }

    public void addInvokeinterface(CtClass clazz, String name, String desc, int count) {
        addInvokeinterface(this.constPool.addClassInfo(clazz), name, desc, count);
    }

    public void addInvokeinterface(String classname, String name, String desc, int count) {
        addInvokeinterface(this.constPool.addClassInfo(classname), name, desc, count);
    }

    public void addInvokeinterface(int clazz, String name, String desc, int count) {
        add(Opcode.INVOKEINTERFACE);
        addIndex(this.constPool.addInterfaceMethodrefInfo(clazz, name, desc));
        add(count);
        add(0);
        growStack(Descriptor.dataSize(desc) - 1);
    }

    public void addInvokedynamic(int bootstrap, String name, String desc) {
        int nt = this.constPool.addNameAndTypeInfo(name, desc);
        int dyn = this.constPool.addInvokeDynamicInfo(bootstrap, nt);
        add(Opcode.INVOKEDYNAMIC);
        addIndex(dyn);
        add(0, 0);
        growStack(Descriptor.dataSize(desc));
    }

    public void addLdc(String s) {
        addLdc(this.constPool.addStringInfo(s));
    }

    public void addLdc(int i) {
        if (i > 255) {
            addOpcode(19);
            addIndex(i);
            return;
        }
        addOpcode(18);
        add(i);
    }

    public void addLdc2w(long l) {
        addOpcode(20);
        addIndex(this.constPool.addLongInfo(l));
    }

    public void addLdc2w(double d) {
        addOpcode(20);
        addIndex(this.constPool.addDoubleInfo(d));
    }

    public void addNew(CtClass clazz) {
        addOpcode(Opcode.NEW);
        addIndex(this.constPool.addClassInfo(clazz));
    }

    public void addNew(String classname) {
        addOpcode(Opcode.NEW);
        addIndex(this.constPool.addClassInfo(classname));
    }

    public void addAnewarray(String classname) {
        addOpcode(Opcode.ANEWARRAY);
        addIndex(this.constPool.addClassInfo(classname));
    }

    public void addAnewarray(CtClass clazz, int length) {
        addIconst(length);
        addOpcode(Opcode.ANEWARRAY);
        addIndex(this.constPool.addClassInfo(clazz));
    }

    public void addNewarray(int atype, int length) {
        addIconst(length);
        addOpcode(188);
        add(atype);
    }

    public int addMultiNewarray(CtClass clazz, int[] dimensions) {
        int len = dimensions.length;
        for (int i : dimensions) {
            addIconst(i);
        }
        growStack(len);
        return addMultiNewarray(clazz, len);
    }

    public int addMultiNewarray(CtClass clazz, int dim) {
        add(Opcode.MULTIANEWARRAY);
        addIndex(this.constPool.addClassInfo(clazz));
        add(dim);
        growStack(1 - dim);
        return dim;
    }

    public int addMultiNewarray(String desc, int dim) {
        add(Opcode.MULTIANEWARRAY);
        addIndex(this.constPool.addClassInfo(desc));
        add(dim);
        growStack(1 - dim);
        return dim;
    }

    public void addPutfield(CtClass c, String name, String desc) {
        addPutfield0(c, null, name, desc);
    }

    public void addPutfield(String classname, String name, String desc) {
        addPutfield0(null, classname, name, desc);
    }

    private void addPutfield0(CtClass target, String classname, String name, String desc) {
        add(Opcode.PUTFIELD);
        int ci = classname == null ? this.constPool.addClassInfo(target) : this.constPool.addClassInfo(classname);
        addIndex(this.constPool.addFieldrefInfo(ci, name, desc));
        growStack((-1) - Descriptor.dataSize(desc));
    }

    public void addPutstatic(CtClass c, String name, String desc) {
        addPutstatic0(c, null, name, desc);
    }

    public void addPutstatic(String classname, String fieldName, String desc) {
        addPutstatic0(null, classname, fieldName, desc);
    }

    private void addPutstatic0(CtClass target, String classname, String fieldName, String desc) {
        add(Opcode.PUTSTATIC);
        int ci = classname == null ? this.constPool.addClassInfo(target) : this.constPool.addClassInfo(classname);
        addIndex(this.constPool.addFieldrefInfo(ci, fieldName, desc));
        growStack(-Descriptor.dataSize(desc));
    }

    public void addReturn(CtClass type) {
        if (type == null) {
            addOpcode(Opcode.RETURN);
        } else if (type.isPrimitive()) {
            CtPrimitiveType ptype = (CtPrimitiveType) type;
            addOpcode(ptype.getReturnOp());
        } else {
            addOpcode(Opcode.ARETURN);
        }
    }

    public void addRet(int var) {
        if (var < 256) {
            addOpcode(Opcode.RET);
            add(var);
            return;
        }
        addOpcode(Opcode.WIDE);
        addOpcode(Opcode.RET);
        addIndex(var);
    }

    public void addPrintln(String message) {
        addGetstatic("java.lang.System", "err", "Ljava/io/PrintStream;");
        addLdc(message);
        addInvokevirtual("java.io.PrintStream", "println", "(Ljava/lang/String;)V");
    }
}