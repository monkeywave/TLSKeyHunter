package javassist.bytecode.stackmap;

import javassist.bytecode.BadBytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.ConstPool;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;
import javassist.bytecode.stackmap.BasicBlock;
import javassist.bytecode.stackmap.TypeData;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypedBlock.class */
public class TypedBlock extends BasicBlock {
    public int stackTop;
    public int numLocals;
    public TypeData[] localsTypes;
    public TypeData[] stackTypes;

    public static TypedBlock[] makeBlocks(MethodInfo minfo, CodeAttribute ca, boolean optimize) throws BadBytecode {
        TypedBlock[] blocks = (TypedBlock[]) new Maker().make(minfo);
        if (optimize && blocks.length < 2 && (blocks.length == 0 || blocks[0].incoming == 0)) {
            return null;
        }
        ConstPool pool = minfo.getConstPool();
        boolean isStatic = (minfo.getAccessFlags() & 8) != 0;
        blocks[0].initFirstBlock(ca.getMaxStack(), ca.getMaxLocals(), pool.getClassName(), minfo.getDescriptor(), isStatic, minfo.isConstructor());
        return blocks;
    }

    protected TypedBlock(int pos) {
        super(pos);
        this.localsTypes = null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javassist.bytecode.stackmap.BasicBlock
    public void toString2(StringBuffer sbuf) {
        super.toString2(sbuf);
        sbuf.append(",\n stack={");
        printTypes(sbuf, this.stackTop, this.stackTypes);
        sbuf.append("}, locals={");
        printTypes(sbuf, this.numLocals, this.localsTypes);
        sbuf.append('}');
    }

    private void printTypes(StringBuffer sbuf, int size, TypeData[] types) {
        if (types == null) {
            return;
        }
        for (int i = 0; i < size; i++) {
            if (i > 0) {
                sbuf.append(", ");
            }
            TypeData td = types[i];
            sbuf.append(td == null ? "<>" : td.toString());
        }
    }

    public boolean alreadySet() {
        return this.localsTypes != null;
    }

    public void setStackMap(int st, TypeData[] stack, int nl, TypeData[] locals) throws BadBytecode {
        this.stackTop = st;
        this.stackTypes = stack;
        this.numLocals = nl;
        this.localsTypes = locals;
    }

    public void resetNumLocals() {
        if (this.localsTypes != null) {
            int nl = this.localsTypes.length;
            while (nl > 0 && this.localsTypes[nl - 1].isBasicType() == TypeTag.TOP && (nl <= 1 || !this.localsTypes[nl - 2].is2WordType())) {
                nl--;
            }
            this.numLocals = nl;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypedBlock$Maker.class */
    public static class Maker extends BasicBlock.Maker {
        @Override // javassist.bytecode.stackmap.BasicBlock.Maker
        protected BasicBlock makeBlock(int pos) {
            return new TypedBlock(pos);
        }

        @Override // javassist.bytecode.stackmap.BasicBlock.Maker
        protected BasicBlock[] makeArray(int size) {
            return new TypedBlock[size];
        }
    }

    void initFirstBlock(int maxStack, int maxLocals, String className, String methodDesc, boolean isStatic, boolean isConstructor) throws BadBytecode {
        if (methodDesc.charAt(0) != '(') {
            throw new BadBytecode("no method descriptor: " + methodDesc);
        }
        this.stackTop = 0;
        this.stackTypes = TypeData.make(maxStack);
        TypeData[] locals = TypeData.make(maxLocals);
        if (isConstructor) {
            locals[0] = new TypeData.UninitThis(className);
        } else if (!isStatic) {
            locals[0] = new TypeData.ClassName(className);
        }
        int n = isStatic ? -1 : 0;
        int i = 1;
        while (true) {
            try {
                n++;
                int descToTag = descToTag(methodDesc, i, n, locals);
                i = descToTag;
                if (descToTag > 0) {
                    if (locals[n].is2WordType()) {
                        n++;
                        locals[n] = TypeTag.TOP;
                    }
                } else {
                    this.numLocals = n;
                    this.localsTypes = locals;
                    return;
                }
            } catch (StringIndexOutOfBoundsException e) {
                throw new BadBytecode("bad method descriptor: " + methodDesc);
            }
        }
    }

    private static int descToTag(String desc, int i, int n, TypeData[] types) throws BadBytecode {
        int i2;
        int arrayDim = 0;
        char c = desc.charAt(i);
        if (c == ')') {
            return 0;
        }
        while (c == '[') {
            arrayDim++;
            i++;
            c = desc.charAt(i);
        }
        if (c == 'L') {
            int i22 = desc.indexOf(59, i + 1);
            if (arrayDim > 0) {
                i2 = i22 + 1;
                types[n] = new TypeData.ClassName(desc.substring(i, i2));
            } else {
                i2 = i22 + 1;
                types[n] = new TypeData.ClassName(desc.substring(i + 1, i2 - 1).replace('/', '.'));
            }
            return i2;
        } else if (arrayDim > 0) {
            int i3 = i + 1;
            types[n] = new TypeData.ClassName(desc.substring(i, i3));
            return i3;
        } else {
            TypeData t = toPrimitiveTag(c);
            if (t == null) {
                throw new BadBytecode("bad method descriptor: " + desc);
            }
            types[n] = t;
            return i + 1;
        }
    }

    private static TypeData toPrimitiveTag(char c) {
        switch (c) {
            case 'B':
            case 'C':
            case 'I':
            case Opcode.AASTORE /* 83 */:
            case 'Z':
                return TypeTag.INTEGER;
            case 'D':
                return TypeTag.DOUBLE;
            case 'E':
            case Opcode.DSTORE_0 /* 71 */:
            case Opcode.DSTORE_1 /* 72 */:
            case Opcode.ASTORE_0 /* 75 */:
            case 'L':
            case Opcode.ASTORE_2 /* 77 */:
            case Opcode.ASTORE_3 /* 78 */:
            case Opcode.IASTORE /* 79 */:
            case Opcode.LASTORE /* 80 */:
            case Opcode.FASTORE /* 81 */:
            case 'R':
            case Opcode.BASTORE /* 84 */:
            case 'U':
            case Opcode.SASTORE /* 86 */:
            case Opcode.POP /* 87 */:
            case Opcode.POP2 /* 88 */:
            case Opcode.DUP /* 89 */:
            default:
                return null;
            case 'F':
                return TypeTag.FLOAT;
            case Opcode.DSTORE_3 /* 74 */:
                return TypeTag.LONG;
        }
    }

    public static String getRetType(String desc) {
        int i = desc.indexOf(41);
        if (i < 0) {
            return "java.lang.Object";
        }
        char c = desc.charAt(i + 1);
        if (c == '[') {
            return desc.substring(i + 1);
        }
        if (c == 'L') {
            return desc.substring(i + 2, desc.length() - 1).replace('/', '.');
        }
        return "java.lang.Object";
    }
}