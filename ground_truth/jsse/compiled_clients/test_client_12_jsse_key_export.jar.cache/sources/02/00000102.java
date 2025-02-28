package javassist.bytecode.stackmap;

import javassist.ClassPool;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.ByteArray;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.Opcode;
import javassist.bytecode.stackmap.TypeData;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/Tracer.class */
public abstract class Tracer implements TypeTag {
    protected ClassPool classPool;
    protected ConstPool cpool;
    protected String returnType;
    protected int stackTop;
    protected TypeData[] stackTypes;
    protected TypeData[] localsTypes;

    public Tracer(ClassPool classes, ConstPool cp, int maxStack, int maxLocals, String retType) {
        this.classPool = classes;
        this.cpool = cp;
        this.returnType = retType;
        this.stackTop = 0;
        this.stackTypes = TypeData.make(maxStack);
        this.localsTypes = TypeData.make(maxLocals);
    }

    public Tracer(Tracer t) {
        this.classPool = t.classPool;
        this.cpool = t.cpool;
        this.returnType = t.returnType;
        this.stackTop = t.stackTop;
        this.stackTypes = TypeData.make(t.stackTypes.length);
        this.localsTypes = TypeData.make(t.localsTypes.length);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int doOpcode(int pos, byte[] code) throws BadBytecode {
        try {
            int op = code[pos] & 255;
            if (op < 54) {
                return doOpcode0_53(pos, code, op);
            }
            if (op < 96) {
                return doOpcode54_95(pos, code, op);
            }
            if (op < 148) {
                return doOpcode96_147(pos, code, op);
            }
            return doOpcode148_201(pos, code, op);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new BadBytecode("inconsistent stack height " + e.getMessage(), e);
        }
    }

    protected void visitBranch(int pos, byte[] code, int offset) throws BadBytecode {
    }

    protected void visitGoto(int pos, byte[] code, int offset) throws BadBytecode {
    }

    protected void visitReturn(int pos, byte[] code) throws BadBytecode {
    }

    protected void visitThrow(int pos, byte[] code) throws BadBytecode {
    }

    protected void visitTableSwitch(int pos, byte[] code, int n, int offsetPos, int defaultOffset) throws BadBytecode {
    }

    protected void visitLookupSwitch(int pos, byte[] code, int n, int pairsPos, int defaultOffset) throws BadBytecode {
    }

    protected void visitJSR(int pos, byte[] code) throws BadBytecode {
    }

    protected void visitRET(int pos, byte[] code) throws BadBytecode {
    }

    private int doOpcode0_53(int pos, byte[] code, int op) throws BadBytecode {
        TypeData[] stackTypes = this.stackTypes;
        switch (op) {
            case 0:
                return 1;
            case 1:
                int i = this.stackTop;
                this.stackTop = i + 1;
                stackTypes[i] = new TypeData.NullType();
                return 1;
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
                int i2 = this.stackTop;
                this.stackTop = i2 + 1;
                stackTypes[i2] = INTEGER;
                return 1;
            case 9:
            case 10:
                int i3 = this.stackTop;
                this.stackTop = i3 + 1;
                stackTypes[i3] = LONG;
                int i4 = this.stackTop;
                this.stackTop = i4 + 1;
                stackTypes[i4] = TOP;
                return 1;
            case 11:
            case 12:
            case 13:
                int i5 = this.stackTop;
                this.stackTop = i5 + 1;
                stackTypes[i5] = FLOAT;
                return 1;
            case 14:
            case 15:
                int i6 = this.stackTop;
                this.stackTop = i6 + 1;
                stackTypes[i6] = DOUBLE;
                int i7 = this.stackTop;
                this.stackTop = i7 + 1;
                stackTypes[i7] = TOP;
                return 1;
            case 16:
            case 17:
                int i8 = this.stackTop;
                this.stackTop = i8 + 1;
                stackTypes[i8] = INTEGER;
                return op == 17 ? 3 : 2;
            case 18:
                doLDC(code[pos + 1] & 255);
                return 2;
            case 19:
            case 20:
                doLDC(ByteArray.readU16bit(code, pos + 1));
                return 3;
            case 21:
                return doXLOAD(INTEGER, code, pos);
            case 22:
                return doXLOAD(LONG, code, pos);
            case 23:
                return doXLOAD(FLOAT, code, pos);
            case 24:
                return doXLOAD(DOUBLE, code, pos);
            case 25:
                return doALOAD(code[pos + 1] & 255);
            case 26:
            case 27:
            case 28:
            case 29:
                int i9 = this.stackTop;
                this.stackTop = i9 + 1;
                stackTypes[i9] = INTEGER;
                return 1;
            case 30:
            case Opcode.LLOAD_1 /* 31 */:
            case 32:
            case Opcode.LLOAD_3 /* 33 */:
                int i10 = this.stackTop;
                this.stackTop = i10 + 1;
                stackTypes[i10] = LONG;
                int i11 = this.stackTop;
                this.stackTop = i11 + 1;
                stackTypes[i11] = TOP;
                return 1;
            case Opcode.FLOAD_0 /* 34 */:
            case 35:
            case Opcode.FLOAD_2 /* 36 */:
            case Opcode.FLOAD_3 /* 37 */:
                int i12 = this.stackTop;
                this.stackTop = i12 + 1;
                stackTypes[i12] = FLOAT;
                return 1;
            case Opcode.DLOAD_0 /* 38 */:
            case Opcode.DLOAD_1 /* 39 */:
            case 40:
            case Opcode.DLOAD_3 /* 41 */:
                int i13 = this.stackTop;
                this.stackTop = i13 + 1;
                stackTypes[i13] = DOUBLE;
                int i14 = this.stackTop;
                this.stackTop = i14 + 1;
                stackTypes[i14] = TOP;
                return 1;
            case Opcode.ALOAD_0 /* 42 */:
            case Opcode.ALOAD_1 /* 43 */:
            case Opcode.ALOAD_2 /* 44 */:
            case 45:
                int reg = op - 42;
                int i15 = this.stackTop;
                this.stackTop = i15 + 1;
                stackTypes[i15] = this.localsTypes[reg];
                return 1;
            case 46:
                int i16 = this.stackTop - 1;
                this.stackTop = i16;
                stackTypes[i16 - 1] = INTEGER;
                return 1;
            case 47:
                stackTypes[this.stackTop - 2] = LONG;
                stackTypes[this.stackTop - 1] = TOP;
                return 1;
            case 48:
                int i17 = this.stackTop - 1;
                this.stackTop = i17;
                stackTypes[i17 - 1] = FLOAT;
                return 1;
            case 49:
                stackTypes[this.stackTop - 2] = DOUBLE;
                stackTypes[this.stackTop - 1] = TOP;
                return 1;
            case 50:
                int i18 = this.stackTop - 1;
                this.stackTop = i18;
                int s = i18 - 1;
                TypeData data = stackTypes[s];
                stackTypes[s] = TypeData.ArrayElement.make(data);
                return 1;
            case 51:
            case 52:
            case 53:
                int i19 = this.stackTop - 1;
                this.stackTop = i19;
                stackTypes[i19 - 1] = INTEGER;
                return 1;
            default:
                throw new RuntimeException("fatal");
        }
    }

    private void doLDC(int index) {
        TypeData[] stackTypes = this.stackTypes;
        int tag = this.cpool.getTag(index);
        if (tag == 8) {
            int i = this.stackTop;
            this.stackTop = i + 1;
            stackTypes[i] = new TypeData.ClassName("java.lang.String");
        } else if (tag == 3) {
            int i2 = this.stackTop;
            this.stackTop = i2 + 1;
            stackTypes[i2] = INTEGER;
        } else if (tag == 4) {
            int i3 = this.stackTop;
            this.stackTop = i3 + 1;
            stackTypes[i3] = FLOAT;
        } else if (tag == 5) {
            int i4 = this.stackTop;
            this.stackTop = i4 + 1;
            stackTypes[i4] = LONG;
            int i5 = this.stackTop;
            this.stackTop = i5 + 1;
            stackTypes[i5] = TOP;
        } else if (tag == 6) {
            int i6 = this.stackTop;
            this.stackTop = i6 + 1;
            stackTypes[i6] = DOUBLE;
            int i7 = this.stackTop;
            this.stackTop = i7 + 1;
            stackTypes[i7] = TOP;
        } else if (tag == 7) {
            int i8 = this.stackTop;
            this.stackTop = i8 + 1;
            stackTypes[i8] = new TypeData.ClassName("java.lang.Class");
        } else if (tag == 17) {
            String desc = this.cpool.getDynamicType(index);
            pushMemberType(desc);
        } else {
            throw new RuntimeException("bad LDC: " + tag);
        }
    }

    private int doXLOAD(TypeData type, byte[] code, int pos) {
        int localVar = code[pos + 1] & 255;
        return doXLOAD(localVar, type);
    }

    private int doXLOAD(int localVar, TypeData type) {
        TypeData[] typeDataArr = this.stackTypes;
        int i = this.stackTop;
        this.stackTop = i + 1;
        typeDataArr[i] = type;
        if (type.is2WordType()) {
            TypeData[] typeDataArr2 = this.stackTypes;
            int i2 = this.stackTop;
            this.stackTop = i2 + 1;
            typeDataArr2[i2] = TOP;
            return 2;
        }
        return 2;
    }

    private int doALOAD(int localVar) {
        TypeData[] typeDataArr = this.stackTypes;
        int i = this.stackTop;
        this.stackTop = i + 1;
        typeDataArr[i] = this.localsTypes[localVar];
        return 2;
    }

    private int doOpcode54_95(int pos, byte[] code, int op) throws BadBytecode {
        switch (op) {
            case 54:
                return doXSTORE(pos, code, INTEGER);
            case 55:
                return doXSTORE(pos, code, LONG);
            case 56:
                return doXSTORE(pos, code, FLOAT);
            case 57:
                return doXSTORE(pos, code, DOUBLE);
            case Opcode.ASTORE /* 58 */:
                return doASTORE(code[pos + 1] & 255);
            case Opcode.ISTORE_0 /* 59 */:
            case 60:
            case Opcode.ISTORE_2 /* 61 */:
            case Opcode.ISTORE_3 /* 62 */:
                this.localsTypes[op - 59] = INTEGER;
                this.stackTop--;
                return 1;
            case 63:
            case 64:
            case 65:
            case 66:
                int var = op - 63;
                this.localsTypes[var] = LONG;
                this.localsTypes[var + 1] = TOP;
                this.stackTop -= 2;
                return 1;
            case 67:
            case 68:
            case 69:
            case 70:
                this.localsTypes[op - 67] = FLOAT;
                this.stackTop--;
                return 1;
            case Opcode.DSTORE_0 /* 71 */:
            case Opcode.DSTORE_1 /* 72 */:
            case 73:
            case Opcode.DSTORE_3 /* 74 */:
                int var2 = op - 71;
                this.localsTypes[var2] = DOUBLE;
                this.localsTypes[var2 + 1] = TOP;
                this.stackTop -= 2;
                return 1;
            case Opcode.ASTORE_0 /* 75 */:
            case 76:
            case Opcode.ASTORE_2 /* 77 */:
            case Opcode.ASTORE_3 /* 78 */:
                doASTORE(op - 75);
                return 1;
            case Opcode.IASTORE /* 79 */:
            case Opcode.LASTORE /* 80 */:
            case Opcode.FASTORE /* 81 */:
            case 82:
                this.stackTop -= (op == 80 || op == 82) ? 4 : 3;
                return 1;
            case Opcode.AASTORE /* 83 */:
                TypeData.ArrayElement.aastore(this.stackTypes[this.stackTop - 3], this.stackTypes[this.stackTop - 1], this.classPool);
                this.stackTop -= 3;
                return 1;
            case Opcode.BASTORE /* 84 */:
            case 85:
            case Opcode.SASTORE /* 86 */:
                this.stackTop -= 3;
                return 1;
            case Opcode.POP /* 87 */:
                this.stackTop--;
                return 1;
            case Opcode.POP2 /* 88 */:
                this.stackTop -= 2;
                return 1;
            case Opcode.DUP /* 89 */:
                int sp = this.stackTop;
                this.stackTypes[sp] = this.stackTypes[sp - 1];
                this.stackTop = sp + 1;
                return 1;
            case 90:
            case Opcode.DUP_X2 /* 91 */:
                int len = (op - 90) + 2;
                doDUP_XX(1, len);
                int sp2 = this.stackTop;
                this.stackTypes[sp2 - len] = this.stackTypes[sp2];
                this.stackTop = sp2 + 1;
                return 1;
            case Opcode.DUP2 /* 92 */:
                doDUP_XX(2, 2);
                this.stackTop += 2;
                return 1;
            case Opcode.DUP2_X1 /* 93 */:
            case Opcode.DUP2_X2 /* 94 */:
                int len2 = (op - 93) + 3;
                doDUP_XX(2, len2);
                int sp3 = this.stackTop;
                this.stackTypes[sp3 - len2] = this.stackTypes[sp3];
                this.stackTypes[(sp3 - len2) + 1] = this.stackTypes[sp3 + 1];
                this.stackTop = sp3 + 2;
                return 1;
            case Opcode.SWAP /* 95 */:
                int sp4 = this.stackTop - 1;
                TypeData t = this.stackTypes[sp4];
                this.stackTypes[sp4] = this.stackTypes[sp4 - 1];
                this.stackTypes[sp4 - 1] = t;
                return 1;
            default:
                throw new RuntimeException("fatal");
        }
    }

    private int doXSTORE(int pos, byte[] code, TypeData type) {
        int index = code[pos + 1] & 255;
        return doXSTORE(index, type);
    }

    private int doXSTORE(int index, TypeData type) {
        this.stackTop--;
        this.localsTypes[index] = type;
        if (type.is2WordType()) {
            this.stackTop--;
            this.localsTypes[index + 1] = TOP;
            return 2;
        }
        return 2;
    }

    private int doASTORE(int index) {
        this.stackTop--;
        this.localsTypes[index] = this.stackTypes[this.stackTop];
        return 2;
    }

    private void doDUP_XX(int delta, int len) {
        TypeData[] types = this.stackTypes;
        int sp = this.stackTop - 1;
        int end = sp - len;
        while (sp > end) {
            types[sp + delta] = types[sp];
            sp--;
        }
    }

    private int doOpcode96_147(int pos, byte[] code, int op) {
        if (op <= 131) {
            this.stackTop += Opcode.STACK_GROW[op];
            return 1;
        }
        switch (op) {
            case Opcode.IINC /* 132 */:
                return 3;
            case Opcode.I2L /* 133 */:
                this.stackTypes[this.stackTop - 1] = LONG;
                this.stackTypes[this.stackTop] = TOP;
                this.stackTop++;
                return 1;
            case Opcode.I2F /* 134 */:
                this.stackTypes[this.stackTop - 1] = FLOAT;
                return 1;
            case Opcode.I2D /* 135 */:
                this.stackTypes[this.stackTop - 1] = DOUBLE;
                this.stackTypes[this.stackTop] = TOP;
                this.stackTop++;
                return 1;
            case Opcode.L2I /* 136 */:
                TypeData[] typeDataArr = this.stackTypes;
                int i = this.stackTop - 1;
                this.stackTop = i;
                typeDataArr[i - 1] = INTEGER;
                return 1;
            case Opcode.L2F /* 137 */:
                TypeData[] typeDataArr2 = this.stackTypes;
                int i2 = this.stackTop - 1;
                this.stackTop = i2;
                typeDataArr2[i2 - 1] = FLOAT;
                return 1;
            case Opcode.L2D /* 138 */:
                this.stackTypes[this.stackTop - 2] = DOUBLE;
                return 1;
            case Opcode.F2I /* 139 */:
                this.stackTypes[this.stackTop - 1] = INTEGER;
                return 1;
            case Opcode.F2L /* 140 */:
                this.stackTypes[this.stackTop - 1] = LONG;
                this.stackTypes[this.stackTop] = TOP;
                this.stackTop++;
                return 1;
            case Opcode.F2D /* 141 */:
                this.stackTypes[this.stackTop - 1] = DOUBLE;
                this.stackTypes[this.stackTop] = TOP;
                this.stackTop++;
                return 1;
            case Opcode.D2I /* 142 */:
                TypeData[] typeDataArr3 = this.stackTypes;
                int i3 = this.stackTop - 1;
                this.stackTop = i3;
                typeDataArr3[i3 - 1] = INTEGER;
                return 1;
            case Opcode.D2L /* 143 */:
                this.stackTypes[this.stackTop - 2] = LONG;
                return 1;
            case Opcode.D2F /* 144 */:
                TypeData[] typeDataArr4 = this.stackTypes;
                int i4 = this.stackTop - 1;
                this.stackTop = i4;
                typeDataArr4[i4 - 1] = FLOAT;
                return 1;
            case Opcode.I2B /* 145 */:
            case Opcode.I2C /* 146 */:
            case Opcode.I2S /* 147 */:
                return 1;
            default:
                throw new RuntimeException("fatal");
        }
    }

    private int doOpcode148_201(int pos, byte[] code, int op) throws BadBytecode {
        String type;
        switch (op) {
            case Opcode.LCMP /* 148 */:
                this.stackTypes[this.stackTop - 4] = INTEGER;
                this.stackTop -= 3;
                return 1;
            case Opcode.FCMPL /* 149 */:
            case Opcode.FCMPG /* 150 */:
                TypeData[] typeDataArr = this.stackTypes;
                int i = this.stackTop - 1;
                this.stackTop = i;
                typeDataArr[i - 1] = INTEGER;
                return 1;
            case Opcode.DCMPL /* 151 */:
            case Opcode.DCMPG /* 152 */:
                this.stackTypes[this.stackTop - 4] = INTEGER;
                this.stackTop -= 3;
                return 1;
            case Opcode.IFEQ /* 153 */:
            case Opcode.IFNE /* 154 */:
            case Opcode.IFLT /* 155 */:
            case Opcode.IFGE /* 156 */:
            case Opcode.IFGT /* 157 */:
            case Opcode.IFLE /* 158 */:
                this.stackTop--;
                visitBranch(pos, code, ByteArray.readS16bit(code, pos + 1));
                return 3;
            case Opcode.IF_ICMPEQ /* 159 */:
            case Opcode.IF_ICMPNE /* 160 */:
            case Opcode.IF_ICMPLT /* 161 */:
            case Opcode.IF_ICMPGE /* 162 */:
            case Opcode.IF_ICMPGT /* 163 */:
            case Opcode.IF_ICMPLE /* 164 */:
            case Opcode.IF_ACMPEQ /* 165 */:
            case Opcode.IF_ACMPNE /* 166 */:
                this.stackTop -= 2;
                visitBranch(pos, code, ByteArray.readS16bit(code, pos + 1));
                return 3;
            case Opcode.GOTO /* 167 */:
                visitGoto(pos, code, ByteArray.readS16bit(code, pos + 1));
                return 3;
            case Opcode.JSR /* 168 */:
                visitJSR(pos, code);
                return 3;
            case Opcode.RET /* 169 */:
                visitRET(pos, code);
                return 2;
            case Opcode.TABLESWITCH /* 170 */:
                this.stackTop--;
                int pos2 = (pos & (-4)) + 8;
                int low = ByteArray.read32bit(code, pos2);
                int high = ByteArray.read32bit(code, pos2 + 4);
                int n = (high - low) + 1;
                visitTableSwitch(pos, code, n, pos2 + 8, ByteArray.read32bit(code, pos2 - 4));
                return ((n * 4) + 16) - (pos & 3);
            case Opcode.LOOKUPSWITCH /* 171 */:
                this.stackTop--;
                int pos22 = (pos & (-4)) + 8;
                int n2 = ByteArray.read32bit(code, pos22);
                visitLookupSwitch(pos, code, n2, pos22 + 4, ByteArray.read32bit(code, pos22 - 4));
                return ((n2 * 8) + 12) - (pos & 3);
            case Opcode.IRETURN /* 172 */:
                this.stackTop--;
                visitReturn(pos, code);
                return 1;
            case Opcode.LRETURN /* 173 */:
                this.stackTop -= 2;
                visitReturn(pos, code);
                return 1;
            case Opcode.FRETURN /* 174 */:
                this.stackTop--;
                visitReturn(pos, code);
                return 1;
            case Opcode.DRETURN /* 175 */:
                this.stackTop -= 2;
                visitReturn(pos, code);
                return 1;
            case Opcode.ARETURN /* 176 */:
                TypeData[] typeDataArr2 = this.stackTypes;
                int i2 = this.stackTop - 1;
                this.stackTop = i2;
                typeDataArr2[i2].setType(this.returnType, this.classPool);
                visitReturn(pos, code);
                return 1;
            case Opcode.RETURN /* 177 */:
                visitReturn(pos, code);
                return 1;
            case Opcode.GETSTATIC /* 178 */:
                return doGetField(pos, code, false);
            case Opcode.PUTSTATIC /* 179 */:
                return doPutField(pos, code, false);
            case Opcode.GETFIELD /* 180 */:
                return doGetField(pos, code, true);
            case Opcode.PUTFIELD /* 181 */:
                return doPutField(pos, code, true);
            case Opcode.INVOKEVIRTUAL /* 182 */:
            case Opcode.INVOKESPECIAL /* 183 */:
                return doInvokeMethod(pos, code, true);
            case Opcode.INVOKESTATIC /* 184 */:
                return doInvokeMethod(pos, code, false);
            case Opcode.INVOKEINTERFACE /* 185 */:
                return doInvokeIntfMethod(pos, code);
            case Opcode.INVOKEDYNAMIC /* 186 */:
                return doInvokeDynamic(pos, code);
            case Opcode.NEW /* 187 */:
                int i3 = ByteArray.readU16bit(code, pos + 1);
                TypeData[] typeDataArr3 = this.stackTypes;
                int i4 = this.stackTop;
                this.stackTop = i4 + 1;
                typeDataArr3[i4] = new TypeData.UninitData(pos, this.cpool.getClassInfo(i3));
                return 3;
            case 188:
                return doNEWARRAY(pos, code);
            case Opcode.ANEWARRAY /* 189 */:
                int i5 = ByteArray.readU16bit(code, pos + 1);
                String type2 = this.cpool.getClassInfo(i5).replace('.', '/');
                if (type2.charAt(0) == '[') {
                    type = "[" + type2;
                } else {
                    type = "[L" + type2 + ";";
                }
                this.stackTypes[this.stackTop - 1] = new TypeData.ClassName(type);
                return 3;
            case Opcode.ARRAYLENGTH /* 190 */:
                this.stackTypes[this.stackTop - 1].setType("[Ljava.lang.Object;", this.classPool);
                this.stackTypes[this.stackTop - 1] = INTEGER;
                return 1;
            case Opcode.ATHROW /* 191 */:
                TypeData[] typeDataArr4 = this.stackTypes;
                int i6 = this.stackTop - 1;
                this.stackTop = i6;
                typeDataArr4[i6].setType("java.lang.Throwable", this.classPool);
                visitThrow(pos, code);
                return 1;
            case 192:
                int i7 = ByteArray.readU16bit(code, pos + 1);
                String type3 = this.cpool.getClassInfo(i7);
                if (type3.charAt(0) == '[') {
                    type3 = type3.replace('.', '/');
                }
                this.stackTypes[this.stackTop - 1] = new TypeData.ClassName(type3);
                return 3;
            case Opcode.INSTANCEOF /* 193 */:
                this.stackTypes[this.stackTop - 1] = INTEGER;
                return 3;
            case Opcode.MONITORENTER /* 194 */:
            case Opcode.MONITOREXIT /* 195 */:
                this.stackTop--;
                return 1;
            case Opcode.WIDE /* 196 */:
                return doWIDE(pos, code);
            case Opcode.MULTIANEWARRAY /* 197 */:
                return doMultiANewArray(pos, code);
            case Opcode.IFNULL /* 198 */:
            case Opcode.IFNONNULL /* 199 */:
                this.stackTop--;
                visitBranch(pos, code, ByteArray.readS16bit(code, pos + 1));
                return 3;
            case 200:
                visitGoto(pos, code, ByteArray.read32bit(code, pos + 1));
                return 5;
            case Opcode.JSR_W /* 201 */:
                visitJSR(pos, code);
                return 5;
            default:
                return 1;
        }
    }

    private int doWIDE(int pos, byte[] code) throws BadBytecode {
        int op = code[pos + 1] & 255;
        switch (op) {
            case 21:
                doWIDE_XLOAD(pos, code, INTEGER);
                return 4;
            case 22:
                doWIDE_XLOAD(pos, code, LONG);
                return 4;
            case 23:
                doWIDE_XLOAD(pos, code, FLOAT);
                return 4;
            case 24:
                doWIDE_XLOAD(pos, code, DOUBLE);
                return 4;
            case 25:
                int index = ByteArray.readU16bit(code, pos + 2);
                doALOAD(index);
                return 4;
            case 54:
                doWIDE_STORE(pos, code, INTEGER);
                return 4;
            case 55:
                doWIDE_STORE(pos, code, LONG);
                return 4;
            case 56:
                doWIDE_STORE(pos, code, FLOAT);
                return 4;
            case 57:
                doWIDE_STORE(pos, code, DOUBLE);
                return 4;
            case Opcode.ASTORE /* 58 */:
                int index2 = ByteArray.readU16bit(code, pos + 2);
                doASTORE(index2);
                return 4;
            case Opcode.IINC /* 132 */:
                return 6;
            case Opcode.RET /* 169 */:
                visitRET(pos, code);
                return 4;
            default:
                throw new RuntimeException("bad WIDE instruction: " + op);
        }
    }

    private void doWIDE_XLOAD(int pos, byte[] code, TypeData type) {
        int index = ByteArray.readU16bit(code, pos + 2);
        doXLOAD(index, type);
    }

    private void doWIDE_STORE(int pos, byte[] code, TypeData type) {
        int index = ByteArray.readU16bit(code, pos + 2);
        doXSTORE(index, type);
    }

    private int doPutField(int pos, byte[] code, boolean notStatic) throws BadBytecode {
        int index = ByteArray.readU16bit(code, pos + 1);
        String desc = this.cpool.getFieldrefType(index);
        this.stackTop -= Descriptor.dataSize(desc);
        char c = desc.charAt(0);
        if (c == 'L') {
            this.stackTypes[this.stackTop].setType(getFieldClassName(desc, 0), this.classPool);
        } else if (c == '[') {
            this.stackTypes[this.stackTop].setType(desc, this.classPool);
        }
        setFieldTarget(notStatic, index);
        return 3;
    }

    private int doGetField(int pos, byte[] code, boolean notStatic) throws BadBytecode {
        int index = ByteArray.readU16bit(code, pos + 1);
        setFieldTarget(notStatic, index);
        String desc = this.cpool.getFieldrefType(index);
        pushMemberType(desc);
        return 3;
    }

    private void setFieldTarget(boolean notStatic, int index) throws BadBytecode {
        if (notStatic) {
            String className = this.cpool.getFieldrefClassName(index);
            TypeData[] typeDataArr = this.stackTypes;
            int i = this.stackTop - 1;
            this.stackTop = i;
            typeDataArr[i].setType(className, this.classPool);
        }
    }

    private int doNEWARRAY(int pos, byte[] code) {
        String type;
        int s = this.stackTop - 1;
        switch (code[pos + 1] & 255) {
            case 4:
                type = "[Z";
                break;
            case 5:
                type = "[C";
                break;
            case 6:
                type = "[F";
                break;
            case 7:
                type = "[D";
                break;
            case 8:
                type = "[B";
                break;
            case 9:
                type = "[S";
                break;
            case 10:
                type = "[I";
                break;
            case 11:
                type = "[J";
                break;
            default:
                throw new RuntimeException("bad newarray");
        }
        this.stackTypes[s] = new TypeData.ClassName(type);
        return 2;
    }

    private int doMultiANewArray(int pos, byte[] code) {
        int i = ByteArray.readU16bit(code, pos + 1);
        int dim = code[pos + 3] & 255;
        this.stackTop -= dim - 1;
        String type = this.cpool.getClassInfo(i).replace('.', '/');
        this.stackTypes[this.stackTop - 1] = new TypeData.ClassName(type);
        return 4;
    }

    private int doInvokeMethod(int pos, byte[] code, boolean notStatic) throws BadBytecode {
        int i = ByteArray.readU16bit(code, pos + 1);
        String desc = this.cpool.getMethodrefType(i);
        checkParamTypes(desc, 1);
        if (notStatic) {
            String className = this.cpool.getMethodrefClassName(i);
            TypeData[] typeDataArr = this.stackTypes;
            int i2 = this.stackTop - 1;
            this.stackTop = i2;
            TypeData target = typeDataArr[i2];
            if ((target instanceof TypeData.UninitTypeVar) && target.isUninit()) {
                constructorCalled(target, ((TypeData.UninitTypeVar) target).offset());
            } else if (target instanceof TypeData.UninitData) {
                constructorCalled(target, ((TypeData.UninitData) target).offset());
            }
            target.setType(className, this.classPool);
        }
        pushMemberType(desc);
        return 3;
    }

    private void constructorCalled(TypeData target, int offset) {
        target.constructorCalled(offset);
        for (int i = 0; i < this.stackTop; i++) {
            this.stackTypes[i].constructorCalled(offset);
        }
        for (int i2 = 0; i2 < this.localsTypes.length; i2++) {
            this.localsTypes[i2].constructorCalled(offset);
        }
    }

    private int doInvokeIntfMethod(int pos, byte[] code) throws BadBytecode {
        int i = ByteArray.readU16bit(code, pos + 1);
        String desc = this.cpool.getInterfaceMethodrefType(i);
        checkParamTypes(desc, 1);
        String className = this.cpool.getInterfaceMethodrefClassName(i);
        TypeData[] typeDataArr = this.stackTypes;
        int i2 = this.stackTop - 1;
        this.stackTop = i2;
        typeDataArr[i2].setType(className, this.classPool);
        pushMemberType(desc);
        return 5;
    }

    private int doInvokeDynamic(int pos, byte[] code) throws BadBytecode {
        int i = ByteArray.readU16bit(code, pos + 1);
        String desc = this.cpool.getInvokeDynamicType(i);
        checkParamTypes(desc, 1);
        pushMemberType(desc);
        return 5;
    }

    private void pushMemberType(String descriptor) {
        int top = 0;
        if (descriptor.charAt(0) == '(') {
            top = descriptor.indexOf(41) + 1;
            if (top < 1) {
                throw new IndexOutOfBoundsException("bad descriptor: " + descriptor);
            }
        }
        TypeData[] types = this.stackTypes;
        int index = this.stackTop;
        switch (descriptor.charAt(top)) {
            case 'D':
                types[index] = DOUBLE;
                types[index + 1] = TOP;
                this.stackTop += 2;
                return;
            case 'F':
                types[index] = FLOAT;
                break;
            case Opcode.DSTORE_3 /* 74 */:
                types[index] = LONG;
                types[index + 1] = TOP;
                this.stackTop += 2;
                return;
            case 'L':
                types[index] = new TypeData.ClassName(getFieldClassName(descriptor, top));
                break;
            case Opcode.SASTORE /* 86 */:
                return;
            case Opcode.DUP_X2 /* 91 */:
                types[index] = new TypeData.ClassName(descriptor.substring(top));
                break;
            default:
                types[index] = INTEGER;
                break;
        }
        this.stackTop++;
    }

    private static String getFieldClassName(String desc, int index) {
        return desc.substring(index + 1, desc.length() - 1).replace('/', '.');
    }

    private void checkParamTypes(String desc, int i) throws BadBytecode {
        int k;
        char c = desc.charAt(i);
        if (c == ')') {
            return;
        }
        int k2 = i;
        boolean array = false;
        while (c == '[') {
            array = true;
            k2++;
            c = desc.charAt(k2);
        }
        if (c == 'L') {
            k = desc.indexOf(59, k2) + 1;
            if (k <= 0) {
                throw new IndexOutOfBoundsException("bad descriptor");
            }
        } else {
            k = k2 + 1;
        }
        checkParamTypes(desc, k);
        if (!array && (c == 'J' || c == 'D')) {
            this.stackTop -= 2;
        } else {
            this.stackTop--;
        }
        if (array) {
            this.stackTypes[this.stackTop].setType(desc.substring(i, k), this.classPool);
        } else if (c == 'L') {
            this.stackTypes[this.stackTop].setType(desc.substring(i + 1, k - 1).replace('/', '.'), this.classPool);
        }
    }
}