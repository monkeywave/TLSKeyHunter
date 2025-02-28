package javassist.bytecode;

import java.io.PrintStream;
import javassist.CtMethod;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/InstructionPrinter.class */
public class InstructionPrinter implements Opcode {
    private static final String[] opcodes = Mnemonic.OPCODE;
    private final PrintStream stream;

    public InstructionPrinter(PrintStream stream) {
        this.stream = stream;
    }

    public static void print(CtMethod method, PrintStream stream) {
        new InstructionPrinter(stream).print(method);
    }

    public void print(CtMethod method) {
        MethodInfo info = method.getMethodInfo2();
        ConstPool pool = info.getConstPool();
        CodeAttribute code = info.getCodeAttribute();
        if (code == null) {
            return;
        }
        CodeIterator iterator = code.iterator();
        while (iterator.hasNext()) {
            try {
                int pos = iterator.next();
                this.stream.println(pos + ": " + instructionString(iterator, pos, pool));
            } catch (BadBytecode e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static String instructionString(CodeIterator iter, int pos, ConstPool pool) {
        int opcode = iter.byteAt(pos);
        if (opcode > opcodes.length || opcode < 0) {
            throw new IllegalArgumentException("Invalid opcode, opcode: " + opcode + " pos: " + pos);
        }
        String opstring = opcodes[opcode];
        switch (opcode) {
            case 16:
                return opstring + " " + iter.byteAt(pos + 1);
            case 17:
                return opstring + " " + iter.s16bitAt(pos + 1);
            case 18:
                return opstring + " " + ldc(pool, iter.byteAt(pos + 1));
            case 19:
            case 20:
                return opstring + " " + ldc(pool, iter.u16bitAt(pos + 1));
            case 21:
            case 22:
            case 23:
            case 24:
            case 25:
            case 54:
            case 55:
            case 56:
            case 57:
            case Opcode.ASTORE /* 58 */:
                return opstring + " " + iter.byteAt(pos + 1);
            case 26:
            case 27:
            case 28:
            case 29:
            case 30:
            case Opcode.LLOAD_1 /* 31 */:
            case 32:
            case Opcode.LLOAD_3 /* 33 */:
            case Opcode.FLOAD_0 /* 34 */:
            case 35:
            case Opcode.FLOAD_2 /* 36 */:
            case Opcode.FLOAD_3 /* 37 */:
            case Opcode.DLOAD_0 /* 38 */:
            case Opcode.DLOAD_1 /* 39 */:
            case 40:
            case Opcode.DLOAD_3 /* 41 */:
            case Opcode.ALOAD_0 /* 42 */:
            case Opcode.ALOAD_1 /* 43 */:
            case Opcode.ALOAD_2 /* 44 */:
            case 45:
            case 46:
            case 47:
            case 48:
            case 49:
            case 50:
            case 51:
            case 52:
            case 53:
            case Opcode.ISTORE_0 /* 59 */:
            case 60:
            case Opcode.ISTORE_2 /* 61 */:
            case Opcode.ISTORE_3 /* 62 */:
            case 63:
            case 64:
            case 65:
            case 66:
            case 67:
            case 68:
            case 69:
            case 70:
            case Opcode.DSTORE_0 /* 71 */:
            case Opcode.DSTORE_1 /* 72 */:
            case 73:
            case Opcode.DSTORE_3 /* 74 */:
            case Opcode.ASTORE_0 /* 75 */:
            case 76:
            case Opcode.ASTORE_2 /* 77 */:
            case Opcode.ASTORE_3 /* 78 */:
            case Opcode.IASTORE /* 79 */:
            case Opcode.LASTORE /* 80 */:
            case Opcode.FASTORE /* 81 */:
            case 82:
            case Opcode.AASTORE /* 83 */:
            case Opcode.BASTORE /* 84 */:
            case 85:
            case Opcode.SASTORE /* 86 */:
            case Opcode.POP /* 87 */:
            case Opcode.POP2 /* 88 */:
            case Opcode.DUP /* 89 */:
            case 90:
            case Opcode.DUP_X2 /* 91 */:
            case Opcode.DUP2 /* 92 */:
            case Opcode.DUP2_X1 /* 93 */:
            case Opcode.DUP2_X2 /* 94 */:
            case Opcode.SWAP /* 95 */:
            case Opcode.IADD /* 96 */:
            case Opcode.LADD /* 97 */:
            case Opcode.FADD /* 98 */:
            case Opcode.DADD /* 99 */:
            case Opcode.ISUB /* 100 */:
            case Opcode.LSUB /* 101 */:
            case Opcode.FSUB /* 102 */:
            case Opcode.DSUB /* 103 */:
            case Opcode.IMUL /* 104 */:
            case Opcode.LMUL /* 105 */:
            case Opcode.FMUL /* 106 */:
            case Opcode.DMUL /* 107 */:
            case Opcode.IDIV /* 108 */:
            case Opcode.LDIV /* 109 */:
            case Opcode.FDIV /* 110 */:
            case Opcode.DDIV /* 111 */:
            case Opcode.IREM /* 112 */:
            case Opcode.LREM /* 113 */:
            case 114:
            case Opcode.DREM /* 115 */:
            case Opcode.INEG /* 116 */:
            case Opcode.LNEG /* 117 */:
            case Opcode.FNEG /* 118 */:
            case Opcode.DNEG /* 119 */:
            case Opcode.ISHL /* 120 */:
            case Opcode.LSHL /* 121 */:
            case Opcode.ISHR /* 122 */:
            case Opcode.LSHR /* 123 */:
            case Opcode.IUSHR /* 124 */:
            case Opcode.LUSHR /* 125 */:
            case Opcode.IAND /* 126 */:
            case Opcode.LAND /* 127 */:
            case 128:
            case Opcode.LOR /* 129 */:
            case Opcode.IXOR /* 130 */:
            case Opcode.LXOR /* 131 */:
            case Opcode.I2L /* 133 */:
            case Opcode.I2F /* 134 */:
            case Opcode.I2D /* 135 */:
            case Opcode.L2I /* 136 */:
            case Opcode.L2F /* 137 */:
            case Opcode.L2D /* 138 */:
            case Opcode.F2I /* 139 */:
            case Opcode.F2L /* 140 */:
            case Opcode.F2D /* 141 */:
            case Opcode.D2I /* 142 */:
            case Opcode.D2L /* 143 */:
            case Opcode.D2F /* 144 */:
            case Opcode.I2B /* 145 */:
            case Opcode.I2C /* 146 */:
            case Opcode.I2S /* 147 */:
            case Opcode.LCMP /* 148 */:
            case Opcode.FCMPL /* 149 */:
            case Opcode.FCMPG /* 150 */:
            case Opcode.DCMPL /* 151 */:
            case Opcode.DCMPG /* 152 */:
            case Opcode.IRETURN /* 172 */:
            case Opcode.LRETURN /* 173 */:
            case Opcode.FRETURN /* 174 */:
            case Opcode.DRETURN /* 175 */:
            case Opcode.ARETURN /* 176 */:
            case Opcode.RETURN /* 177 */:
            case Opcode.ARRAYLENGTH /* 190 */:
            case Opcode.ATHROW /* 191 */:
            case Opcode.INSTANCEOF /* 193 */:
            case Opcode.MONITORENTER /* 194 */:
            case Opcode.MONITOREXIT /* 195 */:
            default:
                return opstring;
            case Opcode.IINC /* 132 */:
                return opstring + " " + iter.byteAt(pos + 1) + ", " + iter.signedByteAt(pos + 2);
            case Opcode.IFEQ /* 153 */:
            case Opcode.IFNE /* 154 */:
            case Opcode.IFLT /* 155 */:
            case Opcode.IFGE /* 156 */:
            case Opcode.IFGT /* 157 */:
            case Opcode.IFLE /* 158 */:
            case Opcode.IF_ICMPEQ /* 159 */:
            case Opcode.IF_ICMPNE /* 160 */:
            case Opcode.IF_ICMPLT /* 161 */:
            case Opcode.IF_ICMPGE /* 162 */:
            case Opcode.IF_ICMPGT /* 163 */:
            case Opcode.IF_ICMPLE /* 164 */:
            case Opcode.IF_ACMPEQ /* 165 */:
            case Opcode.IF_ACMPNE /* 166 */:
            case Opcode.IFNULL /* 198 */:
            case Opcode.IFNONNULL /* 199 */:
                return opstring + " " + (iter.s16bitAt(pos + 1) + pos);
            case Opcode.GOTO /* 167 */:
            case Opcode.JSR /* 168 */:
                return opstring + " " + (iter.s16bitAt(pos + 1) + pos);
            case Opcode.RET /* 169 */:
                return opstring + " " + iter.byteAt(pos + 1);
            case Opcode.TABLESWITCH /* 170 */:
                return tableSwitch(iter, pos);
            case Opcode.LOOKUPSWITCH /* 171 */:
                return lookupSwitch(iter, pos);
            case Opcode.GETSTATIC /* 178 */:
            case Opcode.PUTSTATIC /* 179 */:
            case Opcode.GETFIELD /* 180 */:
            case Opcode.PUTFIELD /* 181 */:
                return opstring + " " + fieldInfo(pool, iter.u16bitAt(pos + 1));
            case Opcode.INVOKEVIRTUAL /* 182 */:
            case Opcode.INVOKESPECIAL /* 183 */:
            case Opcode.INVOKESTATIC /* 184 */:
                return opstring + " " + methodInfo(pool, iter.u16bitAt(pos + 1));
            case Opcode.INVOKEINTERFACE /* 185 */:
                return opstring + " " + interfaceMethodInfo(pool, iter.u16bitAt(pos + 1));
            case Opcode.INVOKEDYNAMIC /* 186 */:
                return opstring + " " + iter.u16bitAt(pos + 1);
            case Opcode.NEW /* 187 */:
                return opstring + " " + classInfo(pool, iter.u16bitAt(pos + 1));
            case 188:
                return opstring + " " + arrayInfo(iter.byteAt(pos + 1));
            case Opcode.ANEWARRAY /* 189 */:
            case 192:
                return opstring + " " + classInfo(pool, iter.u16bitAt(pos + 1));
            case Opcode.WIDE /* 196 */:
                return wide(iter, pos);
            case Opcode.MULTIANEWARRAY /* 197 */:
                return opstring + " " + classInfo(pool, iter.u16bitAt(pos + 1));
            case 200:
            case Opcode.JSR_W /* 201 */:
                return opstring + " " + (iter.s32bitAt(pos + 1) + pos);
        }
    }

    private static String wide(CodeIterator iter, int pos) {
        int opcode = iter.byteAt(pos + 1);
        int index = iter.u16bitAt(pos + 2);
        switch (opcode) {
            case 21:
            case 22:
            case 23:
            case 24:
            case 25:
            case 54:
            case 55:
            case 56:
            case 57:
            case Opcode.ASTORE /* 58 */:
            case Opcode.IINC /* 132 */:
            case Opcode.RET /* 169 */:
                return opcodes[opcode] + " " + index;
            default:
                throw new RuntimeException("Invalid WIDE operand");
        }
    }

    private static String arrayInfo(int type) {
        switch (type) {
            case 4:
                return "boolean";
            case 5:
                return "char";
            case 6:
                return "float";
            case 7:
                return "double";
            case 8:
                return "byte";
            case 9:
                return "short";
            case 10:
                return "int";
            case 11:
                return "long";
            default:
                throw new RuntimeException("Invalid array type");
        }
    }

    private static String classInfo(ConstPool pool, int index) {
        return "#" + index + " = Class " + pool.getClassInfo(index);
    }

    private static String interfaceMethodInfo(ConstPool pool, int index) {
        return "#" + index + " = Method " + pool.getInterfaceMethodrefClassName(index) + "." + pool.getInterfaceMethodrefName(index) + "(" + pool.getInterfaceMethodrefType(index) + ")";
    }

    private static String methodInfo(ConstPool pool, int index) {
        return "#" + index + " = Method " + pool.getMethodrefClassName(index) + "." + pool.getMethodrefName(index) + "(" + pool.getMethodrefType(index) + ")";
    }

    private static String fieldInfo(ConstPool pool, int index) {
        return "#" + index + " = Field " + pool.getFieldrefClassName(index) + "." + pool.getFieldrefName(index) + "(" + pool.getFieldrefType(index) + ")";
    }

    private static String lookupSwitch(CodeIterator iter, int pos) {
        StringBuffer buffer = new StringBuffer("lookupswitch {\n");
        int index = (pos & (-4)) + 4;
        buffer.append("\t\tdefault: ").append(pos + iter.s32bitAt(index)).append("\n");
        int index2 = index + 4;
        int npairs = iter.s32bitAt(index2);
        int index3 = index2 + 4;
        int end = (npairs * 8) + index3;
        while (index3 < end) {
            int match = iter.s32bitAt(index3);
            int target = iter.s32bitAt(index3 + 4) + pos;
            buffer.append("\t\t").append(match).append(": ").append(target).append("\n");
            index3 += 8;
        }
        buffer.setCharAt(buffer.length() - 1, '}');
        return buffer.toString();
    }

    private static String tableSwitch(CodeIterator iter, int pos) {
        StringBuffer buffer = new StringBuffer("tableswitch {\n");
        int index = (pos & (-4)) + 4;
        buffer.append("\t\tdefault: ").append(pos + iter.s32bitAt(index)).append("\n");
        int index2 = index + 4;
        int low = iter.s32bitAt(index2);
        int index3 = index2 + 4;
        int high = iter.s32bitAt(index3);
        int index4 = index3 + 4;
        int end = (((high - low) + 1) * 4) + index4;
        int key = low;
        while (index4 < end) {
            int target = iter.s32bitAt(index4) + pos;
            buffer.append("\t\t").append(key).append(": ").append(target).append("\n");
            index4 += 4;
            key++;
        }
        buffer.setCharAt(buffer.length() - 1, '}');
        return buffer.toString();
    }

    private static String ldc(ConstPool pool, int index) {
        int tag = pool.getTag(index);
        switch (tag) {
            case 3:
                return "#" + index + " = int " + pool.getIntegerInfo(index);
            case 4:
                return "#" + index + " = float " + pool.getFloatInfo(index);
            case 5:
                return "#" + index + " = long " + pool.getLongInfo(index);
            case 6:
                return "#" + index + " = double " + pool.getDoubleInfo(index);
            case 7:
                return classInfo(pool, index);
            case 8:
                return "#" + index + " = \"" + pool.getStringInfo(index) + "\"";
            default:
                throw new RuntimeException("bad LDC: " + tag);
        }
    }
}