package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/CodeAttribute.class */
public class CodeAttribute extends AttributeInfo implements Opcode {
    public static final String tag = "Code";
    private int maxStack;
    private int maxLocals;
    private ExceptionTable exceptions;
    private List<AttributeInfo> attributes;

    public CodeAttribute(ConstPool cp, int stack, int locals, byte[] code, ExceptionTable etable) {
        super(cp, tag);
        this.maxStack = stack;
        this.maxLocals = locals;
        this.info = code;
        this.exceptions = etable;
        this.attributes = new ArrayList();
    }

    private CodeAttribute(ConstPool cp, CodeAttribute src, Map<String, String> classnames) throws BadBytecode {
        super(cp, tag);
        this.maxStack = src.getMaxStack();
        this.maxLocals = src.getMaxLocals();
        this.exceptions = src.getExceptionTable().copy(cp, classnames);
        this.attributes = new ArrayList();
        List<AttributeInfo> src_attr = src.getAttributes();
        int num = src_attr.size();
        for (int i = 0; i < num; i++) {
            AttributeInfo ai = src_attr.get(i);
            this.attributes.add(ai.copy(cp, classnames));
        }
        this.info = src.copyCode(cp, classnames, this.exceptions, this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CodeAttribute(ConstPool cp, int name_id, DataInputStream in) throws IOException {
        super(cp, name_id, (byte[]) null);
        in.readInt();
        this.maxStack = in.readUnsignedShort();
        this.maxLocals = in.readUnsignedShort();
        int code_len = in.readInt();
        this.info = new byte[code_len];
        in.readFully(this.info);
        this.exceptions = new ExceptionTable(cp, in);
        this.attributes = new ArrayList();
        int num = in.readUnsignedShort();
        for (int i = 0; i < num; i++) {
            this.attributes.add(AttributeInfo.read(cp, in));
        }
    }

    @Override // javassist.bytecode.AttributeInfo
    public AttributeInfo copy(ConstPool newCp, Map<String, String> classnames) throws RuntimeCopyException {
        try {
            return new CodeAttribute(newCp, this, classnames);
        } catch (BadBytecode e) {
            throw new RuntimeCopyException("bad bytecode. fatal?");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/CodeAttribute$RuntimeCopyException.class */
    public static class RuntimeCopyException extends RuntimeException {
        private static final long serialVersionUID = 1;

        public RuntimeCopyException(String s) {
            super(s);
        }
    }

    @Override // javassist.bytecode.AttributeInfo
    public int length() {
        return 18 + this.info.length + (this.exceptions.size() * 8) + AttributeInfo.getLength(this.attributes);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // javassist.bytecode.AttributeInfo
    public void write(DataOutputStream out) throws IOException {
        out.writeShort(this.name);
        out.writeInt(length() - 6);
        out.writeShort(this.maxStack);
        out.writeShort(this.maxLocals);
        out.writeInt(this.info.length);
        out.write(this.info);
        this.exceptions.write(out);
        out.writeShort(this.attributes.size());
        AttributeInfo.writeAll(this.attributes, out);
    }

    @Override // javassist.bytecode.AttributeInfo
    public byte[] get() {
        throw new UnsupportedOperationException("CodeAttribute.get()");
    }

    @Override // javassist.bytecode.AttributeInfo
    public void set(byte[] newinfo) {
        throw new UnsupportedOperationException("CodeAttribute.set()");
    }

    @Override // javassist.bytecode.AttributeInfo
    void renameClass(String oldname, String newname) {
        AttributeInfo.renameClass(this.attributes, oldname, newname);
    }

    @Override // javassist.bytecode.AttributeInfo
    void renameClass(Map<String, String> classnames) {
        AttributeInfo.renameClass(this.attributes, classnames);
    }

    @Override // javassist.bytecode.AttributeInfo
    void getRefClasses(Map<String, String> classnames) {
        AttributeInfo.getRefClasses(this.attributes, classnames);
    }

    public String getDeclaringClass() {
        ConstPool cp = getConstPool();
        return cp.getClassName();
    }

    public int getMaxStack() {
        return this.maxStack;
    }

    public void setMaxStack(int value) {
        this.maxStack = value;
    }

    public int computeMaxStack() throws BadBytecode {
        this.maxStack = new CodeAnalyzer(this).computeMaxStack();
        return this.maxStack;
    }

    public int getMaxLocals() {
        return this.maxLocals;
    }

    public void setMaxLocals(int value) {
        this.maxLocals = value;
    }

    public int getCodeLength() {
        return this.info.length;
    }

    public byte[] getCode() {
        return this.info;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setCode(byte[] newinfo) {
        super.set(newinfo);
    }

    public CodeIterator iterator() {
        return new CodeIterator(this);
    }

    public ExceptionTable getExceptionTable() {
        return this.exceptions;
    }

    public List<AttributeInfo> getAttributes() {
        return this.attributes;
    }

    public AttributeInfo getAttribute(String name) {
        return AttributeInfo.lookup(this.attributes, name);
    }

    public void setAttribute(StackMapTable smt) {
        AttributeInfo.remove(this.attributes, StackMapTable.tag);
        if (smt != null) {
            this.attributes.add(smt);
        }
    }

    public void setAttribute(StackMap sm) {
        AttributeInfo.remove(this.attributes, StackMap.tag);
        if (sm != null) {
            this.attributes.add(sm);
        }
    }

    private byte[] copyCode(ConstPool destCp, Map<String, String> classnames, ExceptionTable etable, CodeAttribute destCa) throws BadBytecode {
        int len = getCodeLength();
        byte[] newCode = new byte[len];
        destCa.info = newCode;
        LdcEntry ldc = copyCode(this.info, 0, len, getConstPool(), newCode, destCp, classnames);
        return LdcEntry.doit(newCode, ldc, etable, destCa);
    }

    private static LdcEntry copyCode(byte[] code, int beginPos, int endPos, ConstPool srcCp, byte[] newcode, ConstPool destCp, Map<String, String> classnameMap) throws BadBytecode {
        LdcEntry ldcEntry = null;
        int i = beginPos;
        while (true) {
            int i2 = i;
            if (i2 < endPos) {
                int i22 = CodeIterator.nextOpcode(code, i2);
                byte c = code[i2];
                newcode[i2] = c;
                switch (c & 255) {
                    case 18:
                        int index = srcCp.copy(code[i2 + 1] & 255, destCp, classnameMap);
                        if (index < 256) {
                            newcode[i2 + 1] = (byte) index;
                            continue;
                        } else {
                            newcode[i2] = 0;
                            newcode[i2 + 1] = 0;
                            LdcEntry ldc = new LdcEntry();
                            ldc.where = i2;
                            ldc.index = index;
                            ldc.next = ldcEntry;
                            ldcEntry = ldc;
                        }
                        i = i22;
                    case 19:
                    case 20:
                    case Opcode.GETSTATIC /* 178 */:
                    case Opcode.PUTSTATIC /* 179 */:
                    case Opcode.GETFIELD /* 180 */:
                    case Opcode.PUTFIELD /* 181 */:
                    case Opcode.INVOKEVIRTUAL /* 182 */:
                    case Opcode.INVOKESPECIAL /* 183 */:
                    case Opcode.INVOKESTATIC /* 184 */:
                    case Opcode.NEW /* 187 */:
                    case Opcode.ANEWARRAY /* 189 */:
                    case 192:
                    case Opcode.INSTANCEOF /* 193 */:
                        copyConstPoolInfo(i2 + 1, code, srcCp, newcode, destCp, classnameMap);
                        continue;
                        i = i22;
                    case Opcode.INVOKEINTERFACE /* 185 */:
                        copyConstPoolInfo(i2 + 1, code, srcCp, newcode, destCp, classnameMap);
                        newcode[i2 + 3] = code[i2 + 3];
                        newcode[i2 + 4] = code[i2 + 4];
                        continue;
                        i = i22;
                    case Opcode.INVOKEDYNAMIC /* 186 */:
                        copyConstPoolInfo(i2 + 1, code, srcCp, newcode, destCp, classnameMap);
                        newcode[i2 + 3] = 0;
                        newcode[i2 + 4] = 0;
                        continue;
                        i = i22;
                    case Opcode.MULTIANEWARRAY /* 197 */:
                        copyConstPoolInfo(i2 + 1, code, srcCp, newcode, destCp, classnameMap);
                        newcode[i2 + 3] = code[i2 + 3];
                        continue;
                        i = i22;
                }
                while (true) {
                    i2++;
                    if (i2 < i22) {
                        newcode[i2] = code[i2];
                    }
                }
                i = i22;
            } else {
                return ldcEntry;
            }
        }
    }

    private static void copyConstPoolInfo(int i, byte[] code, ConstPool srcCp, byte[] newcode, ConstPool destCp, Map<String, String> classnameMap) {
        int index = srcCp.copy(((code[i] & GF2Field.MASK) << 8) | (code[i + 1] & GF2Field.MASK), destCp, classnameMap);
        newcode[i] = (byte) (index >> 8);
        newcode[i + 1] = (byte) index;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/CodeAttribute$LdcEntry.class */
    public static class LdcEntry {
        LdcEntry next;
        int where;
        int index;

        LdcEntry() {
        }

        static byte[] doit(byte[] code, LdcEntry ldc, ExceptionTable etable, CodeAttribute ca) throws BadBytecode {
            if (ldc != null) {
                code = CodeIterator.changeLdcToLdcW(code, etable, ca, ldc);
            }
            return code;
        }
    }

    public void insertLocalVar(int where, int size) throws BadBytecode {
        CodeIterator ci = iterator();
        while (ci.hasNext()) {
            shiftIndex(ci, where, size);
        }
        setMaxLocals(getMaxLocals() + size);
    }

    private static void shiftIndex(CodeIterator ci, int lessThan, int delta) throws BadBytecode {
        int var;
        int index = ci.next();
        int opcode = ci.byteAt(index);
        if (opcode < 21) {
            return;
        }
        if (opcode < 79) {
            if (opcode < 26) {
                shiftIndex8(ci, index, opcode, lessThan, delta);
            } else if (opcode < 46) {
                shiftIndex0(ci, index, opcode, lessThan, delta, 26, 21);
            } else if (opcode < 54) {
            } else {
                if (opcode < 59) {
                    shiftIndex8(ci, index, opcode, lessThan, delta);
                } else {
                    shiftIndex0(ci, index, opcode, lessThan, delta, 59, 54);
                }
            }
        } else if (opcode == 132) {
            int var2 = ci.byteAt(index + 1);
            if (var2 < lessThan) {
                return;
            }
            int var3 = var2 + delta;
            if (var3 < 256) {
                ci.writeByte(var3, index + 1);
                return;
            }
            int plus = (byte) ci.byteAt(index + 2);
            int pos = ci.insertExGap(3);
            ci.writeByte(Opcode.WIDE, pos - 3);
            ci.writeByte(Opcode.IINC, pos - 2);
            ci.write16bit(var3, pos - 1);
            ci.write16bit(plus, pos + 1);
        } else if (opcode == 169) {
            shiftIndex8(ci, index, opcode, lessThan, delta);
        } else if (opcode != 196 || (var = ci.u16bitAt(index + 2)) < lessThan) {
        } else {
            ci.write16bit(var + delta, index + 2);
        }
    }

    private static void shiftIndex8(CodeIterator ci, int index, int opcode, int lessThan, int delta) throws BadBytecode {
        int var = ci.byteAt(index + 1);
        if (var < lessThan) {
            return;
        }
        int var2 = var + delta;
        if (var2 < 256) {
            ci.writeByte(var2, index + 1);
            return;
        }
        int pos = ci.insertExGap(2);
        ci.writeByte(Opcode.WIDE, pos - 2);
        ci.writeByte(opcode, pos - 1);
        ci.write16bit(var2, pos);
    }

    private static void shiftIndex0(CodeIterator ci, int index, int opcode, int lessThan, int delta, int opcode_i_0, int opcode_i) throws BadBytecode {
        int var = (opcode - opcode_i_0) % 4;
        if (var < lessThan) {
            return;
        }
        int var2 = var + delta;
        if (var2 < 4) {
            ci.writeByte(opcode + delta, index);
            return;
        }
        int opcode2 = ((opcode - opcode_i_0) / 4) + opcode_i;
        if (var2 < 256) {
            int pos = ci.insertExGap(1);
            ci.writeByte(opcode2, pos - 1);
            ci.writeByte(var2, pos);
            return;
        }
        int pos2 = ci.insertExGap(3);
        ci.writeByte(Opcode.WIDE, pos2 - 1);
        ci.writeByte(opcode2, pos2);
        ci.write16bit(var2, pos2 + 1);
    }
}