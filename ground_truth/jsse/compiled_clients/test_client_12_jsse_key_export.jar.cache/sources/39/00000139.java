package javassist.compiler.ast;

import javassist.bytecode.Opcode;
import javassist.compiler.CompileError;
import javassist.compiler.TokenId;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/compiler/ast/IntConst.class */
public class IntConst extends ASTree {
    private static final long serialVersionUID = 1;
    protected long value;
    protected int type;

    public IntConst(long v, int tokenId) {
        this.value = v;
        this.type = tokenId;
    }

    public long get() {
        return this.value;
    }

    public void set(long v) {
        this.value = v;
    }

    public int getType() {
        return this.type;
    }

    @Override // javassist.compiler.ast.ASTree
    public String toString() {
        return Long.toString(this.value);
    }

    @Override // javassist.compiler.ast.ASTree
    public void accept(Visitor v) throws CompileError {
        v.atIntConst(this);
    }

    public ASTree compute(int op, ASTree right) {
        if (right instanceof IntConst) {
            return compute0(op, (IntConst) right);
        }
        if (right instanceof DoubleConst) {
            return compute0(op, (DoubleConst) right);
        }
        return null;
    }

    private IntConst compute0(int op, IntConst right) {
        int newType;
        long newValue;
        int type1 = this.type;
        int type2 = right.type;
        if (type1 == 403 || type2 == 403) {
            newType = 403;
        } else if (type1 == 401 && type2 == 401) {
            newType = 401;
        } else {
            newType = 402;
        }
        long value1 = this.value;
        long value2 = right.value;
        switch (op) {
            case Opcode.FLOAD_3 /* 37 */:
                newValue = value1 % value2;
                break;
            case Opcode.DLOAD_0 /* 38 */:
                newValue = value1 & value2;
                break;
            case Opcode.ALOAD_0 /* 42 */:
                newValue = value1 * value2;
                break;
            case Opcode.ALOAD_1 /* 43 */:
                newValue = value1 + value2;
                break;
            case 45:
                newValue = value1 - value2;
                break;
            case 47:
                newValue = value1 / value2;
                break;
            case Opcode.DUP2_X2 /* 94 */:
                newValue = value1 ^ value2;
                break;
            case Opcode.IUSHR /* 124 */:
                newValue = value1 | value2;
                break;
            case TokenId.LSHIFT /* 364 */:
                newValue = this.value << ((int) value2);
                newType = type1;
                break;
            case TokenId.RSHIFT /* 366 */:
                newValue = this.value >> ((int) value2);
                newType = type1;
                break;
            case TokenId.ARSHIFT /* 370 */:
                newValue = this.value >>> ((int) value2);
                newType = type1;
                break;
            default:
                return null;
        }
        return new IntConst(newValue, newType);
    }

    private DoubleConst compute0(int op, DoubleConst right) {
        double newValue;
        double value1 = this.value;
        double value2 = right.value;
        switch (op) {
            case Opcode.FLOAD_3 /* 37 */:
                newValue = value1 % value2;
                break;
            case Opcode.DLOAD_0 /* 38 */:
            case Opcode.DLOAD_1 /* 39 */:
            case 40:
            case Opcode.DLOAD_3 /* 41 */:
            case Opcode.ALOAD_2 /* 44 */:
            case 46:
            default:
                return null;
            case Opcode.ALOAD_0 /* 42 */:
                newValue = value1 * value2;
                break;
            case Opcode.ALOAD_1 /* 43 */:
                newValue = value1 + value2;
                break;
            case 45:
                newValue = value1 - value2;
                break;
            case 47:
                newValue = value1 / value2;
                break;
        }
        return new DoubleConst(newValue, right.type);
    }
}