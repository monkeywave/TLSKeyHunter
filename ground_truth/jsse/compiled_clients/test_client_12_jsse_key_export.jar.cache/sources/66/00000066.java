package javassist.bytecode;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/CodeAnalyzer.class */
class CodeAnalyzer implements Opcode {
    private ConstPool constPool;
    private CodeAttribute codeAttr;

    public CodeAnalyzer(CodeAttribute ca) {
        this.codeAttr = ca;
        this.constPool = ca.getConstPool();
    }

    public int computeMaxStack() throws BadBytecode {
        boolean repeat;
        CodeIterator ci = this.codeAttr.iterator();
        int length = ci.getCodeLength();
        int[] stack = new int[length];
        this.constPool = this.codeAttr.getConstPool();
        initStack(stack, this.codeAttr);
        do {
            repeat = false;
            for (int i = 0; i < length; i++) {
                if (stack[i] < 0) {
                    repeat = true;
                    visitBytecode(ci, stack, i);
                }
            }
        } while (repeat);
        int maxStack = 1;
        for (int i2 = 0; i2 < length; i2++) {
            if (stack[i2] > maxStack) {
                maxStack = stack[i2];
            }
        }
        return maxStack - 1;
    }

    private void initStack(int[] stack, CodeAttribute ca) {
        stack[0] = -1;
        ExceptionTable et = ca.getExceptionTable();
        if (et != null) {
            int size = et.size();
            for (int i = 0; i < size; i++) {
                stack[et.handlerPc(i)] = -2;
            }
        }
    }

    private void visitBytecode(CodeIterator ci, int[] stack, int index) throws BadBytecode {
        int codeLength = stack.length;
        ci.move(index);
        int stackDepth = -stack[index];
        int[] jsrDepth = {-1};
        while (ci.hasNext()) {
            int index2 = ci.next();
            stack[index2] = stackDepth;
            int op = ci.byteAt(index2);
            stackDepth = visitInst(op, ci, index2, stackDepth);
            if (stackDepth < 1) {
                throw new BadBytecode("stack underflow at " + index2);
            }
            if (!processBranch(op, ci, index2, codeLength, stack, stackDepth, jsrDepth) && !isEnd(op)) {
                if (op == 168 || op == 201) {
                    stackDepth--;
                }
            } else {
                return;
            }
        }
    }

    private boolean processBranch(int opcode, CodeIterator ci, int index, int codeLength, int[] stack, int stackDepth, int[] jsrDepth) throws BadBytecode {
        int target;
        if ((153 <= opcode && opcode <= 166) || opcode == 198 || opcode == 199) {
            int target2 = index + ci.s16bitAt(index + 1);
            checkTarget(index, target2, codeLength, stack, stackDepth);
            return false;
        }
        switch (opcode) {
            case Opcode.GOTO /* 167 */:
                int target3 = index + ci.s16bitAt(index + 1);
                checkTarget(index, target3, codeLength, stack, stackDepth);
                return true;
            case Opcode.JSR /* 168 */:
            case Opcode.JSR_W /* 201 */:
                if (opcode == 168) {
                    target = index + ci.s16bitAt(index + 1);
                } else {
                    target = index + ci.s32bitAt(index + 1);
                }
                checkTarget(index, target, codeLength, stack, stackDepth);
                if (jsrDepth[0] < 0) {
                    jsrDepth[0] = stackDepth;
                    return false;
                } else if (stackDepth == jsrDepth[0]) {
                    return false;
                } else {
                    throw new BadBytecode("sorry, cannot compute this data flow due to JSR: " + stackDepth + "," + jsrDepth[0]);
                }
            case Opcode.RET /* 169 */:
                if (jsrDepth[0] < 0) {
                    jsrDepth[0] = stackDepth + 1;
                    return false;
                } else if (stackDepth + 1 == jsrDepth[0]) {
                    return true;
                } else {
                    throw new BadBytecode("sorry, cannot compute this data flow due to RET: " + stackDepth + "," + jsrDepth[0]);
                }
            case Opcode.TABLESWITCH /* 170 */:
            case Opcode.LOOKUPSWITCH /* 171 */:
                int index2 = (index & (-4)) + 4;
                int target4 = index + ci.s32bitAt(index2);
                checkTarget(index, target4, codeLength, stack, stackDepth);
                if (opcode == 171) {
                    int npairs = ci.s32bitAt(index2 + 4);
                    int index22 = index2 + 12;
                    for (int i = 0; i < npairs; i++) {
                        int target5 = index + ci.s32bitAt(index22);
                        checkTarget(index, target5, codeLength, stack, stackDepth);
                        index22 += 8;
                    }
                    return true;
                }
                int low = ci.s32bitAt(index2 + 4);
                int high = ci.s32bitAt(index2 + 8);
                int n = (high - low) + 1;
                int index23 = index2 + 12;
                for (int i2 = 0; i2 < n; i2++) {
                    int target6 = index + ci.s32bitAt(index23);
                    checkTarget(index, target6, codeLength, stack, stackDepth);
                    index23 += 4;
                }
                return true;
            case 200:
                int target7 = index + ci.s32bitAt(index + 1);
                checkTarget(index, target7, codeLength, stack, stackDepth);
                return true;
            default:
                return false;
        }
    }

    private void checkTarget(int opIndex, int target, int codeLength, int[] stack, int stackDepth) throws BadBytecode {
        if (target < 0 || codeLength <= target) {
            throw new BadBytecode("bad branch offset at " + opIndex);
        }
        int d = stack[target];
        if (d == 0) {
            stack[target] = -stackDepth;
        } else if (d != stackDepth && d != (-stackDepth)) {
            throw new BadBytecode("verification error (" + stackDepth + "," + d + ") at " + opIndex);
        }
    }

    private static boolean isEnd(int opcode) {
        return (172 <= opcode && opcode <= 177) || opcode == 191;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private int visitInst(int op, CodeIterator ci, int index, int stack) throws BadBytecode {
        int stack2;
        switch (op) {
            case Opcode.GETSTATIC /* 178 */:
                stack2 = stack + getFieldSize(ci, index);
                break;
            case Opcode.PUTSTATIC /* 179 */:
                stack2 = stack - getFieldSize(ci, index);
                break;
            case Opcode.GETFIELD /* 180 */:
                stack2 = stack + (getFieldSize(ci, index) - 1);
                break;
            case Opcode.PUTFIELD /* 181 */:
                stack2 = stack - (getFieldSize(ci, index) + 1);
                break;
            case Opcode.INVOKEVIRTUAL /* 182 */:
            case Opcode.INVOKESPECIAL /* 183 */:
                String desc = this.constPool.getMethodrefType(ci.u16bitAt(index + 1));
                stack2 = stack + (Descriptor.dataSize(desc) - 1);
                break;
            case Opcode.INVOKESTATIC /* 184 */:
                String desc2 = this.constPool.getMethodrefType(ci.u16bitAt(index + 1));
                stack2 = stack + Descriptor.dataSize(desc2);
                break;
            case Opcode.INVOKEINTERFACE /* 185 */:
                String desc3 = this.constPool.getInterfaceMethodrefType(ci.u16bitAt(index + 1));
                stack2 = stack + (Descriptor.dataSize(desc3) - 1);
                break;
            case Opcode.INVOKEDYNAMIC /* 186 */:
                String desc4 = this.constPool.getInvokeDynamicType(ci.u16bitAt(index + 1));
                stack2 = stack + Descriptor.dataSize(desc4);
                break;
            case Opcode.NEW /* 187 */:
            case 188:
            case Opcode.ANEWARRAY /* 189 */:
            case Opcode.ARRAYLENGTH /* 190 */:
            case 192:
            case Opcode.INSTANCEOF /* 193 */:
            case Opcode.MONITORENTER /* 194 */:
            case Opcode.MONITOREXIT /* 195 */:
            default:
                stack2 = stack + STACK_GROW[op];
                break;
            case Opcode.ATHROW /* 191 */:
                stack2 = 1;
                break;
            case Opcode.WIDE /* 196 */:
                op = ci.byteAt(index + 1);
                stack2 = stack + STACK_GROW[op];
                break;
            case Opcode.MULTIANEWARRAY /* 197 */:
                stack2 = stack + (1 - ci.byteAt(index + 3));
                break;
        }
        return stack2;
    }

    private int getFieldSize(CodeIterator ci, int index) {
        String desc = this.constPool.getFieldrefType(ci.u16bitAt(index + 1));
        return Descriptor.dataSize(desc);
    }
}