package javassist.bytecode.analysis;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.ExceptionTable;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/Analyzer.class */
public class Analyzer implements Opcode {
    private final SubroutineScanner scanner = new SubroutineScanner();
    private CtClass clazz;
    private ExceptionInfo[] exceptions;
    private Frame[] frames;
    private Subroutine[] subroutines;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/Analyzer$ExceptionInfo.class */
    public static class ExceptionInfo {
        private int end;
        private int handler;
        private int start;
        private Type type;

        private ExceptionInfo(int start, int end, int handler, Type type) {
            this.start = start;
            this.end = end;
            this.handler = handler;
            this.type = type;
        }
    }

    public Frame[] analyze(CtClass clazz, MethodInfo method) throws BadBytecode {
        this.clazz = clazz;
        CodeAttribute codeAttribute = method.getCodeAttribute();
        if (codeAttribute == null) {
            return null;
        }
        int maxLocals = codeAttribute.getMaxLocals();
        int maxStack = codeAttribute.getMaxStack();
        int codeLength = codeAttribute.getCodeLength();
        CodeIterator iter = codeAttribute.iterator();
        IntQueue queue = new IntQueue();
        this.exceptions = buildExceptionInfo(method);
        this.subroutines = this.scanner.scan(method);
        Executor executor = new Executor(clazz.getClassPool(), method.getConstPool());
        this.frames = new Frame[codeLength];
        this.frames[iter.lookAhead()] = firstFrame(method, maxLocals, maxStack);
        queue.add(iter.next());
        while (!queue.isEmpty()) {
            analyzeNextEntry(method, iter, queue, executor);
        }
        return this.frames;
    }

    public Frame[] analyze(CtMethod method) throws BadBytecode {
        return analyze(method.getDeclaringClass(), method.getMethodInfo2());
    }

    private void analyzeNextEntry(MethodInfo method, CodeIterator iter, IntQueue queue, Executor executor) throws BadBytecode {
        int pos = queue.take();
        iter.move(pos);
        iter.next();
        Frame frame = this.frames[pos].copy();
        Subroutine subroutine = this.subroutines[pos];
        try {
            executor.execute(method, pos, iter, frame, subroutine);
            int opcode = iter.byteAt(pos);
            if (opcode == 170) {
                mergeTableSwitch(queue, pos, iter, frame);
            } else if (opcode == 171) {
                mergeLookupSwitch(queue, pos, iter, frame);
            } else if (opcode == 169) {
                mergeRet(queue, iter, pos, frame, subroutine);
            } else if (Util.isJumpInstruction(opcode)) {
                int target = Util.getJumpTarget(pos, iter);
                if (Util.isJsr(opcode)) {
                    mergeJsr(queue, this.frames[pos], this.subroutines[target], pos, lookAhead(iter, pos));
                } else if (!Util.isGoto(opcode)) {
                    merge(queue, frame, lookAhead(iter, pos));
                }
                merge(queue, frame, target);
            } else if (opcode != 191 && !Util.isReturn(opcode)) {
                merge(queue, frame, lookAhead(iter, pos));
            }
            mergeExceptionHandlers(queue, method, pos, frame);
        } catch (RuntimeException e) {
            throw new BadBytecode(e.getMessage() + "[pos = " + pos + "]", e);
        }
    }

    private ExceptionInfo[] buildExceptionInfo(MethodInfo method) {
        Type type;
        ConstPool constPool = method.getConstPool();
        ClassPool classes = this.clazz.getClassPool();
        ExceptionTable table = method.getCodeAttribute().getExceptionTable();
        ExceptionInfo[] exceptions = new ExceptionInfo[table.size()];
        for (int i = 0; i < table.size(); i++) {
            int index = table.catchType(i);
            if (index == 0) {
                try {
                    type = Type.THROWABLE;
                } catch (NotFoundException e) {
                    throw new IllegalStateException(e.getMessage());
                }
            } else {
                type = Type.get(classes.get(constPool.getClassInfo(index)));
            }
            Type type2 = type;
            exceptions[i] = new ExceptionInfo(table.startPc(i), table.endPc(i), table.handlerPc(i), type2);
        }
        return exceptions;
    }

    private Frame firstFrame(MethodInfo method, int maxLocals, int maxStack) {
        int pos = 0;
        Frame first = new Frame(maxLocals, maxStack);
        if ((method.getAccessFlags() & 8) == 0) {
            pos = 0 + 1;
            first.setLocal(0, Type.get(this.clazz));
        }
        try {
            CtClass[] parameters = Descriptor.getParameterTypes(method.getDescriptor(), this.clazz.getClassPool());
            for (CtClass ctClass : parameters) {
                Type type = zeroExtend(Type.get(ctClass));
                int i = pos;
                pos++;
                first.setLocal(i, type);
                if (type.getSize() == 2) {
                    pos++;
                    first.setLocal(pos, Type.TOP);
                }
            }
            return first;
        } catch (NotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private int getNext(CodeIterator iter, int of, int restore) throws BadBytecode {
        iter.move(of);
        iter.next();
        int next = iter.lookAhead();
        iter.move(restore);
        iter.next();
        return next;
    }

    private int lookAhead(CodeIterator iter, int pos) throws BadBytecode {
        if (!iter.hasNext()) {
            throw new BadBytecode("Execution falls off end! [pos = " + pos + "]");
        }
        return iter.lookAhead();
    }

    private void merge(IntQueue queue, Frame frame, int target) {
        boolean changed;
        Frame old = this.frames[target];
        if (old == null) {
            this.frames[target] = frame.copy();
            changed = true;
        } else {
            changed = old.merge(frame);
        }
        if (changed) {
            queue.add(target);
        }
    }

    private void mergeExceptionHandlers(IntQueue queue, MethodInfo method, int pos, Frame frame) {
        for (int i = 0; i < this.exceptions.length; i++) {
            ExceptionInfo exception = this.exceptions[i];
            if (pos >= exception.start && pos < exception.end) {
                Frame newFrame = frame.copy();
                newFrame.clearStack();
                newFrame.push(exception.type);
                merge(queue, newFrame, exception.handler);
            }
        }
    }

    private void mergeJsr(IntQueue queue, Frame frame, Subroutine sub, int pos, int next) throws BadBytecode {
        if (sub == null) {
            throw new BadBytecode("No subroutine at jsr target! [pos = " + pos + "]");
        }
        Frame old = this.frames[next];
        boolean changed = false;
        if (old == null) {
            Frame[] frameArr = this.frames;
            Frame copy = frame.copy();
            frameArr[next] = copy;
            old = copy;
            changed = true;
        } else {
            for (int i = 0; i < frame.localsLength(); i++) {
                if (!sub.isAccessed(i)) {
                    Type oldType = old.getLocal(i);
                    Type newType = frame.getLocal(i);
                    if (oldType == null) {
                        old.setLocal(i, newType);
                        changed = true;
                    } else {
                        Type newType2 = oldType.merge(newType);
                        old.setLocal(i, newType2);
                        if (!newType2.equals(oldType) || newType2.popChanged()) {
                            changed = true;
                        }
                    }
                }
            }
        }
        if (!old.isJsrMerged()) {
            old.setJsrMerged(true);
            changed = true;
        }
        if (changed && old.isRetMerged()) {
            queue.add(next);
        }
    }

    private void mergeLookupSwitch(IntQueue queue, int pos, CodeIterator iter, Frame frame) throws BadBytecode {
        int index = (pos & (-4)) + 4;
        merge(queue, frame, pos + iter.s32bitAt(index));
        int index2 = index + 4;
        int npairs = iter.s32bitAt(index2);
        int index3 = index2 + 4;
        int end = (npairs * 8) + index3;
        for (int index4 = index3 + 4; index4 < end; index4 += 8) {
            int target = iter.s32bitAt(index4) + pos;
            merge(queue, frame, target);
        }
    }

    private void mergeRet(IntQueue queue, CodeIterator iter, int pos, Frame frame, Subroutine subroutine) throws BadBytecode {
        boolean changed;
        if (subroutine == null) {
            throw new BadBytecode("Ret on no subroutine! [pos = " + pos + "]");
        }
        for (Integer num : subroutine.callers()) {
            int caller = num.intValue();
            int returnLoc = getNext(iter, caller, pos);
            Frame old = this.frames[returnLoc];
            if (old == null) {
                Frame[] frameArr = this.frames;
                Frame copyStack = frame.copyStack();
                frameArr[returnLoc] = copyStack;
                old = copyStack;
                changed = true;
            } else {
                changed = old.mergeStack(frame);
            }
            for (Integer num2 : subroutine.accessed()) {
                int index = num2.intValue();
                Type oldType = old.getLocal(index);
                Type newType = frame.getLocal(index);
                if (oldType != newType) {
                    old.setLocal(index, newType);
                    changed = true;
                }
            }
            if (!old.isRetMerged()) {
                old.setRetMerged(true);
                changed = true;
            }
            if (changed && old.isJsrMerged()) {
                queue.add(returnLoc);
            }
        }
    }

    private void mergeTableSwitch(IntQueue queue, int pos, CodeIterator iter, Frame frame) throws BadBytecode {
        int index = (pos & (-4)) + 4;
        merge(queue, frame, pos + iter.s32bitAt(index));
        int index2 = index + 4;
        int low = iter.s32bitAt(index2);
        int index3 = index2 + 4;
        int high = iter.s32bitAt(index3);
        int index4 = index3 + 4;
        int end = (((high - low) + 1) * 4) + index4;
        while (index4 < end) {
            int target = iter.s32bitAt(index4) + pos;
            merge(queue, frame, target);
            index4 += 4;
        }
    }

    private Type zeroExtend(Type type) {
        if (type == Type.SHORT || type == Type.BYTE || type == Type.CHAR || type == Type.BOOLEAN) {
            return Type.INTEGER;
        }
        return type;
    }
}