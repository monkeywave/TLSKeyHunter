package javassist.bytecode.stackmap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ExceptionTable;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/BasicBlock.class */
public class BasicBlock {
    protected int position;
    protected int length = 0;
    protected int incoming = 0;
    protected BasicBlock[] exit;
    protected boolean stop;
    protected Catch toCatch;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/BasicBlock$JsrBytecode.class */
    public static class JsrBytecode extends BadBytecode {
        private static final long serialVersionUID = 1;

        JsrBytecode() {
            super("JSR");
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public BasicBlock(int pos) {
        this.position = pos;
    }

    public static BasicBlock find(BasicBlock[] blocks, int pos) throws BadBytecode {
        for (BasicBlock b : blocks) {
            if (b.position <= pos && pos < b.position + b.length) {
                return b;
            }
        }
        throw new BadBytecode("no basic block at " + pos);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/BasicBlock$Catch.class */
    public static class Catch {
        public Catch next;
        public BasicBlock body;
        public int typeIndex;

        Catch(BasicBlock b, int i, Catch c) {
            this.body = b;
            this.typeIndex = i;
            this.next = c;
        }
    }

    public String toString() {
        StringBuffer sbuf = new StringBuffer();
        String cname = getClass().getName();
        int i = cname.lastIndexOf(46);
        sbuf.append(i < 0 ? cname : cname.substring(i + 1));
        sbuf.append("[");
        toString2(sbuf);
        sbuf.append("]");
        return sbuf.toString();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void toString2(StringBuffer sbuf) {
        BasicBlock[] basicBlockArr;
        sbuf.append("pos=").append(this.position).append(", len=").append(this.length).append(", in=").append(this.incoming).append(", exit{");
        if (this.exit != null) {
            for (BasicBlock b : this.exit) {
                sbuf.append(b.position).append(",");
            }
        }
        sbuf.append("}, {");
        Catch r0 = this.toCatch;
        while (true) {
            Catch th = r0;
            if (th != null) {
                sbuf.append("(").append(th.body.position).append(", ").append(th.typeIndex).append("), ");
                r0 = th.next;
            } else {
                sbuf.append("}");
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/BasicBlock$Mark.class */
    public static class Mark implements Comparable<Mark> {
        int position;
        BasicBlock block = null;
        BasicBlock[] jump = null;
        boolean alwaysJmp = false;
        int size = 0;
        Catch catcher = null;

        Mark(int p) {
            this.position = p;
        }

        @Override // java.lang.Comparable
        public int compareTo(Mark obj) {
            if (null == obj) {
                return -1;
            }
            return this.position - obj.position;
        }

        void setJump(BasicBlock[] bb, int s, boolean always) {
            this.jump = bb;
            this.size = s;
            this.alwaysJmp = always;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/BasicBlock$Maker.class */
    public static class Maker {
        protected BasicBlock makeBlock(int pos) {
            return new BasicBlock(pos);
        }

        protected BasicBlock[] makeArray(int size) {
            return new BasicBlock[size];
        }

        private BasicBlock[] makeArray(BasicBlock b) {
            BasicBlock[] array = makeArray(1);
            array[0] = b;
            return array;
        }

        private BasicBlock[] makeArray(BasicBlock b1, BasicBlock b2) {
            BasicBlock[] array = makeArray(2);
            array[0] = b1;
            array[1] = b2;
            return array;
        }

        public BasicBlock[] make(MethodInfo minfo) throws BadBytecode {
            CodeAttribute ca = minfo.getCodeAttribute();
            if (ca == null) {
                return null;
            }
            CodeIterator ci = ca.iterator();
            return make(ci, 0, ci.getCodeLength(), ca.getExceptionTable());
        }

        public BasicBlock[] make(CodeIterator ci, int begin, int end, ExceptionTable et) throws BadBytecode {
            Map<Integer, Mark> marks = makeMarks(ci, begin, end, et);
            BasicBlock[] bb = makeBlocks(marks);
            addCatchers(bb, et);
            return bb;
        }

        private Mark makeMark(Map<Integer, Mark> table, int pos) {
            return makeMark0(table, pos, true, true);
        }

        private Mark makeMark(Map<Integer, Mark> table, int pos, BasicBlock[] jump, int size, boolean always) {
            Mark m = makeMark0(table, pos, false, false);
            m.setJump(jump, size, always);
            return m;
        }

        private Mark makeMark0(Map<Integer, Mark> table, int pos, boolean isBlockBegin, boolean isTarget) {
            Integer p = Integer.valueOf(pos);
            Mark m = table.get(p);
            if (m == null) {
                m = new Mark(pos);
                table.put(p, m);
            }
            if (isBlockBegin) {
                if (m.block == null) {
                    m.block = makeBlock(pos);
                }
                if (isTarget) {
                    m.block.incoming++;
                }
            }
            return m;
        }

        private Map<Integer, Mark> makeMarks(CodeIterator ci, int begin, int end, ExceptionTable et) throws BadBytecode {
            int index;
            ci.begin();
            ci.move(begin);
            Map<Integer, Mark> marks = new HashMap<>();
            while (ci.hasNext() && (index = ci.next()) < end) {
                int op = ci.byteAt(index);
                if ((153 <= op && op <= 166) || op == 198 || op == 199) {
                    Mark to = makeMark(marks, index + ci.s16bitAt(index + 1));
                    Mark next = makeMark(marks, index + 3);
                    makeMark(marks, index, makeArray(to.block, next.block), 3, false);
                } else if (167 <= op && op <= 171) {
                    switch (op) {
                        case Opcode.GOTO /* 167 */:
                            makeGoto(marks, index, index + ci.s16bitAt(index + 1), 3);
                            continue;
                        case Opcode.JSR /* 168 */:
                            makeJsr(marks, index, index + ci.s16bitAt(index + 1), 3);
                            continue;
                        case Opcode.RET /* 169 */:
                            makeMark(marks, index, null, 2, true);
                            continue;
                        case Opcode.TABLESWITCH /* 170 */:
                            int pos = (index & (-4)) + 4;
                            int low = ci.s32bitAt(pos + 4);
                            int high = ci.s32bitAt(pos + 8);
                            int ncases = (high - low) + 1;
                            BasicBlock[] to2 = makeArray(ncases + 1);
                            to2[0] = makeMark(marks, index + ci.s32bitAt(pos)).block;
                            int p = pos + 12;
                            int n = p + (ncases * 4);
                            int k = 1;
                            while (p < n) {
                                int i = k;
                                k++;
                                to2[i] = makeMark(marks, index + ci.s32bitAt(p)).block;
                                p += 4;
                            }
                            makeMark(marks, index, to2, n - index, true);
                            continue;
                        case Opcode.LOOKUPSWITCH /* 171 */:
                            int pos2 = (index & (-4)) + 4;
                            int ncases2 = ci.s32bitAt(pos2 + 4);
                            BasicBlock[] to3 = makeArray(ncases2 + 1);
                            to3[0] = makeMark(marks, index + ci.s32bitAt(pos2)).block;
                            int p2 = pos2 + 8 + 4;
                            int n2 = (p2 + (ncases2 * 8)) - 4;
                            int k2 = 1;
                            while (p2 < n2) {
                                int i2 = k2;
                                k2++;
                                to3[i2] = makeMark(marks, index + ci.s32bitAt(p2)).block;
                                p2 += 8;
                            }
                            makeMark(marks, index, to3, n2 - index, true);
                            continue;
                    }
                } else if ((172 <= op && op <= 177) || op == 191) {
                    makeMark(marks, index, null, 1, true);
                } else if (op == 200) {
                    makeGoto(marks, index, index + ci.s32bitAt(index + 1), 5);
                } else if (op == 201) {
                    makeJsr(marks, index, index + ci.s32bitAt(index + 1), 5);
                } else if (op == 196 && ci.byteAt(index + 1) == 169) {
                    makeMark(marks, index, null, 4, true);
                }
            }
            if (et != null) {
                int i3 = et.size();
                while (true) {
                    i3--;
                    if (i3 >= 0) {
                        makeMark0(marks, et.startPc(i3), true, false);
                        makeMark(marks, et.handlerPc(i3));
                    }
                }
            }
            return marks;
        }

        private void makeGoto(Map<Integer, Mark> marks, int pos, int target, int size) {
            Mark to = makeMark(marks, target);
            BasicBlock[] jumps = makeArray(to.block);
            makeMark(marks, pos, jumps, size, true);
        }

        protected void makeJsr(Map<Integer, Mark> marks, int pos, int target, int size) throws BadBytecode {
            throw new JsrBytecode();
        }

        private BasicBlock[] makeBlocks(Map<Integer, Mark> markTable) {
            BasicBlock prev;
            Mark[] marks = (Mark[]) markTable.values().toArray(new Mark[markTable.size()]);
            Arrays.sort(marks);
            List<BasicBlock> blocks = new ArrayList<>();
            int i = 0;
            if (marks.length > 0 && marks[0].position == 0 && marks[0].block != null) {
                i = 0 + 1;
                prev = getBBlock(marks[0]);
            } else {
                prev = makeBlock(0);
            }
            blocks.add(prev);
            while (i < marks.length) {
                int i2 = i;
                i++;
                Mark m = marks[i2];
                BasicBlock bb = getBBlock(m);
                if (bb == null) {
                    if (prev.length > 0) {
                        prev = makeBlock(prev.position + prev.length);
                        blocks.add(prev);
                    }
                    prev.length = (m.position + m.size) - prev.position;
                    prev.exit = m.jump;
                    prev.stop = m.alwaysJmp;
                } else {
                    if (prev.length == 0) {
                        prev.length = m.position - prev.position;
                        bb.incoming++;
                        prev.exit = makeArray(bb);
                    } else if (prev.position + prev.length < m.position) {
                        BasicBlock prev2 = makeBlock(prev.position + prev.length);
                        blocks.add(prev2);
                        prev2.length = m.position - prev2.position;
                        prev2.stop = true;
                        prev2.exit = makeArray(bb);
                    }
                    blocks.add(bb);
                    prev = bb;
                }
            }
            return (BasicBlock[]) blocks.toArray(makeArray(blocks.size()));
        }

        private static BasicBlock getBBlock(Mark m) {
            BasicBlock b = m.block;
            if (b != null && m.size > 0) {
                b.exit = m.jump;
                b.length = m.size;
                b.stop = m.alwaysJmp;
            }
            return b;
        }

        private void addCatchers(BasicBlock[] blocks, ExceptionTable et) throws BadBytecode {
            if (et == null) {
                return;
            }
            int i = et.size();
            while (true) {
                i--;
                if (i >= 0) {
                    BasicBlock handler = BasicBlock.find(blocks, et.handlerPc(i));
                    int start = et.startPc(i);
                    int end = et.endPc(i);
                    int type = et.catchType(i);
                    handler.incoming--;
                    for (BasicBlock bb : blocks) {
                        int iPos = bb.position;
                        if (start <= iPos && iPos < end) {
                            bb.toCatch = new Catch(handler, type, bb.toCatch);
                            handler.incoming++;
                        }
                    }
                } else {
                    return;
                }
            }
        }
    }
}