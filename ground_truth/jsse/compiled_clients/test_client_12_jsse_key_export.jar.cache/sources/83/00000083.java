package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/ExceptionTable.class */
public class ExceptionTable implements Cloneable {
    private ConstPool constPool;
    private List<ExceptionTableEntry> entries;

    public ExceptionTable(ConstPool cp) {
        this.constPool = cp;
        this.entries = new ArrayList();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ExceptionTable(ConstPool cp, DataInputStream in) throws IOException {
        this.constPool = cp;
        int length = in.readUnsignedShort();
        List<ExceptionTableEntry> list = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            int start = in.readUnsignedShort();
            int end = in.readUnsignedShort();
            int handle = in.readUnsignedShort();
            int type = in.readUnsignedShort();
            list.add(new ExceptionTableEntry(start, end, handle, type));
        }
        this.entries = list;
    }

    public Object clone() throws CloneNotSupportedException {
        ExceptionTable r = (ExceptionTable) super.clone();
        r.entries = new ArrayList(this.entries);
        return r;
    }

    public int size() {
        return this.entries.size();
    }

    public int startPc(int nth) {
        return this.entries.get(nth).startPc;
    }

    public void setStartPc(int nth, int value) {
        this.entries.get(nth).startPc = value;
    }

    public int endPc(int nth) {
        return this.entries.get(nth).endPc;
    }

    public void setEndPc(int nth, int value) {
        this.entries.get(nth).endPc = value;
    }

    public int handlerPc(int nth) {
        return this.entries.get(nth).handlerPc;
    }

    public void setHandlerPc(int nth, int value) {
        this.entries.get(nth).handlerPc = value;
    }

    public int catchType(int nth) {
        return this.entries.get(nth).catchType;
    }

    public void setCatchType(int nth, int value) {
        this.entries.get(nth).catchType = value;
    }

    public void add(int index, ExceptionTable table, int offset) {
        int len = table.size();
        while (true) {
            len--;
            if (len >= 0) {
                ExceptionTableEntry e = table.entries.get(len);
                add(index, e.startPc + offset, e.endPc + offset, e.handlerPc + offset, e.catchType);
            } else {
                return;
            }
        }
    }

    public void add(int index, int start, int end, int handler, int type) {
        if (start < end) {
            this.entries.add(index, new ExceptionTableEntry(start, end, handler, type));
        }
    }

    public void add(int start, int end, int handler, int type) {
        if (start < end) {
            this.entries.add(new ExceptionTableEntry(start, end, handler, type));
        }
    }

    public void remove(int index) {
        this.entries.remove(index);
    }

    public ExceptionTable copy(ConstPool newCp, Map<String, String> classnames) {
        ExceptionTable et = new ExceptionTable(newCp);
        ConstPool srcCp = this.constPool;
        for (ExceptionTableEntry e : this.entries) {
            int type = srcCp.copy(e.catchType, newCp, classnames);
            et.add(e.startPc, e.endPc, e.handlerPc, type);
        }
        return et;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void shiftPc(int where, int gapLength, boolean exclusive) {
        for (ExceptionTableEntry e : this.entries) {
            e.startPc = shiftPc(e.startPc, where, gapLength, exclusive);
            e.endPc = shiftPc(e.endPc, where, gapLength, exclusive);
            e.handlerPc = shiftPc(e.handlerPc, where, gapLength, exclusive);
        }
    }

    private static int shiftPc(int pc, int where, int gapLength, boolean exclusive) {
        if (pc > where || (exclusive && pc == where)) {
            pc += gapLength;
        }
        return pc;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void write(DataOutputStream out) throws IOException {
        out.writeShort(size());
        for (ExceptionTableEntry e : this.entries) {
            out.writeShort(e.startPc);
            out.writeShort(e.endPc);
            out.writeShort(e.handlerPc);
            out.writeShort(e.catchType);
        }
    }
}