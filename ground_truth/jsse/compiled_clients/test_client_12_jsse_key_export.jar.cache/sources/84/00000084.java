package javassist.bytecode;

/* compiled from: ExceptionTable.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/ExceptionTableEntry.class */
class ExceptionTableEntry {
    int startPc;
    int endPc;
    int handlerPc;
    int catchType;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ExceptionTableEntry(int start, int end, int handle, int type) {
        this.startPc = start;
        this.endPc = end;
        this.handlerPc = handle;
        this.catchType = type;
    }
}