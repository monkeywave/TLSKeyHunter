package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ConstPool.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/LongInfo.class */
public class LongInfo extends ConstInfo {
    static final int tag = 5;
    long value;

    public LongInfo(long l, int index) {
        super(index);
        this.value = l;
    }

    public LongInfo(DataInputStream in, int index) throws IOException {
        super(index);
        this.value = in.readLong();
    }

    public int hashCode() {
        return (int) (this.value ^ (this.value >>> 32));
    }

    public boolean equals(Object obj) {
        return (obj instanceof LongInfo) && ((LongInfo) obj).value == this.value;
    }

    @Override // javassist.bytecode.ConstInfo
    public int getTag() {
        return 5;
    }

    @Override // javassist.bytecode.ConstInfo
    public int copy(ConstPool src, ConstPool dest, Map<String, String> map) {
        return dest.addLongInfo(this.value);
    }

    @Override // javassist.bytecode.ConstInfo
    public void write(DataOutputStream out) throws IOException {
        out.writeByte(5);
        out.writeLong(this.value);
    }

    @Override // javassist.bytecode.ConstInfo
    public void print(PrintWriter out) {
        out.print("Long ");
        out.println(this.value);
    }
}