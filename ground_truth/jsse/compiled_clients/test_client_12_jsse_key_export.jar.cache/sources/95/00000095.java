package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ConstPool.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/MethodHandleInfo.class */
public class MethodHandleInfo extends ConstInfo {
    static final int tag = 15;
    int refKind;
    int refIndex;

    public MethodHandleInfo(int kind, int referenceIndex, int index) {
        super(index);
        this.refKind = kind;
        this.refIndex = referenceIndex;
    }

    public MethodHandleInfo(DataInputStream in, int index) throws IOException {
        super(index);
        this.refKind = in.readUnsignedByte();
        this.refIndex = in.readUnsignedShort();
    }

    public int hashCode() {
        return (this.refKind << 16) ^ this.refIndex;
    }

    public boolean equals(Object obj) {
        if (obj instanceof MethodHandleInfo) {
            MethodHandleInfo mh = (MethodHandleInfo) obj;
            return mh.refKind == this.refKind && mh.refIndex == this.refIndex;
        }
        return false;
    }

    @Override // javassist.bytecode.ConstInfo
    public int getTag() {
        return 15;
    }

    @Override // javassist.bytecode.ConstInfo
    public int copy(ConstPool src, ConstPool dest, Map<String, String> map) {
        return dest.addMethodHandleInfo(this.refKind, src.getItem(this.refIndex).copy(src, dest, map));
    }

    @Override // javassist.bytecode.ConstInfo
    public void write(DataOutputStream out) throws IOException {
        out.writeByte(15);
        out.writeByte(this.refKind);
        out.writeShort(this.refIndex);
    }

    @Override // javassist.bytecode.ConstInfo
    public void print(PrintWriter out) {
        out.print("MethodHandle #");
        out.print(this.refKind);
        out.print(", index #");
        out.println(this.refIndex);
    }
}