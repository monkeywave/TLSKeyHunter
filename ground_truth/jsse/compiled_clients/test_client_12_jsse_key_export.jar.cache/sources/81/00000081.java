package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ConstPool.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/DynamicInfo.class */
public class DynamicInfo extends ConstInfo {
    static final int tag = 17;
    int bootstrap;
    int nameAndType;

    public DynamicInfo(int bootstrapMethod, int ntIndex, int index) {
        super(index);
        this.bootstrap = bootstrapMethod;
        this.nameAndType = ntIndex;
    }

    public DynamicInfo(DataInputStream in, int index) throws IOException {
        super(index);
        this.bootstrap = in.readUnsignedShort();
        this.nameAndType = in.readUnsignedShort();
    }

    public int hashCode() {
        return (this.bootstrap << 16) ^ this.nameAndType;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DynamicInfo) {
            DynamicInfo iv = (DynamicInfo) obj;
            return iv.bootstrap == this.bootstrap && iv.nameAndType == this.nameAndType;
        }
        return false;
    }

    @Override // javassist.bytecode.ConstInfo
    public int getTag() {
        return 17;
    }

    @Override // javassist.bytecode.ConstInfo
    public int copy(ConstPool src, ConstPool dest, Map<String, String> map) {
        return dest.addDynamicInfo(this.bootstrap, src.getItem(this.nameAndType).copy(src, dest, map));
    }

    @Override // javassist.bytecode.ConstInfo
    public void write(DataOutputStream out) throws IOException {
        out.writeByte(17);
        out.writeShort(this.bootstrap);
        out.writeShort(this.nameAndType);
    }

    @Override // javassist.bytecode.ConstInfo
    public void print(PrintWriter out) {
        out.print("Dynamic #");
        out.print(this.bootstrap);
        out.print(", name&type #");
        out.println(this.nameAndType);
    }
}