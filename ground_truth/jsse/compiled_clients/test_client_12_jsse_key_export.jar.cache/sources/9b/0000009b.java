package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ConstPool.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/ModuleInfo.class */
public class ModuleInfo extends ConstInfo {
    static final int tag = 19;
    int name;

    public ModuleInfo(int moduleName, int index) {
        super(index);
        this.name = moduleName;
    }

    public ModuleInfo(DataInputStream in, int index) throws IOException {
        super(index);
        this.name = in.readUnsignedShort();
    }

    public int hashCode() {
        return this.name;
    }

    public boolean equals(Object obj) {
        return (obj instanceof ModuleInfo) && ((ModuleInfo) obj).name == this.name;
    }

    @Override // javassist.bytecode.ConstInfo
    public int getTag() {
        return 19;
    }

    public String getModuleName(ConstPool cp) {
        return cp.getUtf8Info(this.name);
    }

    @Override // javassist.bytecode.ConstInfo
    public int copy(ConstPool src, ConstPool dest, Map<String, String> map) {
        String moduleName = src.getUtf8Info(this.name);
        int newName = dest.addUtf8Info(moduleName);
        return dest.addModuleInfo(newName);
    }

    @Override // javassist.bytecode.ConstInfo
    public void write(DataOutputStream out) throws IOException {
        out.writeByte(19);
        out.writeShort(this.name);
    }

    @Override // javassist.bytecode.ConstInfo
    public void print(PrintWriter out) {
        out.print("Module #");
        out.println(this.name);
    }
}