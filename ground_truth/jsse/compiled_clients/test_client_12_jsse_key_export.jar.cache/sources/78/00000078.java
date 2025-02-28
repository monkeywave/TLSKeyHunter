package javassist.bytecode;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ConstPool.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/ConstInfoPadding.class */
public class ConstInfoPadding extends ConstInfo {
    public ConstInfoPadding(int i) {
        super(i);
    }

    @Override // javassist.bytecode.ConstInfo
    public int getTag() {
        return 0;
    }

    @Override // javassist.bytecode.ConstInfo
    public int copy(ConstPool src, ConstPool dest, Map<String, String> map) {
        return dest.addConstInfoPadding();
    }

    @Override // javassist.bytecode.ConstInfo
    public void write(DataOutputStream out) throws IOException {
    }

    @Override // javassist.bytecode.ConstInfo
    public void print(PrintWriter out) {
        out.println("padding");
    }
}