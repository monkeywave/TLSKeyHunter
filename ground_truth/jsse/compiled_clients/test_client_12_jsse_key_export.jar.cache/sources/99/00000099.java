package javassist.bytecode;

import java.io.DataInputStream;
import java.io.IOException;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ConstPool.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/MethodrefInfo.class */
public class MethodrefInfo extends MemberrefInfo {
    static final int tag = 10;

    public MethodrefInfo(int cindex, int ntindex, int thisIndex) {
        super(cindex, ntindex, thisIndex);
    }

    public MethodrefInfo(DataInputStream in, int thisIndex) throws IOException {
        super(in, thisIndex);
    }

    @Override // javassist.bytecode.ConstInfo
    public int getTag() {
        return 10;
    }

    @Override // javassist.bytecode.MemberrefInfo
    public String getTagName() {
        return "Method";
    }

    @Override // javassist.bytecode.MemberrefInfo
    protected int copy2(ConstPool dest, int cindex, int ntindex) {
        return dest.addMethodrefInfo(cindex, ntindex);
    }
}