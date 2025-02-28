package javassist.bytecode;

import java.io.DataInputStream;
import java.io.IOException;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ConstPool.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/InterfaceMethodrefInfo.class */
public class InterfaceMethodrefInfo extends MemberrefInfo {
    static final int tag = 11;

    public InterfaceMethodrefInfo(int cindex, int ntindex, int thisIndex) {
        super(cindex, ntindex, thisIndex);
    }

    public InterfaceMethodrefInfo(DataInputStream in, int thisIndex) throws IOException {
        super(in, thisIndex);
    }

    @Override // javassist.bytecode.ConstInfo
    public int getTag() {
        return 11;
    }

    @Override // javassist.bytecode.MemberrefInfo
    public String getTagName() {
        return "Interface";
    }

    @Override // javassist.bytecode.MemberrefInfo
    protected int copy2(ConstPool dest, int cindex, int ntindex) {
        return dest.addInterfaceMethodrefInfo(cindex, ntindex);
    }
}