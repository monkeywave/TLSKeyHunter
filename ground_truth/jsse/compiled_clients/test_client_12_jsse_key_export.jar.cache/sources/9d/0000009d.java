package javassist.bytecode;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/NestHostAttribute.class */
public class NestHostAttribute extends AttributeInfo {
    public static final String tag = "NestHost";

    /* JADX INFO: Access modifiers changed from: package-private */
    public NestHostAttribute(ConstPool cp, int n, DataInputStream in) throws IOException {
        super(cp, n, in);
    }

    private NestHostAttribute(ConstPool cp, int hostIndex) {
        super(cp, tag, new byte[2]);
        ByteArray.write16bit(hostIndex, get(), 0);
    }

    @Override // javassist.bytecode.AttributeInfo
    public AttributeInfo copy(ConstPool newCp, Map<String, String> classnames) {
        int hostIndex = ByteArray.readU16bit(get(), 0);
        int newHostIndex = getConstPool().copy(hostIndex, newCp, classnames);
        return new NestHostAttribute(newCp, newHostIndex);
    }

    public int hostClassIndex() {
        return ByteArray.readU16bit(this.info, 0);
    }
}