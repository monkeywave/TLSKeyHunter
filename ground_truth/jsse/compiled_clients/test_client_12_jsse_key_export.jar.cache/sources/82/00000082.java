package javassist.bytecode;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/EnclosingMethodAttribute.class */
public class EnclosingMethodAttribute extends AttributeInfo {
    public static final String tag = "EnclosingMethod";

    /* JADX INFO: Access modifiers changed from: package-private */
    public EnclosingMethodAttribute(ConstPool cp, int n, DataInputStream in) throws IOException {
        super(cp, n, in);
    }

    public EnclosingMethodAttribute(ConstPool cp, String className, String methodName, String methodDesc) {
        super(cp, tag);
        int ci = cp.addClassInfo(className);
        int ni = cp.addNameAndTypeInfo(methodName, methodDesc);
        byte[] bvalue = {(byte) (ci >>> 8), (byte) ci, (byte) (ni >>> 8), (byte) ni};
        set(bvalue);
    }

    public EnclosingMethodAttribute(ConstPool cp, String className) {
        super(cp, tag);
        int ci = cp.addClassInfo(className);
        byte[] bvalue = {(byte) (ci >>> 8), (byte) ci, (byte) (0 >>> 8), (byte) 0};
        set(bvalue);
    }

    public int classIndex() {
        return ByteArray.readU16bit(get(), 0);
    }

    public int methodIndex() {
        return ByteArray.readU16bit(get(), 2);
    }

    public String className() {
        return getConstPool().getClassInfo(classIndex());
    }

    public String methodName() {
        ConstPool cp = getConstPool();
        int mi = methodIndex();
        if (mi == 0) {
            return MethodInfo.nameClinit;
        }
        int ni = cp.getNameAndTypeName(mi);
        return cp.getUtf8Info(ni);
    }

    public String methodDescriptor() {
        ConstPool cp = getConstPool();
        int mi = methodIndex();
        int ti = cp.getNameAndTypeDescriptor(mi);
        return cp.getUtf8Info(ti);
    }

    @Override // javassist.bytecode.AttributeInfo
    public AttributeInfo copy(ConstPool newCp, Map<String, String> classnames) {
        if (methodIndex() == 0) {
            return new EnclosingMethodAttribute(newCp, className());
        }
        return new EnclosingMethodAttribute(newCp, className(), methodName(), methodDescriptor());
    }
}