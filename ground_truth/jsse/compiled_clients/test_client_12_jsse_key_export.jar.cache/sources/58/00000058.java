package javassist.bytecode;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/BootstrapMethodsAttribute.class */
public class BootstrapMethodsAttribute extends AttributeInfo {
    public static final String tag = "BootstrapMethods";

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/BootstrapMethodsAttribute$BootstrapMethod.class */
    public static class BootstrapMethod {
        public int methodRef;
        public int[] arguments;

        public BootstrapMethod(int method, int[] args) {
            this.methodRef = method;
            this.arguments = args;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BootstrapMethodsAttribute(ConstPool cp, int n, DataInputStream in) throws IOException {
        super(cp, n, in);
    }

    public BootstrapMethodsAttribute(ConstPool cp, BootstrapMethod[] methods) {
        super(cp, tag);
        int size = 2;
        for (BootstrapMethod bootstrapMethod : methods) {
            size += 4 + (bootstrapMethod.arguments.length * 2);
        }
        byte[] data = new byte[size];
        ByteArray.write16bit(methods.length, data, 0);
        int pos = 2;
        for (int i = 0; i < methods.length; i++) {
            ByteArray.write16bit(methods[i].methodRef, data, pos);
            ByteArray.write16bit(methods[i].arguments.length, data, pos + 2);
            int[] args = methods[i].arguments;
            pos += 4;
            for (int i2 : args) {
                ByteArray.write16bit(i2, data, pos);
                pos += 2;
            }
        }
        set(data);
    }

    public BootstrapMethod[] getMethods() {
        byte[] data = get();
        int num = ByteArray.readU16bit(data, 0);
        BootstrapMethod[] methods = new BootstrapMethod[num];
        int pos = 2;
        for (int i = 0; i < num; i++) {
            int ref = ByteArray.readU16bit(data, pos);
            int len = ByteArray.readU16bit(data, pos + 2);
            int[] args = new int[len];
            pos += 4;
            for (int k = 0; k < len; k++) {
                args[k] = ByteArray.readU16bit(data, pos);
                pos += 2;
            }
            methods[i] = new BootstrapMethod(ref, args);
        }
        return methods;
    }

    @Override // javassist.bytecode.AttributeInfo
    public AttributeInfo copy(ConstPool newCp, Map<String, String> classnames) {
        BootstrapMethod[] methods = getMethods();
        ConstPool thisCp = getConstPool();
        for (BootstrapMethod m : methods) {
            m.methodRef = thisCp.copy(m.methodRef, newCp, classnames);
            for (int k = 0; k < m.arguments.length; k++) {
                m.arguments[k] = thisCp.copy(m.arguments[k], newCp, classnames);
            }
        }
        return new BootstrapMethodsAttribute(newCp, methods);
    }
}