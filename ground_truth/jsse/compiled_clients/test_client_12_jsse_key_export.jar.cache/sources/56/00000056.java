package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/AttributeInfo.class */
public class AttributeInfo {
    protected ConstPool constPool;
    int name;
    byte[] info;

    /* JADX INFO: Access modifiers changed from: protected */
    public AttributeInfo(ConstPool cp, int attrname, byte[] attrinfo) {
        this.constPool = cp;
        this.name = attrname;
        this.info = attrinfo;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public AttributeInfo(ConstPool cp, String attrname) {
        this(cp, attrname, (byte[]) null);
    }

    public AttributeInfo(ConstPool cp, String attrname, byte[] attrinfo) {
        this(cp, cp.addUtf8Info(attrname), attrinfo);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public AttributeInfo(ConstPool cp, int n, DataInputStream in) throws IOException {
        this.constPool = cp;
        this.name = n;
        int len = in.readInt();
        this.info = new byte[len];
        if (len > 0) {
            in.readFully(this.info);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AttributeInfo read(ConstPool cp, DataInputStream in) throws IOException {
        int name = in.readUnsignedShort();
        String nameStr = cp.getUtf8Info(name);
        char first = nameStr.charAt(0);
        if (first < 'E') {
            if (nameStr.equals(AnnotationDefaultAttribute.tag)) {
                return new AnnotationDefaultAttribute(cp, name, in);
            }
            if (nameStr.equals(BootstrapMethodsAttribute.tag)) {
                return new BootstrapMethodsAttribute(cp, name, in);
            }
            if (nameStr.equals(CodeAttribute.tag)) {
                return new CodeAttribute(cp, name, in);
            }
            if (nameStr.equals(ConstantAttribute.tag)) {
                return new ConstantAttribute(cp, name, in);
            }
            if (nameStr.equals(DeprecatedAttribute.tag)) {
                return new DeprecatedAttribute(cp, name, in);
            }
        }
        if (first < 'M') {
            if (nameStr.equals(EnclosingMethodAttribute.tag)) {
                return new EnclosingMethodAttribute(cp, name, in);
            }
            if (nameStr.equals(ExceptionsAttribute.tag)) {
                return new ExceptionsAttribute(cp, name, in);
            }
            if (nameStr.equals(InnerClassesAttribute.tag)) {
                return new InnerClassesAttribute(cp, name, in);
            }
            if (nameStr.equals(LineNumberAttribute.tag)) {
                return new LineNumberAttribute(cp, name, in);
            }
            if (nameStr.equals(LocalVariableAttribute.tag)) {
                return new LocalVariableAttribute(cp, name, in);
            }
            if (nameStr.equals("LocalVariableTypeTable")) {
                return new LocalVariableTypeAttribute(cp, name, in);
            }
        }
        if (first < 'S') {
            if (nameStr.equals(MethodParametersAttribute.tag)) {
                return new MethodParametersAttribute(cp, name, in);
            }
            if (nameStr.equals(NestHostAttribute.tag)) {
                return new NestHostAttribute(cp, name, in);
            }
            if (nameStr.equals(NestMembersAttribute.tag)) {
                return new NestMembersAttribute(cp, name, in);
            }
            if (nameStr.equals(AnnotationsAttribute.visibleTag) || nameStr.equals(AnnotationsAttribute.invisibleTag)) {
                return new AnnotationsAttribute(cp, name, in);
            }
            if (nameStr.equals(ParameterAnnotationsAttribute.visibleTag) || nameStr.equals(ParameterAnnotationsAttribute.invisibleTag)) {
                return new ParameterAnnotationsAttribute(cp, name, in);
            }
            if (nameStr.equals(TypeAnnotationsAttribute.visibleTag) || nameStr.equals(TypeAnnotationsAttribute.invisibleTag)) {
                return new TypeAnnotationsAttribute(cp, name, in);
            }
        }
        if (first >= 'S') {
            if (nameStr.equals(SignatureAttribute.tag)) {
                return new SignatureAttribute(cp, name, in);
            }
            if (nameStr.equals(SourceFileAttribute.tag)) {
                return new SourceFileAttribute(cp, name, in);
            }
            if (nameStr.equals(SyntheticAttribute.tag)) {
                return new SyntheticAttribute(cp, name, in);
            }
            if (nameStr.equals(StackMap.tag)) {
                return new StackMap(cp, name, in);
            }
            if (nameStr.equals(StackMapTable.tag)) {
                return new StackMapTable(cp, name, in);
            }
        }
        return new AttributeInfo(cp, name, in);
    }

    public String getName() {
        return this.constPool.getUtf8Info(this.name);
    }

    public ConstPool getConstPool() {
        return this.constPool;
    }

    public int length() {
        return this.info.length + 6;
    }

    public byte[] get() {
        return this.info;
    }

    public void set(byte[] newinfo) {
        this.info = newinfo;
    }

    public AttributeInfo copy(ConstPool newCp, Map<String, String> classnames) {
        return new AttributeInfo(newCp, getName(), Arrays.copyOf(this.info, this.info.length));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void write(DataOutputStream out) throws IOException {
        out.writeShort(this.name);
        out.writeInt(this.info.length);
        if (this.info.length > 0) {
            out.write(this.info);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getLength(List<AttributeInfo> attributes) {
        int size = 0;
        for (AttributeInfo attr : attributes) {
            size += attr.length();
        }
        return size;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AttributeInfo lookup(List<AttributeInfo> attributes, String name) {
        if (attributes == null) {
            return null;
        }
        for (AttributeInfo ai : attributes) {
            if (ai.getName().equals(name)) {
                return ai;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static synchronized AttributeInfo remove(List<AttributeInfo> attributes, String name) {
        if (attributes == null) {
            return null;
        }
        for (AttributeInfo ai : attributes) {
            if (ai.getName().equals(name) && attributes.remove(ai)) {
                return ai;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void writeAll(List<AttributeInfo> attributes, DataOutputStream out) throws IOException {
        if (attributes == null) {
            return;
        }
        for (AttributeInfo attr : attributes) {
            attr.write(out);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<AttributeInfo> copyAll(List<AttributeInfo> attributes, ConstPool cp) {
        if (attributes == null) {
            return null;
        }
        List<AttributeInfo> newList = new ArrayList<>();
        for (AttributeInfo attr : attributes) {
            newList.add(attr.copy(cp, null));
        }
        return newList;
    }

    void renameClass(String oldname, String newname) {
    }

    void renameClass(Map<String, String> classnames) {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void renameClass(List<AttributeInfo> attributes, String oldname, String newname) {
        if (attributes == null) {
            return;
        }
        for (AttributeInfo ai : attributes) {
            ai.renameClass(oldname, newname);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void renameClass(List<AttributeInfo> attributes, Map<String, String> classnames) {
        if (attributes == null) {
            return;
        }
        for (AttributeInfo ai : attributes) {
            ai.renameClass(classnames);
        }
    }

    void getRefClasses(Map<String, String> classnames) {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void getRefClasses(List<AttributeInfo> attributes, Map<String, String> classnames) {
        if (attributes == null) {
            return;
        }
        for (AttributeInfo ai : attributes) {
            ai.getRefClasses(classnames);
        }
    }
}