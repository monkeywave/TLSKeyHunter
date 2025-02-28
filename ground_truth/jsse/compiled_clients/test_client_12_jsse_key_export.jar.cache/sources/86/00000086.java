package javassist.bytecode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/FieldInfo.class */
public final class FieldInfo {
    ConstPool constPool;
    int accessFlags;
    int name;
    String cachedName;
    String cachedType;
    int descriptor;
    List<AttributeInfo> attribute;

    private FieldInfo(ConstPool cp) {
        this.constPool = cp;
        this.accessFlags = 0;
        this.attribute = null;
    }

    public FieldInfo(ConstPool cp, String fieldName, String desc) {
        this(cp);
        this.name = cp.addUtf8Info(fieldName);
        this.cachedName = fieldName;
        this.descriptor = cp.addUtf8Info(desc);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FieldInfo(ConstPool cp, DataInputStream in) throws IOException {
        this(cp);
        read(in);
    }

    public String toString() {
        return getName() + " " + getDescriptor();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void compact(ConstPool cp) {
        this.name = cp.addUtf8Info(getName());
        this.descriptor = cp.addUtf8Info(getDescriptor());
        this.attribute = AttributeInfo.copyAll(this.attribute, cp);
        this.constPool = cp;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void prune(ConstPool cp) {
        List<AttributeInfo> newAttributes = new ArrayList<>();
        AttributeInfo invisibleAnnotations = getAttribute(AnnotationsAttribute.invisibleTag);
        if (invisibleAnnotations != null) {
            newAttributes.add(invisibleAnnotations.copy(cp, null));
        }
        AttributeInfo visibleAnnotations = getAttribute(AnnotationsAttribute.visibleTag);
        if (visibleAnnotations != null) {
            newAttributes.add(visibleAnnotations.copy(cp, null));
        }
        AttributeInfo signature = getAttribute(SignatureAttribute.tag);
        if (signature != null) {
            newAttributes.add(signature.copy(cp, null));
        }
        int index = getConstantValue();
        if (index != 0) {
            newAttributes.add(new ConstantAttribute(cp, this.constPool.copy(index, cp, null)));
        }
        this.attribute = newAttributes;
        this.name = cp.addUtf8Info(getName());
        this.descriptor = cp.addUtf8Info(getDescriptor());
        this.constPool = cp;
    }

    public ConstPool getConstPool() {
        return this.constPool;
    }

    public String getName() {
        if (this.cachedName == null) {
            this.cachedName = this.constPool.getUtf8Info(this.name);
        }
        return this.cachedName;
    }

    public void setName(String newName) {
        this.name = this.constPool.addUtf8Info(newName);
        this.cachedName = newName;
    }

    public int getAccessFlags() {
        return this.accessFlags;
    }

    public void setAccessFlags(int acc) {
        this.accessFlags = acc;
    }

    public String getDescriptor() {
        return this.constPool.getUtf8Info(this.descriptor);
    }

    public void setDescriptor(String desc) {
        if (!desc.equals(getDescriptor())) {
            this.descriptor = this.constPool.addUtf8Info(desc);
        }
    }

    public int getConstantValue() {
        ConstantAttribute attr;
        if ((this.accessFlags & 8) == 0 || (attr = (ConstantAttribute) getAttribute(ConstantAttribute.tag)) == null) {
            return 0;
        }
        return attr.getConstantValue();
    }

    public List<AttributeInfo> getAttributes() {
        if (this.attribute == null) {
            this.attribute = new ArrayList();
        }
        return this.attribute;
    }

    public AttributeInfo getAttribute(String name) {
        return AttributeInfo.lookup(this.attribute, name);
    }

    public AttributeInfo removeAttribute(String name) {
        return AttributeInfo.remove(this.attribute, name);
    }

    public void addAttribute(AttributeInfo info) {
        if (this.attribute == null) {
            this.attribute = new ArrayList();
        }
        AttributeInfo.remove(this.attribute, info.getName());
        this.attribute.add(info);
    }

    private void read(DataInputStream in) throws IOException {
        this.accessFlags = in.readUnsignedShort();
        this.name = in.readUnsignedShort();
        this.descriptor = in.readUnsignedShort();
        int n = in.readUnsignedShort();
        this.attribute = new ArrayList();
        for (int i = 0; i < n; i++) {
            this.attribute.add(AttributeInfo.read(this.constPool, in));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void write(DataOutputStream out) throws IOException {
        out.writeShort(this.accessFlags);
        out.writeShort(this.name);
        out.writeShort(this.descriptor);
        if (this.attribute == null) {
            out.writeShort(0);
            return;
        }
        out.writeShort(this.attribute.size());
        AttributeInfo.writeAll(this.attribute, out);
    }
}