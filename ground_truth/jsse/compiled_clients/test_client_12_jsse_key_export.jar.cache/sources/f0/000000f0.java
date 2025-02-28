package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;
import javassist.bytecode.SignatureAttribute;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/ClassMemberValue.class */
public class ClassMemberValue extends MemberValue {
    int valueIndex;

    public ClassMemberValue(int index, ConstPool cp) {
        super('c', cp);
        this.valueIndex = index;
    }

    public ClassMemberValue(String className, ConstPool cp) {
        super('c', cp);
        setValue(className);
    }

    public ClassMemberValue(ConstPool cp) {
        super('c', cp);
        setValue("java.lang.Class");
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) throws ClassNotFoundException {
        String classname = getValue();
        if (classname.equals("void")) {
            return Void.TYPE;
        }
        if (classname.equals("int")) {
            return Integer.TYPE;
        }
        if (classname.equals("byte")) {
            return Byte.TYPE;
        }
        if (classname.equals("long")) {
            return Long.TYPE;
        }
        if (classname.equals("double")) {
            return Double.TYPE;
        }
        if (classname.equals("float")) {
            return Float.TYPE;
        }
        if (classname.equals("char")) {
            return Character.TYPE;
        }
        if (classname.equals("short")) {
            return Short.TYPE;
        }
        if (classname.equals("boolean")) {
            return Boolean.TYPE;
        }
        return loadClass(cl, classname);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) throws ClassNotFoundException {
        return loadClass(cl, "java.lang.Class");
    }

    public String getValue() {
        String v = this.f0cp.getUtf8Info(this.valueIndex);
        try {
            return SignatureAttribute.toTypeSignature(v).jvmTypeName();
        } catch (BadBytecode e) {
            throw new RuntimeException(e);
        }
    }

    public void setValue(String newClassName) {
        String setTo = Descriptor.m130of(newClassName);
        this.valueIndex = this.f0cp.addUtf8Info(setTo);
    }

    public String toString() {
        return getValue().replace('$', '.') + ".class";
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.classInfoIndex(this.f0cp.getUtf8Info(this.valueIndex));
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitClassMemberValue(this);
    }
}