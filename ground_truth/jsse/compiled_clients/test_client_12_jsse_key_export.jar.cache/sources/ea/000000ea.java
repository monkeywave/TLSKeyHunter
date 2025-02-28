package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/AnnotationMemberValue.class */
public class AnnotationMemberValue extends MemberValue {
    Annotation value;

    public AnnotationMemberValue(ConstPool cp) {
        this(null, cp);
    }

    public AnnotationMemberValue(Annotation a, ConstPool cp) {
        super('@', cp);
        this.value = a;
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) throws ClassNotFoundException {
        return AnnotationImpl.make(cl, getType(cl), cp, this.value);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) throws ClassNotFoundException {
        if (this.value == null) {
            throw new ClassNotFoundException("no type specified");
        }
        return loadClass(cl, this.value.getTypeName());
    }

    public Annotation getValue() {
        return this.value;
    }

    public void setValue(Annotation newValue) {
        this.value = newValue;
    }

    public String toString() {
        return this.value.toString();
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.annotationValue();
        this.value.write(writer);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitAnnotationMemberValue(this);
    }
}