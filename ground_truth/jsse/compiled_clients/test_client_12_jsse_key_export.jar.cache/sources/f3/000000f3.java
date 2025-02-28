package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/FloatMemberValue.class */
public class FloatMemberValue extends MemberValue {
    int valueIndex;

    public FloatMemberValue(int index, ConstPool cp) {
        super('F', cp);
        this.valueIndex = index;
    }

    public FloatMemberValue(float f, ConstPool cp) {
        super('F', cp);
        setValue(f);
    }

    public FloatMemberValue(ConstPool cp) {
        super('F', cp);
        setValue(0.0f);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Float.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Float.TYPE;
    }

    public float getValue() {
        return this.f0cp.getFloatInfo(this.valueIndex);
    }

    public void setValue(float newValue) {
        this.valueIndex = this.f0cp.addFloatInfo(newValue);
    }

    public String toString() {
        return Float.toString(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitFloatMemberValue(this);
    }
}