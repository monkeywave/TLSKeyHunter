package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/DoubleMemberValue.class */
public class DoubleMemberValue extends MemberValue {
    int valueIndex;

    public DoubleMemberValue(int index, ConstPool cp) {
        super('D', cp);
        this.valueIndex = index;
    }

    public DoubleMemberValue(double d, ConstPool cp) {
        super('D', cp);
        setValue(d);
    }

    public DoubleMemberValue(ConstPool cp) {
        super('D', cp);
        setValue(0.0d);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Double.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Double.TYPE;
    }

    public double getValue() {
        return this.f0cp.getDoubleInfo(this.valueIndex);
    }

    public void setValue(double newValue) {
        this.valueIndex = this.f0cp.addDoubleInfo(newValue);
    }

    public String toString() {
        return Double.toString(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitDoubleMemberValue(this);
    }
}