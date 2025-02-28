package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/IntegerMemberValue.class */
public class IntegerMemberValue extends MemberValue {
    int valueIndex;

    public IntegerMemberValue(int index, ConstPool cp) {
        super('I', cp);
        this.valueIndex = index;
    }

    public IntegerMemberValue(ConstPool cp, int value) {
        super('I', cp);
        setValue(value);
    }

    public IntegerMemberValue(ConstPool cp) {
        super('I', cp);
        setValue(0);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Integer.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Integer.TYPE;
    }

    public int getValue() {
        return this.f0cp.getIntegerInfo(this.valueIndex);
    }

    public void setValue(int newValue) {
        this.valueIndex = this.f0cp.addIntegerInfo(newValue);
    }

    public String toString() {
        return Integer.toString(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitIntegerMemberValue(this);
    }
}