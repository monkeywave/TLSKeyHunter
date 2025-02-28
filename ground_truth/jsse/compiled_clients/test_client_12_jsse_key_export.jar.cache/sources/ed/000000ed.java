package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/BooleanMemberValue.class */
public class BooleanMemberValue extends MemberValue {
    int valueIndex;

    public BooleanMemberValue(int index, ConstPool cp) {
        super('Z', cp);
        this.valueIndex = index;
    }

    public BooleanMemberValue(boolean b, ConstPool cp) {
        super('Z', cp);
        setValue(b);
    }

    public BooleanMemberValue(ConstPool cp) {
        super('Z', cp);
        setValue(false);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Boolean.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Boolean.TYPE;
    }

    public boolean getValue() {
        return this.f0cp.getIntegerInfo(this.valueIndex) != 0;
    }

    public void setValue(boolean newValue) {
        this.valueIndex = this.f0cp.addIntegerInfo(newValue ? 1 : 0);
    }

    public String toString() {
        return getValue() ? "true" : "false";
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitBooleanMemberValue(this);
    }
}