package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/ShortMemberValue.class */
public class ShortMemberValue extends MemberValue {
    int valueIndex;

    public ShortMemberValue(int index, ConstPool cp) {
        super('S', cp);
        this.valueIndex = index;
    }

    public ShortMemberValue(short s, ConstPool cp) {
        super('S', cp);
        setValue(s);
    }

    public ShortMemberValue(ConstPool cp) {
        super('S', cp);
        setValue((short) 0);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Short.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Short.TYPE;
    }

    public short getValue() {
        return (short) this.f0cp.getIntegerInfo(this.valueIndex);
    }

    public void setValue(short newValue) {
        this.valueIndex = this.f0cp.addIntegerInfo(newValue);
    }

    public String toString() {
        return Short.toString(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitShortMemberValue(this);
    }
}