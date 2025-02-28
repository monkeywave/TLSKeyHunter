package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/ByteMemberValue.class */
public class ByteMemberValue extends MemberValue {
    int valueIndex;

    public ByteMemberValue(int index, ConstPool cp) {
        super('B', cp);
        this.valueIndex = index;
    }

    public ByteMemberValue(byte b, ConstPool cp) {
        super('B', cp);
        setValue(b);
    }

    public ByteMemberValue(ConstPool cp) {
        super('B', cp);
        setValue((byte) 0);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Byte.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Byte.TYPE;
    }

    public byte getValue() {
        return (byte) this.f0cp.getIntegerInfo(this.valueIndex);
    }

    public void setValue(byte newValue) {
        this.valueIndex = this.f0cp.addIntegerInfo(newValue);
    }

    public String toString() {
        return Byte.toString(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitByteMemberValue(this);
    }
}