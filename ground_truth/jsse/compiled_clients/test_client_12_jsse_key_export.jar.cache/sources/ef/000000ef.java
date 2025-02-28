package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/CharMemberValue.class */
public class CharMemberValue extends MemberValue {
    int valueIndex;

    public CharMemberValue(int index, ConstPool cp) {
        super('C', cp);
        this.valueIndex = index;
    }

    public CharMemberValue(char c, ConstPool cp) {
        super('C', cp);
        setValue(c);
    }

    public CharMemberValue(ConstPool cp) {
        super('C', cp);
        setValue((char) 0);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Character.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Character.TYPE;
    }

    public char getValue() {
        return (char) this.f0cp.getIntegerInfo(this.valueIndex);
    }

    public void setValue(char newValue) {
        this.valueIndex = this.f0cp.addIntegerInfo(newValue);
    }

    public String toString() {
        return Character.toString(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitCharMemberValue(this);
    }
}