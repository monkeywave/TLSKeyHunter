package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/LongMemberValue.class */
public class LongMemberValue extends MemberValue {
    int valueIndex;

    public LongMemberValue(int index, ConstPool cp) {
        super('J', cp);
        this.valueIndex = index;
    }

    public LongMemberValue(long j, ConstPool cp) {
        super('J', cp);
        setValue(j);
    }

    public LongMemberValue(ConstPool cp) {
        super('J', cp);
        setValue(0L);
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Object getValue(ClassLoader cl, ClassPool cp, Method m) {
        return Long.valueOf(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    Class<?> getType(ClassLoader cl) {
        return Long.TYPE;
    }

    public long getValue() {
        return this.f0cp.getLongInfo(this.valueIndex);
    }

    public void setValue(long newValue) {
        this.valueIndex = this.f0cp.addLongInfo(newValue);
    }

    public String toString() {
        return Long.toString(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void write(AnnotationsWriter writer) throws IOException {
        writer.constValueIndex(getValue());
    }

    @Override // javassist.bytecode.annotation.MemberValue
    public void accept(MemberValueVisitor visitor) {
        visitor.visitLongMemberValue(this);
    }
}