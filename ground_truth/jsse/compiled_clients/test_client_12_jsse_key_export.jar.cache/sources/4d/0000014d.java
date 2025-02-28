package javassist.convert;

import javassist.CtClass;
import javassist.CtField;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/convert/TransformWriteField.class */
public final class TransformWriteField extends TransformReadField {
    public TransformWriteField(Transformer next, CtField field, String methodClassname, String methodName) {
        super(next, field, methodClassname, methodName);
    }

    @Override // javassist.convert.TransformReadField, javassist.convert.Transformer
    public int transform(CtClass tclazz, int pos, CodeIterator iterator, ConstPool cp) throws BadBytecode {
        int c = iterator.byteAt(pos);
        if (c == 181 || c == 179) {
            int index = iterator.u16bitAt(pos + 1);
            String typedesc = isField(tclazz.getClassPool(), cp, this.fieldClass, this.fieldname, this.isPrivate, index);
            if (typedesc != null) {
                if (c == 179) {
                    CodeAttribute ca = iterator.get();
                    iterator.move(pos);
                    char c0 = typedesc.charAt(0);
                    if (c0 == 'J' || c0 == 'D') {
                        int pos2 = iterator.insertGap(3);
                        iterator.writeByte(1, pos2);
                        iterator.writeByte(91, pos2 + 1);
                        iterator.writeByte(87, pos2 + 2);
                        ca.setMaxStack(ca.getMaxStack() + 2);
                    } else {
                        int pos3 = iterator.insertGap(2);
                        iterator.writeByte(1, pos3);
                        iterator.writeByte(95, pos3 + 1);
                        ca.setMaxStack(ca.getMaxStack() + 1);
                    }
                    pos = iterator.next();
                }
                int mi = cp.addClassInfo(this.methodClassname);
                String type = "(Ljava/lang/Object;" + typedesc + ")V";
                int methodref = cp.addMethodrefInfo(mi, this.methodName, type);
                iterator.writeByte(Opcode.INVOKESTATIC, pos);
                iterator.write16bit(methodref, pos + 1);
            }
        }
        return pos;
    }
}