package javassist.convert;

import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/convert/TransformNewClass.class */
public final class TransformNewClass extends Transformer {
    private int nested;
    private String classname;
    private String newClassName;
    private int newClassIndex;
    private int newMethodNTIndex;
    private int newMethodIndex;

    public TransformNewClass(Transformer next, String classname, String newClassName) {
        super(next);
        this.classname = classname;
        this.newClassName = newClassName;
    }

    @Override // javassist.convert.Transformer
    public void initialize(ConstPool cp, CodeAttribute attr) {
        this.nested = 0;
        this.newMethodIndex = 0;
        this.newMethodNTIndex = 0;
        this.newClassIndex = 0;
    }

    @Override // javassist.convert.Transformer
    public int transform(CtClass clazz, int pos, CodeIterator iterator, ConstPool cp) throws CannotCompileException {
        int c = iterator.byteAt(pos);
        if (c == 187) {
            if (cp.getClassInfo(iterator.u16bitAt(pos + 1)).equals(this.classname)) {
                if (iterator.byteAt(pos + 3) != 89) {
                    throw new CannotCompileException("NEW followed by no DUP was found");
                }
                if (this.newClassIndex == 0) {
                    this.newClassIndex = cp.addClassInfo(this.newClassName);
                }
                iterator.write16bit(this.newClassIndex, pos + 1);
                this.nested++;
            }
        } else if (c == 183) {
            int index = iterator.u16bitAt(pos + 1);
            int typedesc = cp.isConstructor(this.classname, index);
            if (typedesc != 0 && this.nested > 0) {
                int nt = cp.getMethodrefNameAndType(index);
                if (this.newMethodNTIndex != nt) {
                    this.newMethodNTIndex = nt;
                    this.newMethodIndex = cp.addMethodrefInfo(this.newClassIndex, nt);
                }
                iterator.write16bit(this.newMethodIndex, pos + 1);
                this.nested--;
            }
        }
        return pos;
    }
}