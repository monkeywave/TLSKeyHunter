package javassist;

import java.io.DataOutputStream;
import java.io.IOException;
import javassist.bytecode.ClassFile;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/CtNewClass.class */
public class CtNewClass extends CtClassType {
    protected boolean hasConstructor;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CtNewClass(String name, ClassPool cp, boolean isInterface, CtClass superclass) {
        super(name, cp);
        String superName;
        this.wasChanged = true;
        if (isInterface || superclass == null) {
            superName = null;
        } else {
            superName = superclass.getName();
        }
        this.classfile = new ClassFile(isInterface, name, superName);
        if (isInterface && superclass != null) {
            this.classfile.setInterfaces(new String[]{superclass.getName()});
        }
        setModifiers(Modifier.setPublic(getModifiers()));
        this.hasConstructor = isInterface;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // javassist.CtClassType, javassist.CtClass
    public void extendToString(StringBuffer buffer) {
        if (this.hasConstructor) {
            buffer.append("hasConstructor ");
        }
        super.extendToString(buffer);
    }

    @Override // javassist.CtClassType, javassist.CtClass
    public void addConstructor(CtConstructor c) throws CannotCompileException {
        this.hasConstructor = true;
        super.addConstructor(c);
    }

    @Override // javassist.CtClassType, javassist.CtClass
    public void toBytecode(DataOutputStream out) throws CannotCompileException, IOException {
        if (!this.hasConstructor) {
            try {
                inheritAllConstructors();
                this.hasConstructor = true;
            } catch (NotFoundException e) {
                throw new CannotCompileException(e);
            }
        }
        super.toBytecode(out);
    }

    public void inheritAllConstructors() throws CannotCompileException, NotFoundException {
        CtClass superclazz = getSuperclass();
        CtConstructor[] cs = superclazz.getDeclaredConstructors();
        int n = 0;
        for (CtConstructor c : cs) {
            int mod = c.getModifiers();
            if (isInheritable(mod, superclazz)) {
                CtConstructor cons = CtNewConstructor.make(c.getParameterTypes(), c.getExceptionTypes(), this);
                cons.setModifiers(mod & 7);
                addConstructor(cons);
                n++;
            }
        }
        if (n < 1) {
            throw new CannotCompileException("no inheritable constructor in " + superclazz.getName());
        }
    }

    private boolean isInheritable(int mod, CtClass superclazz) {
        if (Modifier.isPrivate(mod)) {
            return false;
        }
        if (Modifier.isPackage(mod)) {
            String pname = getPackageName();
            String pname2 = superclazz.getPackageName();
            if (pname == null) {
                return pname2 == null;
            }
            return pname.equals(pname2);
        }
        return true;
    }
}