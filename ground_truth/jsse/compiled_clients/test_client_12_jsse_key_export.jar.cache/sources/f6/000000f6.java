package javassist.bytecode.annotation;

import java.io.IOException;
import java.lang.reflect.Method;
import javassist.ClassPool;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/annotation/MemberValue.class */
public abstract class MemberValue {

    /* renamed from: cp */
    ConstPool f0cp;
    char tag;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract Object getValue(ClassLoader classLoader, ClassPool classPool, Method method) throws ClassNotFoundException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract Class<?> getType(ClassLoader classLoader) throws ClassNotFoundException;

    public abstract void accept(MemberValueVisitor memberValueVisitor);

    public abstract void write(AnnotationsWriter annotationsWriter) throws IOException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MemberValue(char tag, ConstPool cp) {
        this.f0cp = cp;
        this.tag = tag;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Class<?> loadClass(ClassLoader cl, String classname) throws ClassNotFoundException, NoSuchClassError {
        try {
            return Class.forName(convertFromArray(classname), true, cl);
        } catch (LinkageError e) {
            throw new NoSuchClassError(classname, e);
        }
    }

    private static String convertFromArray(String classname) {
        int index = classname.indexOf("[]");
        if (index != -1) {
            String rawType = classname.substring(0, index);
            StringBuffer sb = new StringBuffer(Descriptor.m130of(rawType));
            while (index != -1) {
                sb.insert(0, "[");
                index = classname.indexOf("[]", index + 1);
            }
            return sb.toString().replace('/', '.');
        }
        return classname;
    }
}