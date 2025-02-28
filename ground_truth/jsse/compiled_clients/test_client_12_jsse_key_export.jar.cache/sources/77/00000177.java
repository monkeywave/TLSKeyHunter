package javassist.tools.reflect;

import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.NotFoundException;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/reflect/Loader.class */
public class Loader extends javassist.Loader {
    protected Reflection reflection;

    public static void main(String[] args) throws Throwable {
        Loader cl = new Loader();
        cl.run(args);
    }

    public Loader() throws CannotCompileException, NotFoundException {
        delegateLoadingOf("javassist.tools.reflect.Loader");
        this.reflection = new Reflection();
        ClassPool pool = ClassPool.getDefault();
        addTranslator(pool, this.reflection);
    }

    public boolean makeReflective(String clazz, String metaobject, String metaclass) throws CannotCompileException, NotFoundException {
        return this.reflection.makeReflective(clazz, metaobject, metaclass);
    }
}