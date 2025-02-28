package javassist;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/Translator.class */
public interface Translator {
    void start(ClassPool classPool) throws NotFoundException, CannotCompileException;

    void onLoad(ClassPool classPool, String str) throws NotFoundException, CannotCompileException;
}