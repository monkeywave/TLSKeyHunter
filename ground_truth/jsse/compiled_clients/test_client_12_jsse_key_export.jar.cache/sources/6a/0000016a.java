package javassist.scopedpool;

import java.util.Map;
import javassist.ClassPool;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/scopedpool/ScopedClassPoolRepository.class */
public interface ScopedClassPoolRepository {
    void setClassPoolFactory(ScopedClassPoolFactory scopedClassPoolFactory);

    ScopedClassPoolFactory getClassPoolFactory();

    boolean isPrune();

    void setPrune(boolean z);

    ScopedClassPool createScopedClassPool(ClassLoader classLoader, ClassPool classPool);

    ClassPool findClassPool(ClassLoader classLoader);

    ClassPool registerClassLoader(ClassLoader classLoader);

    Map<ClassLoader, ScopedClassPool> getRegisteredCLs();

    void clearUnregisteredClassLoaders();

    void unregisterClassLoader(ClassLoader classLoader);
}