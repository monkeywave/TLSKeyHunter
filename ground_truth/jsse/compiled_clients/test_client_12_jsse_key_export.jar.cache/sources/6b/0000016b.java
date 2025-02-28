package javassist.scopedpool;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import javassist.ClassPool;
import javassist.LoaderClassPath;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/scopedpool/ScopedClassPoolRepositoryImpl.class */
public class ScopedClassPoolRepositoryImpl implements ScopedClassPoolRepository {
    private static final ScopedClassPoolRepositoryImpl instance = new ScopedClassPoolRepositoryImpl();
    boolean pruneWhenCached;
    private boolean prune = true;
    protected Map<ClassLoader, ScopedClassPool> registeredCLs = Collections.synchronizedMap(new WeakHashMap());
    protected ScopedClassPoolFactory factory = new ScopedClassPoolFactoryImpl();
    protected ClassPool classpool = ClassPool.getDefault();

    public static ScopedClassPoolRepository getInstance() {
        return instance;
    }

    private ScopedClassPoolRepositoryImpl() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        this.classpool.insertClassPath(new LoaderClassPath(cl));
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public boolean isPrune() {
        return this.prune;
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public void setPrune(boolean prune) {
        this.prune = prune;
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public ScopedClassPool createScopedClassPool(ClassLoader cl, ClassPool src) {
        return this.factory.create(cl, src, this);
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public ClassPool findClassPool(ClassLoader cl) {
        if (cl == null) {
            return registerClassLoader(ClassLoader.getSystemClassLoader());
        }
        return registerClassLoader(cl);
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public ClassPool registerClassLoader(ClassLoader ucl) {
        synchronized (this.registeredCLs) {
            if (this.registeredCLs.containsKey(ucl)) {
                return this.registeredCLs.get(ucl);
            }
            ScopedClassPool pool = createScopedClassPool(ucl, this.classpool);
            this.registeredCLs.put(ucl, pool);
            return pool;
        }
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public Map<ClassLoader, ScopedClassPool> getRegisteredCLs() {
        clearUnregisteredClassLoaders();
        return this.registeredCLs;
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public void clearUnregisteredClassLoaders() {
        List<ClassLoader> toUnregister = null;
        synchronized (this.registeredCLs) {
            for (Map.Entry<ClassLoader, ScopedClassPool> reg : this.registeredCLs.entrySet()) {
                if (reg.getValue().isUnloadedClassLoader()) {
                    ClassLoader cl = reg.getValue().getClassLoader();
                    if (cl != null) {
                        if (toUnregister == null) {
                            toUnregister = new ArrayList<>();
                        }
                        toUnregister.add(cl);
                    }
                    this.registeredCLs.remove(reg.getKey());
                }
            }
            if (toUnregister != null) {
                for (ClassLoader cl2 : toUnregister) {
                    unregisterClassLoader(cl2);
                }
            }
        }
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public void unregisterClassLoader(ClassLoader cl) {
        synchronized (this.registeredCLs) {
            ScopedClassPool pool = this.registeredCLs.remove(cl);
            if (pool != null) {
                pool.close();
            }
        }
    }

    public void insertDelegate(ScopedClassPoolRepository delegate) {
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public void setClassPoolFactory(ScopedClassPoolFactory factory) {
        this.factory = factory;
    }

    @Override // javassist.scopedpool.ScopedClassPoolRepository
    public ScopedClassPoolFactory getClassPoolFactory() {
        return this.factory;
    }
}