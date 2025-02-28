package javassist.bytecode.analysis;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/MultiArrayType.class */
public class MultiArrayType extends Type {
    private MultiType component;
    private int dims;

    public MultiArrayType(MultiType component, int dims) {
        super(null);
        this.component = component;
        this.dims = dims;
    }

    @Override // javassist.bytecode.analysis.Type
    public CtClass getCtClass() {
        CtClass clazz = this.component.getCtClass();
        if (clazz == null) {
            return null;
        }
        ClassPool pool = clazz.getClassPool();
        if (pool == null) {
            pool = ClassPool.getDefault();
        }
        String name = arrayName(clazz.getName(), this.dims);
        try {
            return pool.get(name);
        } catch (NotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // javassist.bytecode.analysis.Type
    boolean popChanged() {
        return this.component.popChanged();
    }

    @Override // javassist.bytecode.analysis.Type
    public int getDimensions() {
        return this.dims;
    }

    @Override // javassist.bytecode.analysis.Type
    public Type getComponent() {
        return this.dims == 1 ? this.component : new MultiArrayType(this.component, this.dims - 1);
    }

    @Override // javassist.bytecode.analysis.Type
    public int getSize() {
        return 1;
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean isArray() {
        return true;
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean isAssignableFrom(Type type) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean isReference() {
        return true;
    }

    public boolean isAssignableTo(Type type) {
        if (m128eq(type.getCtClass(), Type.OBJECT.getCtClass()) || m128eq(type.getCtClass(), Type.CLONEABLE.getCtClass()) || m128eq(type.getCtClass(), Type.SERIALIZABLE.getCtClass())) {
            return true;
        }
        if (!type.isArray()) {
            return false;
        }
        Type typeRoot = getRootComponent(type);
        int typeDims = type.getDimensions();
        if (typeDims > this.dims) {
            return false;
        }
        if (typeDims < this.dims) {
            if (m128eq(typeRoot.getCtClass(), Type.OBJECT.getCtClass()) || m128eq(typeRoot.getCtClass(), Type.CLONEABLE.getCtClass()) || m128eq(typeRoot.getCtClass(), Type.SERIALIZABLE.getCtClass())) {
                return true;
            }
            return false;
        }
        return this.component.isAssignableTo(typeRoot);
    }

    @Override // javassist.bytecode.analysis.Type
    public int hashCode() {
        return this.component.hashCode() + this.dims;
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean equals(Object o) {
        if (!(o instanceof MultiArrayType)) {
            return false;
        }
        MultiArrayType multi = (MultiArrayType) o;
        return this.component.equals(multi.component) && this.dims == multi.dims;
    }

    @Override // javassist.bytecode.analysis.Type
    public String toString() {
        return arrayName(this.component.toString(), this.dims);
    }
}