package javassist.bytecode.analysis;

import java.util.HashMap;
import java.util.Map;
import javassist.CtClass;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/MultiType.class */
public class MultiType extends Type {
    private Map<String, CtClass> interfaces;
    private Type resolved;
    private Type potentialClass;
    private MultiType mergeSource;
    private boolean changed;

    public MultiType(Map<String, CtClass> interfaces) {
        this(interfaces, null);
    }

    public MultiType(Map<String, CtClass> interfaces, Type potentialClass) {
        super(null);
        this.changed = false;
        this.interfaces = interfaces;
        this.potentialClass = potentialClass;
    }

    @Override // javassist.bytecode.analysis.Type
    public CtClass getCtClass() {
        if (this.resolved != null) {
            return this.resolved.getCtClass();
        }
        return Type.OBJECT.getCtClass();
    }

    @Override // javassist.bytecode.analysis.Type
    public Type getComponent() {
        return null;
    }

    @Override // javassist.bytecode.analysis.Type
    public int getSize() {
        return 1;
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean isArray() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // javassist.bytecode.analysis.Type
    public boolean popChanged() {
        boolean changed = this.changed;
        this.changed = false;
        return changed;
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean isAssignableFrom(Type type) {
        throw new UnsupportedOperationException("Not implemented");
    }

    public boolean isAssignableTo(Type type) {
        if (this.resolved != null) {
            return type.isAssignableFrom(this.resolved);
        }
        if (Type.OBJECT.equals(type)) {
            return true;
        }
        if (this.potentialClass != null && !type.isAssignableFrom(this.potentialClass)) {
            this.potentialClass = null;
        }
        Map<String, CtClass> map = mergeMultiAndSingle(this, type);
        if (map.size() == 1 && this.potentialClass == null) {
            this.resolved = Type.get(map.values().iterator().next());
            propogateResolved();
            return true;
        } else if (map.size() >= 1) {
            this.interfaces = map;
            propogateState();
            return true;
        } else if (this.potentialClass != null) {
            this.resolved = this.potentialClass;
            propogateResolved();
            return true;
        } else {
            return false;
        }
    }

    private void propogateState() {
        MultiType multiType = this.mergeSource;
        while (true) {
            MultiType source = multiType;
            if (source != null) {
                source.interfaces = this.interfaces;
                source.potentialClass = this.potentialClass;
                multiType = source.mergeSource;
            } else {
                return;
            }
        }
    }

    private void propogateResolved() {
        MultiType multiType = this.mergeSource;
        while (true) {
            MultiType source = multiType;
            if (source != null) {
                source.resolved = this.resolved;
                multiType = source.mergeSource;
            } else {
                return;
            }
        }
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean isReference() {
        return true;
    }

    private Map<String, CtClass> getAllMultiInterfaces(MultiType type) {
        Map<String, CtClass> map = new HashMap<>();
        for (CtClass intf : type.interfaces.values()) {
            map.put(intf.getName(), intf);
            getAllInterfaces(intf, map);
        }
        return map;
    }

    private Map<String, CtClass> mergeMultiInterfaces(MultiType type1, MultiType type2) {
        Map<String, CtClass> map1 = getAllMultiInterfaces(type1);
        Map<String, CtClass> map2 = getAllMultiInterfaces(type2);
        return findCommonInterfaces(map1, map2);
    }

    private Map<String, CtClass> mergeMultiAndSingle(MultiType multi, Type single) {
        Map<String, CtClass> map1 = getAllMultiInterfaces(multi);
        Map<String, CtClass> map2 = getAllInterfaces(single.getCtClass(), null);
        return findCommonInterfaces(map1, map2);
    }

    private boolean inMergeSource(MultiType source) {
        while (source != null) {
            if (source == this) {
                return true;
            }
            source = source.mergeSource;
        }
        return false;
    }

    @Override // javassist.bytecode.analysis.Type
    public Type merge(Type type) {
        Map<String, CtClass> merged;
        if (this == type) {
            return this;
        }
        if (type == UNINIT) {
            return this;
        }
        if (type == BOGUS) {
            return BOGUS;
        }
        if (type == null) {
            return this;
        }
        if (this.resolved != null) {
            return this.resolved.merge(type);
        }
        if (this.potentialClass != null) {
            Type mergePotential = this.potentialClass.merge(type);
            if (!mergePotential.equals(this.potentialClass) || mergePotential.popChanged()) {
                this.potentialClass = Type.OBJECT.equals(mergePotential) ? null : mergePotential;
                this.changed = true;
            }
        }
        if (type instanceof MultiType) {
            MultiType multi = (MultiType) type;
            if (multi.resolved != null) {
                merged = mergeMultiAndSingle(this, multi.resolved);
            } else {
                merged = mergeMultiInterfaces(multi, this);
                if (!inMergeSource(multi)) {
                    this.mergeSource = multi;
                }
            }
        } else {
            merged = mergeMultiAndSingle(this, type);
        }
        if (merged.size() > 1 || (merged.size() == 1 && this.potentialClass != null)) {
            if (merged.size() != this.interfaces.size()) {
                this.changed = true;
            } else if (!this.changed) {
                for (String key : merged.keySet()) {
                    if (!this.interfaces.containsKey(key)) {
                        this.changed = true;
                    }
                }
            }
            this.interfaces = merged;
            propogateState();
            return this;
        }
        if (merged.size() == 1) {
            this.resolved = Type.get(merged.values().iterator().next());
        } else if (this.potentialClass != null) {
            this.resolved = this.potentialClass;
        } else {
            this.resolved = OBJECT;
        }
        propogateResolved();
        return this.resolved;
    }

    @Override // javassist.bytecode.analysis.Type
    public int hashCode() {
        if (this.resolved != null) {
            return this.resolved.hashCode();
        }
        return this.interfaces.keySet().hashCode();
    }

    @Override // javassist.bytecode.analysis.Type
    public boolean equals(Object o) {
        if (!(o instanceof MultiType)) {
            return false;
        }
        MultiType multi = (MultiType) o;
        if (this.resolved != null) {
            return this.resolved.equals(multi.resolved);
        }
        if (multi.resolved != null) {
            return false;
        }
        return this.interfaces.keySet().equals(multi.interfaces.keySet());
    }

    @Override // javassist.bytecode.analysis.Type
    public String toString() {
        if (this.resolved != null) {
            return this.resolved.toString();
        }
        StringBuffer buffer = new StringBuffer("{");
        for (String key : this.interfaces.keySet()) {
            buffer.append(key).append(", ");
        }
        if (this.potentialClass != null) {
            buffer.append("*").append(this.potentialClass.toString());
        } else {
            buffer.setLength(buffer.length() - 2);
        }
        buffer.append("}");
        return buffer.toString();
    }
}