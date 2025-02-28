package javassist.bytecode.stackmap;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.ConstPool;
import javassist.bytecode.Descriptor;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData.class */
public abstract class TypeData {
    public abstract int getTypeTag();

    public abstract int getTypeData(ConstPool constPool);

    public abstract BasicType isBasicType();

    public abstract boolean is2WordType();

    /* renamed from: eq */
    public abstract boolean mo126eq(TypeData typeData);

    public abstract String getName();

    public abstract void setType(String str, ClassPool classPool) throws BadBytecode;

    public abstract TypeData getArrayType(int i) throws NotFoundException;

    abstract String toString2(Set<TypeData> set);

    public static TypeData[] make(int size) {
        TypeData[] array = new TypeData[size];
        for (int i = 0; i < size; i++) {
            array[i] = TypeTag.TOP;
        }
        return array;
    }

    protected TypeData() {
    }

    private static void setType(TypeData td, String className, ClassPool cp) throws BadBytecode {
        td.setType(className, cp);
    }

    public TypeData join() {
        return new TypeVar(this);
    }

    public boolean isNullType() {
        return false;
    }

    public boolean isUninit() {
        return false;
    }

    public int dfs(List<TypeData> order, int index, ClassPool cp) throws NotFoundException {
        return index;
    }

    protected TypeVar toTypeVar(int dim) {
        return null;
    }

    public void constructorCalled(int offset) {
    }

    public String toString() {
        return super.toString() + "(" + toString2(new HashSet()) + ")";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$BasicType.class */
    public static class BasicType extends TypeData {
        private String name;
        private int typeTag;
        private char decodedName;

        public BasicType(String type, int tag, char decoded) {
            this.name = type;
            this.typeTag = tag;
            this.decodedName = decoded;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            return this.typeTag;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            return 0;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData join() {
            if (this == TypeTag.TOP) {
                return this;
            }
            return super.join();
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public BasicType isBasicType() {
            return this;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean is2WordType() {
            return this.typeTag == 4 || this.typeTag == 3;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        /* renamed from: eq */
        public boolean mo126eq(TypeData d) {
            return this == d;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public String getName() {
            return this.name;
        }

        public char getDecodedName() {
            return this.decodedName;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void setType(String s, ClassPool cp) throws BadBytecode {
            throw new BadBytecode("conflict: " + this.name + " and " + s);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData getArrayType(int dim) throws NotFoundException {
            if (this == TypeTag.TOP) {
                return this;
            }
            if (dim < 0) {
                throw new NotFoundException("no element type: " + this.name);
            }
            if (dim == 0) {
                return this;
            }
            char[] name = new char[dim + 1];
            for (int i = 0; i < dim; i++) {
                name[i] = '[';
            }
            name[dim] = this.decodedName;
            return new ClassName(new String(name));
        }

        @Override // javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> set) {
            return this.name;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$AbsTypeVar.class */
    public static abstract class AbsTypeVar extends TypeData {
        public abstract void merge(TypeData typeData);

        @Override // javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            return 7;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            return cp.addClassInfo(getName());
        }

        @Override // javassist.bytecode.stackmap.TypeData
        /* renamed from: eq */
        public boolean mo126eq(TypeData d) {
            return getName().equals(d.getName());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$TypeVar.class */
    public static class TypeVar extends AbsTypeVar {
        protected String fixedType;
        private boolean is2WordType;
        private int visited = 0;
        private int smallest = 0;
        private boolean inList = false;
        private int dimension = 0;
        protected List<String> uppers = null;
        protected List<TypeData> lowers = new ArrayList(2);
        protected List<TypeData> usedBy = new ArrayList(2);

        public TypeVar(TypeData t) {
            merge(t);
            this.fixedType = null;
            this.is2WordType = t.is2WordType();
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public String getName() {
            if (this.fixedType == null) {
                return this.lowers.get(0).getName();
            }
            return this.fixedType;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public BasicType isBasicType() {
            if (this.fixedType == null) {
                return this.lowers.get(0).isBasicType();
            }
            return null;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean is2WordType() {
            if (this.fixedType == null) {
                return this.is2WordType;
            }
            return false;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean isNullType() {
            if (this.fixedType == null) {
                return this.lowers.get(0).isNullType();
            }
            return false;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean isUninit() {
            if (this.fixedType == null) {
                return this.lowers.get(0).isUninit();
            }
            return false;
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar
        public void merge(TypeData t) {
            this.lowers.add(t);
            if (t instanceof TypeVar) {
                ((TypeVar) t).usedBy.add(this);
            }
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar, javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            if (this.fixedType == null) {
                return this.lowers.get(0).getTypeTag();
            }
            return super.getTypeTag();
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar, javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            if (this.fixedType == null) {
                return this.lowers.get(0).getTypeData(cp);
            }
            return super.getTypeData(cp);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void setType(String typeName, ClassPool cp) throws BadBytecode {
            if (this.uppers == null) {
                this.uppers = new ArrayList();
            }
            this.uppers.add(typeName);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        protected TypeVar toTypeVar(int dim) {
            this.dimension = dim;
            return this;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData getArrayType(int dim) throws NotFoundException {
            if (dim == 0) {
                return this;
            }
            BasicType bt = isBasicType();
            if (bt == null) {
                if (isNullType()) {
                    return new NullType();
                }
                return new ClassName(getName()).getArrayType(dim);
            }
            return bt.getArrayType(dim);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int dfs(List<TypeData> preOrder, int index, ClassPool cp) throws NotFoundException {
            TypeVar cv;
            if (this.visited > 0) {
                return index;
            }
            int index2 = index + 1;
            this.smallest = index2;
            this.visited = index2;
            preOrder.add(this);
            this.inList = true;
            int n = this.lowers.size();
            for (int i = 0; i < n; i++) {
                TypeVar child = this.lowers.get(i).toTypeVar(this.dimension);
                if (child != null) {
                    if (child.visited == 0) {
                        index2 = child.dfs(preOrder, index2, cp);
                        if (child.smallest < this.smallest) {
                            this.smallest = child.smallest;
                        }
                    } else if (child.inList && child.visited < this.smallest) {
                        this.smallest = child.visited;
                    }
                }
            }
            if (this.visited == this.smallest) {
                List<TypeData> scc = new ArrayList<>();
                do {
                    cv = (TypeVar) preOrder.remove(preOrder.size() - 1);
                    cv.inList = false;
                    scc.add(cv);
                } while (cv != this);
                fixTypes(scc, cp);
            }
            return index2;
        }

        private void fixTypes(List<TypeData> scc, ClassPool cp) throws NotFoundException {
            Set<String> lowersSet = new HashSet<>();
            boolean isBasicType = false;
            TypeData kind = null;
            int size = scc.size();
            for (int i = 0; i < size; i++) {
                TypeVar tvar = (TypeVar) scc.get(i);
                List<TypeData> tds = tvar.lowers;
                int size2 = tds.size();
                for (int j = 0; j < size2; j++) {
                    TypeData td = tds.get(j);
                    TypeData d = td.getArrayType(tvar.dimension);
                    TypeData bt = d.isBasicType();
                    if (kind == null) {
                        if (bt == null) {
                            isBasicType = false;
                            kind = d;
                            if (d.isUninit()) {
                                break;
                            }
                        } else {
                            isBasicType = true;
                            kind = bt;
                        }
                        if (bt == null && !d.isNullType()) {
                            lowersSet.add(d.getName());
                        }
                    } else {
                        if ((bt == null && isBasicType) || (bt != null && kind != bt)) {
                            isBasicType = true;
                            kind = TypeTag.TOP;
                            break;
                        }
                        if (bt == null) {
                            lowersSet.add(d.getName());
                        }
                    }
                }
            }
            if (isBasicType) {
                this.is2WordType = kind.is2WordType();
                fixTypes1(scc, kind);
                return;
            }
            String typeName = fixTypes2(scc, lowersSet, cp);
            fixTypes1(scc, new ClassName(typeName));
        }

        private void fixTypes1(List<TypeData> scc, TypeData kind) throws NotFoundException {
            int size = scc.size();
            for (int i = 0; i < size; i++) {
                TypeVar cv = (TypeVar) scc.get(i);
                TypeData kind2 = kind.getArrayType(-cv.dimension);
                if (kind2.isBasicType() == null) {
                    cv.fixedType = kind2.getName();
                } else {
                    cv.lowers.clear();
                    cv.lowers.add(kind2);
                    cv.is2WordType = kind2.is2WordType();
                }
            }
        }

        private String fixTypes2(List<TypeData> scc, Set<String> lowersSet, ClassPool cp) throws NotFoundException {
            CtClass cc;
            Iterator<String> it = lowersSet.iterator();
            if (lowersSet.size() == 0) {
                return null;
            }
            if (lowersSet.size() == 1) {
                return it.next();
            }
            CtClass ctClass = cp.get(it.next());
            while (true) {
                cc = ctClass;
                if (!it.hasNext()) {
                    break;
                }
                ctClass = commonSuperClassEx(cc, cp.get(it.next()));
            }
            if (cc.getSuperclass() == null || isObjectArray(cc)) {
                cc = fixByUppers(scc, cp, new HashSet(), cc);
            }
            if (cc.isArray()) {
                return Descriptor.toJvmName(cc);
            }
            return cc.getName();
        }

        private static boolean isObjectArray(CtClass cc) throws NotFoundException {
            return cc.isArray() && cc.getComponentType().getSuperclass() == null;
        }

        private CtClass fixByUppers(List<TypeData> users, ClassPool cp, Set<TypeData> visited, CtClass type) throws NotFoundException {
            if (users == null) {
                return type;
            }
            int size = users.size();
            for (int i = 0; i < size; i++) {
                TypeVar t = (TypeVar) users.get(i);
                if (!visited.add(t)) {
                    return type;
                }
                if (t.uppers != null) {
                    int s = t.uppers.size();
                    for (int k = 0; k < s; k++) {
                        CtClass cc = cp.get(t.uppers.get(k));
                        if (cc.subtypeOf(type)) {
                            type = cc;
                        }
                    }
                }
                type = fixByUppers(t.usedBy, cp, visited, type);
            }
            return type;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> hash) {
            TypeData e;
            hash.add(this);
            if (this.lowers.size() > 0 && (e = this.lowers.get(0)) != null && !hash.contains(e)) {
                return e.toString2(hash);
            }
            return "?";
        }
    }

    public static CtClass commonSuperClassEx(CtClass one, CtClass two) throws NotFoundException {
        if (one == two) {
            return one;
        }
        if (one.isArray() && two.isArray()) {
            CtClass ele1 = one.getComponentType();
            CtClass ele2 = two.getComponentType();
            CtClass element = commonSuperClassEx(ele1, ele2);
            if (element == ele1) {
                return one;
            }
            if (element == ele2) {
                return two;
            }
            return one.getClassPool().get(element == null ? "java.lang.Object" : element.getName() + "[]");
        } else if (one.isPrimitive() || two.isPrimitive()) {
            return null;
        } else {
            if (one.isArray() || two.isArray()) {
                return one.getClassPool().get("java.lang.Object");
            }
            return commonSuperClass(one, two);
        }
    }

    public static CtClass commonSuperClass(CtClass one, CtClass two) throws NotFoundException {
        CtClass shallow;
        CtClass deep = one;
        CtClass shallow2 = two;
        CtClass backupDeep = deep;
        while (true) {
            if (m127eq(deep, shallow2) && deep.getSuperclass() != null) {
                return deep;
            }
            CtClass deepSuper = deep.getSuperclass();
            CtClass shallowSuper = shallow2.getSuperclass();
            if (shallowSuper == null) {
                shallow = shallow2;
                break;
            } else if (deepSuper == null) {
                backupDeep = shallow2;
                deep = shallow2;
                shallow = backupDeep;
                break;
            } else {
                deep = deepSuper;
                shallow2 = shallowSuper;
            }
        }
        while (true) {
            deep = deep.getSuperclass();
            if (deep == null) {
                break;
            }
            backupDeep = backupDeep.getSuperclass();
        }
        CtClass deep2 = backupDeep;
        while (!m127eq(deep2, shallow)) {
            deep2 = deep2.getSuperclass();
            shallow = shallow.getSuperclass();
        }
        return deep2;
    }

    /* renamed from: eq */
    static boolean m127eq(CtClass one, CtClass two) {
        return one == two || !(one == null || two == null || !one.getName().equals(two.getName()));
    }

    public static void aastore(TypeData array, TypeData value, ClassPool cp) throws BadBytecode {
        if ((array instanceof AbsTypeVar) && !value.isNullType()) {
            ((AbsTypeVar) array).merge(ArrayType.make(value));
        }
        if (value instanceof AbsTypeVar) {
            if (array instanceof AbsTypeVar) {
                ArrayElement.make(array);
            } else if (array instanceof ClassName) {
                if (array.isNullType()) {
                    return;
                }
                String type = ArrayElement.typeName(array.getName());
                value.setType(type, cp);
            } else {
                throw new BadBytecode("bad AASTORE: " + array);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$ArrayType.class */
    public static class ArrayType extends AbsTypeVar {
        private AbsTypeVar element;

        private ArrayType(AbsTypeVar elementType) {
            this.element = elementType;
        }

        static TypeData make(TypeData element) throws BadBytecode {
            if (element instanceof ArrayElement) {
                return ((ArrayElement) element).arrayType();
            }
            if (element instanceof AbsTypeVar) {
                return new ArrayType((AbsTypeVar) element);
            }
            if ((element instanceof ClassName) && !element.isNullType()) {
                return new ClassName(typeName(element.getName()));
            }
            throw new BadBytecode("bad AASTORE: " + element);
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar
        public void merge(TypeData t) {
            try {
                if (!t.isNullType()) {
                    this.element.merge(ArrayElement.make(t));
                }
            } catch (BadBytecode e) {
                throw new RuntimeException("fatal: " + e);
            }
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public String getName() {
            return typeName(this.element.getName());
        }

        public AbsTypeVar elementType() {
            return this.element;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public BasicType isBasicType() {
            return null;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean is2WordType() {
            return false;
        }

        public static String typeName(String elementType) {
            if (elementType.charAt(0) == '[') {
                return "[" + elementType;
            }
            return "[L" + elementType.replace('.', '/') + ";";
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void setType(String s, ClassPool cp) throws BadBytecode {
            this.element.setType(ArrayElement.typeName(s), cp);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        protected TypeVar toTypeVar(int dim) {
            return this.element.toTypeVar(dim + 1);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData getArrayType(int dim) throws NotFoundException {
            return this.element.getArrayType(dim + 1);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int dfs(List<TypeData> order, int index, ClassPool cp) throws NotFoundException {
            return this.element.dfs(order, index, cp);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> set) {
            return "[" + this.element.toString2(set);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$ArrayElement.class */
    public static class ArrayElement extends AbsTypeVar {
        private AbsTypeVar array;

        private ArrayElement(AbsTypeVar a) {
            this.array = a;
        }

        public static TypeData make(TypeData array) throws BadBytecode {
            if (array instanceof ArrayType) {
                return ((ArrayType) array).elementType();
            }
            if (array instanceof AbsTypeVar) {
                return new ArrayElement((AbsTypeVar) array);
            }
            if ((array instanceof ClassName) && !array.isNullType()) {
                return new ClassName(typeName(array.getName()));
            }
            throw new BadBytecode("bad AASTORE: " + array);
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar
        public void merge(TypeData t) {
            try {
                if (!t.isNullType()) {
                    this.array.merge(ArrayType.make(t));
                }
            } catch (BadBytecode e) {
                throw new RuntimeException("fatal: " + e);
            }
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public String getName() {
            return typeName(this.array.getName());
        }

        public AbsTypeVar arrayType() {
            return this.array;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public BasicType isBasicType() {
            return null;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean is2WordType() {
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String typeName(String arrayType) {
            if (arrayType.length() > 1 && arrayType.charAt(0) == '[') {
                char c = arrayType.charAt(1);
                if (c == 'L') {
                    return arrayType.substring(2, arrayType.length() - 1).replace('/', '.');
                }
                if (c == '[') {
                    return arrayType.substring(1);
                }
                return "java.lang.Object";
            }
            return "java.lang.Object";
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void setType(String s, ClassPool cp) throws BadBytecode {
            this.array.setType(ArrayType.typeName(s), cp);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        protected TypeVar toTypeVar(int dim) {
            return this.array.toTypeVar(dim - 1);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData getArrayType(int dim) throws NotFoundException {
            return this.array.getArrayType(dim - 1);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int dfs(List<TypeData> order, int index, ClassPool cp) throws NotFoundException {
            return this.array.dfs(order, index, cp);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> set) {
            return "*" + this.array.toString2(set);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$UninitTypeVar.class */
    public static class UninitTypeVar extends AbsTypeVar {
        protected TypeData type;

        public UninitTypeVar(UninitData t) {
            this.type = t;
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar, javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            return this.type.getTypeTag();
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar, javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            return this.type.getTypeData(cp);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public BasicType isBasicType() {
            return this.type.isBasicType();
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean is2WordType() {
            return this.type.is2WordType();
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean isUninit() {
            return this.type.isUninit();
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar, javassist.bytecode.stackmap.TypeData
        /* renamed from: eq */
        public boolean mo126eq(TypeData d) {
            return this.type.mo126eq(d);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public String getName() {
            return this.type.getName();
        }

        @Override // javassist.bytecode.stackmap.TypeData
        protected TypeVar toTypeVar(int dim) {
            return null;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData join() {
            return this.type.join();
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void setType(String s, ClassPool cp) throws BadBytecode {
            this.type.setType(s, cp);
        }

        @Override // javassist.bytecode.stackmap.TypeData.AbsTypeVar
        public void merge(TypeData t) {
            if (!t.mo126eq(this.type)) {
                this.type = TypeTag.TOP;
            }
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void constructorCalled(int offset) {
            this.type.constructorCalled(offset);
        }

        public int offset() {
            if (this.type instanceof UninitData) {
                return ((UninitData) this.type).offset;
            }
            throw new RuntimeException("not available");
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData getArrayType(int dim) throws NotFoundException {
            return this.type.getArrayType(dim);
        }

        @Override // javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> set) {
            return "";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$ClassName.class */
    public static class ClassName extends TypeData {
        private String name;

        public ClassName(String n) {
            this.name = n;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public String getName() {
            return this.name;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public BasicType isBasicType() {
            return null;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean is2WordType() {
            return false;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            return 7;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            return cp.addClassInfo(getName());
        }

        @Override // javassist.bytecode.stackmap.TypeData
        /* renamed from: eq */
        public boolean mo126eq(TypeData d) {
            return this.name.equals(d.getName());
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void setType(String typeName, ClassPool cp) throws BadBytecode {
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData getArrayType(int dim) throws NotFoundException {
            if (dim == 0) {
                return this;
            }
            if (dim > 0) {
                char[] dimType = new char[dim];
                for (int i = 0; i < dim; i++) {
                    dimType[i] = '[';
                }
                String elementType = getName();
                if (elementType.charAt(0) != '[') {
                    elementType = "L" + elementType.replace('.', '/') + ";";
                }
                return new ClassName(new String(dimType) + elementType);
            }
            for (int i2 = 0; i2 < (-dim); i2++) {
                if (this.name.charAt(i2) != '[') {
                    throw new NotFoundException("no " + dim + " dimensional array type: " + getName());
                }
            }
            char type = this.name.charAt(-dim);
            if (type == '[') {
                return new ClassName(this.name.substring(-dim));
            }
            if (type == 'L') {
                return new ClassName(this.name.substring((-dim) + 1, this.name.length() - 1).replace('/', '.'));
            }
            if (type == TypeTag.DOUBLE.decodedName) {
                return TypeTag.DOUBLE;
            }
            if (type == TypeTag.FLOAT.decodedName) {
                return TypeTag.FLOAT;
            }
            if (type == TypeTag.LONG.decodedName) {
                return TypeTag.LONG;
            }
            return TypeTag.INTEGER;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> set) {
            return this.name;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$NullType.class */
    public static class NullType extends ClassName {
        public NullType() {
            super("null-type");
        }

        @Override // javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            return 5;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean isNullType() {
            return true;
        }

        @Override // javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            return 0;
        }

        @Override // javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        public TypeData getArrayType(int dim) {
            return this;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$UninitData.class */
    public static class UninitData extends ClassName {
        int offset;
        boolean initialized;

        /* JADX INFO: Access modifiers changed from: package-private */
        public UninitData(int offset, String className) {
            super(className);
            this.offset = offset;
            this.initialized = false;
        }

        public UninitData copy() {
            return new UninitData(this.offset, getName());
        }

        @Override // javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            return 8;
        }

        @Override // javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            return this.offset;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public TypeData join() {
            if (this.initialized) {
                return new TypeVar(new ClassName(getName()));
            }
            return new UninitTypeVar(copy());
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public boolean isUninit() {
            return true;
        }

        @Override // javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        /* renamed from: eq */
        public boolean mo126eq(TypeData d) {
            if (d instanceof UninitData) {
                UninitData ud = (UninitData) d;
                return this.offset == ud.offset && getName().equals(ud.getName());
            }
            return false;
        }

        public int offset() {
            return this.offset;
        }

        @Override // javassist.bytecode.stackmap.TypeData
        public void constructorCalled(int offset) {
            if (offset == this.offset) {
                this.initialized = true;
            }
        }

        @Override // javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> set) {
            return getName() + "," + this.offset;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/stackmap/TypeData$UninitThis.class */
    public static class UninitThis extends UninitData {
        /* JADX INFO: Access modifiers changed from: package-private */
        public UninitThis(String className) {
            super(-1, className);
        }

        @Override // javassist.bytecode.stackmap.TypeData.UninitData
        public UninitData copy() {
            return new UninitThis(getName());
        }

        @Override // javassist.bytecode.stackmap.TypeData.UninitData, javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        public int getTypeTag() {
            return 6;
        }

        @Override // javassist.bytecode.stackmap.TypeData.UninitData, javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        public int getTypeData(ConstPool cp) {
            return 0;
        }

        @Override // javassist.bytecode.stackmap.TypeData.UninitData, javassist.bytecode.stackmap.TypeData.ClassName, javassist.bytecode.stackmap.TypeData
        String toString2(Set<TypeData> set) {
            return "uninit:this";
        }
    }
}