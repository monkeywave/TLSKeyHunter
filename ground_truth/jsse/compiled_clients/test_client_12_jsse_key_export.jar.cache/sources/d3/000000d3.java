package javassist.bytecode.analysis;

import java.util.ArrayList;
import java.util.List;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.stackmap.BasicBlock;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/ControlFlow.class */
public class ControlFlow {
    private CtClass clazz;
    private MethodInfo methodInfo;
    private Block[] basicBlocks;
    private Frame[] frames;

    public ControlFlow(CtMethod method) throws BadBytecode {
        this(method.getDeclaringClass(), method.getMethodInfo2());
    }

    public ControlFlow(CtClass ctclazz, MethodInfo minfo) throws BadBytecode {
        this.clazz = ctclazz;
        this.methodInfo = minfo;
        this.frames = null;
        this.basicBlocks = (Block[]) new BasicBlock.Maker() { // from class: javassist.bytecode.analysis.ControlFlow.1
            @Override // javassist.bytecode.stackmap.BasicBlock.Maker
            protected BasicBlock makeBlock(int pos) {
                return new Block(pos, ControlFlow.this.methodInfo);
            }

            @Override // javassist.bytecode.stackmap.BasicBlock.Maker
            protected BasicBlock[] makeArray(int size) {
                return new Block[size];
            }
        }.make(minfo);
        if (this.basicBlocks == null) {
            this.basicBlocks = new Block[0];
        }
        int size = this.basicBlocks.length;
        int[] counters = new int[size];
        for (int i = 0; i < size; i++) {
            Block b = this.basicBlocks[i];
            b.index = i;
            b.entrances = new Block[b.incomings()];
            counters[i] = 0;
        }
        for (int i2 = 0; i2 < size; i2++) {
            Block b2 = this.basicBlocks[i2];
            for (int k = 0; k < b2.exits(); k++) {
                Block e = b2.exit(k);
                Block[] blockArr = e.entrances;
                int i3 = e.index;
                int i4 = counters[i3];
                counters[i3] = i4 + 1;
                blockArr[i4] = b2;
            }
            Catcher[] catchers = b2.catchers();
            for (Catcher catcher : catchers) {
                Block catchBlock = catcher.node;
                Block[] blockArr2 = catchBlock.entrances;
                int i5 = catchBlock.index;
                int i6 = counters[i5];
                counters[i5] = i6 + 1;
                blockArr2[i6] = b2;
            }
        }
    }

    public Block[] basicBlocks() {
        return this.basicBlocks;
    }

    public Frame frameAt(int pos) throws BadBytecode {
        if (this.frames == null) {
            this.frames = new Analyzer().analyze(this.clazz, this.methodInfo);
        }
        return this.frames[pos];
    }

    public Node[] dominatorTree() {
        int size = this.basicBlocks.length;
        if (size == 0) {
            return null;
        }
        Node[] nodes = new Node[size];
        boolean[] visited = new boolean[size];
        int[] distance = new int[size];
        for (int i = 0; i < size; i++) {
            nodes[i] = new Node(this.basicBlocks[i]);
            visited[i] = false;
        }
        Access access = new Access(nodes) { // from class: javassist.bytecode.analysis.ControlFlow.2
            @Override // javassist.bytecode.analysis.ControlFlow.Access
            BasicBlock[] exits(Node n) {
                return n.block.getExit();
            }

            @Override // javassist.bytecode.analysis.ControlFlow.Access
            BasicBlock[] entrances(Node n) {
                return n.block.entrances;
            }
        };
        nodes[0].makeDepth1stTree(null, visited, 0, distance, access);
        do {
            for (int i2 = 0; i2 < size; i2++) {
                visited[i2] = false;
            }
        } while (nodes[0].makeDominatorTree(visited, distance, access));
        Node.setChildren(nodes);
        return nodes;
    }

    public Node[] postDominatorTree() {
        boolean changed;
        int size = this.basicBlocks.length;
        if (size == 0) {
            return null;
        }
        Node[] nodes = new Node[size];
        boolean[] visited = new boolean[size];
        int[] distance = new int[size];
        for (int i = 0; i < size; i++) {
            nodes[i] = new Node(this.basicBlocks[i]);
            visited[i] = false;
        }
        Access access = new Access(nodes) { // from class: javassist.bytecode.analysis.ControlFlow.3
            @Override // javassist.bytecode.analysis.ControlFlow.Access
            BasicBlock[] exits(Node n) {
                return n.block.entrances;
            }

            @Override // javassist.bytecode.analysis.ControlFlow.Access
            BasicBlock[] entrances(Node n) {
                return n.block.getExit();
            }
        };
        int counter = 0;
        for (int i2 = 0; i2 < size; i2++) {
            if (nodes[i2].block.exits() == 0) {
                counter = nodes[i2].makeDepth1stTree(null, visited, counter, distance, access);
            }
        }
        do {
            for (int i3 = 0; i3 < size; i3++) {
                visited[i3] = false;
            }
            changed = false;
            for (int i4 = 0; i4 < size; i4++) {
                if (nodes[i4].block.exits() == 0 && nodes[i4].makeDominatorTree(visited, distance, access)) {
                    changed = true;
                }
            }
        } while (changed);
        Node.setChildren(nodes);
        return nodes;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/ControlFlow$Block.class */
    public static class Block extends BasicBlock {
        public Object clientData;
        int index;
        MethodInfo method;
        Block[] entrances;

        Block(int pos, MethodInfo minfo) {
            super(pos);
            this.clientData = null;
            this.method = minfo;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // javassist.bytecode.stackmap.BasicBlock
        public void toString2(StringBuffer sbuf) {
            super.toString2(sbuf);
            sbuf.append(", incoming{");
            for (int i = 0; i < this.entrances.length; i++) {
                sbuf.append(this.entrances[i].position).append(", ");
            }
            sbuf.append("}");
        }

        BasicBlock[] getExit() {
            return this.exit;
        }

        public int index() {
            return this.index;
        }

        public int position() {
            return this.position;
        }

        public int length() {
            return this.length;
        }

        public int incomings() {
            return this.incoming;
        }

        public Block incoming(int n) {
            return this.entrances[n];
        }

        public int exits() {
            if (this.exit == null) {
                return 0;
            }
            return this.exit.length;
        }

        public Block exit(int n) {
            return (Block) this.exit[n];
        }

        public Catcher[] catchers() {
            List<Catcher> catchers = new ArrayList<>();
            BasicBlock.Catch r0 = this.toCatch;
            while (true) {
                BasicBlock.Catch c = r0;
                if (c != null) {
                    catchers.add(new Catcher(c));
                    r0 = c.next;
                } else {
                    return (Catcher[]) catchers.toArray(new Catcher[catchers.size()]);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/ControlFlow$Access.class */
    public static abstract class Access {
        Node[] all;

        abstract BasicBlock[] exits(Node node);

        abstract BasicBlock[] entrances(Node node);

        Access(Node[] nodes) {
            this.all = nodes;
        }

        Node node(BasicBlock b) {
            return this.all[((Block) b).index];
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/ControlFlow$Node.class */
    public static class Node {
        private Block block;
        private Node parent = null;
        private Node[] children;

        Node(Block b) {
            this.block = b;
        }

        public String toString() {
            StringBuffer sbuf = new StringBuffer();
            sbuf.append("Node[pos=").append(block().position());
            sbuf.append(", parent=");
            sbuf.append(this.parent == null ? "*" : Integer.toString(this.parent.block().position()));
            sbuf.append(", children{");
            for (int i = 0; i < this.children.length; i++) {
                sbuf.append(this.children[i].block().position()).append(", ");
            }
            sbuf.append("}]");
            return sbuf.toString();
        }

        public Block block() {
            return this.block;
        }

        public Node parent() {
            return this.parent;
        }

        public int children() {
            return this.children.length;
        }

        public Node child(int n) {
            return this.children[n];
        }

        int makeDepth1stTree(Node caller, boolean[] visited, int counter, int[] distance, Access access) {
            int index = this.block.index;
            if (visited[index]) {
                return counter;
            }
            visited[index] = true;
            this.parent = caller;
            BasicBlock[] exits = access.exits(this);
            if (exits != null) {
                for (BasicBlock basicBlock : exits) {
                    Node n = access.node(basicBlock);
                    counter = n.makeDepth1stTree(this, visited, counter, distance, access);
                }
            }
            int i = counter;
            int counter2 = counter + 1;
            distance[index] = i;
            return counter2;
        }

        boolean makeDominatorTree(boolean[] visited, int[] distance, Access access) {
            Node n;
            int index = this.block.index;
            if (visited[index]) {
                return false;
            }
            visited[index] = true;
            boolean changed = false;
            BasicBlock[] exits = access.exits(this);
            if (exits != null) {
                for (BasicBlock basicBlock : exits) {
                    if (access.node(basicBlock).makeDominatorTree(visited, distance, access)) {
                        changed = true;
                    }
                }
            }
            BasicBlock[] entrances = access.entrances(this);
            if (entrances != null) {
                for (BasicBlock basicBlock2 : entrances) {
                    if (this.parent != null && (n = getAncestor(this.parent, access.node(basicBlock2), distance)) != this.parent) {
                        this.parent = n;
                        changed = true;
                    }
                }
            }
            return changed;
        }

        /* JADX WARN: Removed duplicated region for block: B:4:0x0005  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct code enable 'Show inconsistent code' option in preferences
        */
        private static javassist.bytecode.analysis.ControlFlow.Node getAncestor(javassist.bytecode.analysis.ControlFlow.Node r4, javassist.bytecode.analysis.ControlFlow.Node r5, int[] r6) {
            /*
            L0:
                r0 = r4
                r1 = r5
                if (r0 == r1) goto L31
                r0 = r6
                r1 = r4
                javassist.bytecode.analysis.ControlFlow$Block r1 = r1.block
                int r1 = r1.index
                r0 = r0[r1]
                r1 = r6
                r2 = r5
                javassist.bytecode.analysis.ControlFlow$Block r2 = r2.block
                int r2 = r2.index
                r1 = r1[r2]
                if (r0 >= r1) goto L22
                r0 = r4
                javassist.bytecode.analysis.ControlFlow$Node r0 = r0.parent
                r4 = r0
                goto L27
            L22:
                r0 = r5
                javassist.bytecode.analysis.ControlFlow$Node r0 = r0.parent
                r5 = r0
            L27:
                r0 = r4
                if (r0 == 0) goto L2f
                r0 = r5
                if (r0 != 0) goto L0
            L2f:
                r0 = 0
                return r0
            L31:
                r0 = r4
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: javassist.bytecode.analysis.ControlFlow.Node.getAncestor(javassist.bytecode.analysis.ControlFlow$Node, javassist.bytecode.analysis.ControlFlow$Node, int[]):javassist.bytecode.analysis.ControlFlow$Node");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static void setChildren(Node[] all) {
            int size = all.length;
            int[] nchildren = new int[size];
            for (int i = 0; i < size; i++) {
                nchildren[i] = 0;
            }
            for (Node node : all) {
                Node p = node.parent;
                if (p != null) {
                    int i2 = p.block.index;
                    nchildren[i2] = nchildren[i2] + 1;
                }
            }
            for (int i3 = 0; i3 < size; i3++) {
                all[i3].children = new Node[nchildren[i3]];
            }
            for (int i4 = 0; i4 < size; i4++) {
                nchildren[i4] = 0;
            }
            for (Node n : all) {
                Node p2 = n.parent;
                if (p2 != null) {
                    Node[] nodeArr = p2.children;
                    int i5 = p2.block.index;
                    int i6 = nchildren[i5];
                    nchildren[i5] = i6 + 1;
                    nodeArr[i6] = n;
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:javassist/bytecode/analysis/ControlFlow$Catcher.class */
    public static class Catcher {
        private Block node;
        private int typeIndex;

        Catcher(BasicBlock.Catch c) {
            this.node = (Block) c.body;
            this.typeIndex = c.typeIndex;
        }

        public Block block() {
            return this.node;
        }

        public String type() {
            if (this.typeIndex == 0) {
                return "java.lang.Throwable";
            }
            return this.node.method.getConstPool().getClassInfo(this.typeIndex);
        }
    }
}