package javassist.util;

import com.sun.jdi.Bootstrap;
import com.sun.jdi.ReferenceType;
import com.sun.jdi.VirtualMachine;
import com.sun.jdi.connect.AttachingConnector;
import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.IllegalConnectorArgumentsException;
import com.sun.jdi.event.EventQueue;
import com.sun.jdi.event.EventSet;
import com.sun.jdi.request.EventRequestManager;
import com.sun.jdi.request.MethodEntryRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/util/HotSwapper.class */
public class HotSwapper {
    private VirtualMachine jvm;
    private MethodEntryRequest request;
    private Map<ReferenceType, byte[]> newClassFiles;
    private Trigger trigger;
    private static final String HOST_NAME = "localhost";
    private static final String TRIGGER_NAME = Trigger.class.getName();

    public HotSwapper(int port) throws IOException, IllegalConnectorArgumentsException {
        this(Integer.toString(port));
    }

    public HotSwapper(String port) throws IOException, IllegalConnectorArgumentsException {
        this.jvm = null;
        this.request = null;
        this.newClassFiles = null;
        this.trigger = new Trigger();
        AttachingConnector connector = findConnector("com.sun.jdi.SocketAttach");
        Map<String, Connector.Argument> arguments = connector.defaultArguments();
        arguments.get("hostname").setValue(HOST_NAME);
        arguments.get("port").setValue(port);
        this.jvm = connector.attach(arguments);
        EventRequestManager manager = this.jvm.eventRequestManager();
        this.request = methodEntryRequests(manager, TRIGGER_NAME);
    }

    private Connector findConnector(String connector) throws IOException {
        List<Connector> connectors = Bootstrap.virtualMachineManager().allConnectors();
        for (Connector con : connectors) {
            if (con.name().equals(connector)) {
                return con;
            }
        }
        throw new IOException("Not found: " + connector);
    }

    private static MethodEntryRequest methodEntryRequests(EventRequestManager manager, String classpattern) {
        MethodEntryRequest mereq = manager.createMethodEntryRequest();
        mereq.addClassFilter(classpattern);
        mereq.setSuspendPolicy(1);
        return mereq;
    }

    private void deleteEventRequest(EventRequestManager manager, MethodEntryRequest request) {
        manager.deleteEventRequest(request);
    }

    public void reload(String className, byte[] classFile) {
        ReferenceType classtype = toRefType(className);
        Map<ReferenceType, byte[]> map = new HashMap<>();
        map.put(classtype, classFile);
        reload2(map, className);
    }

    public void reload(Map<String, byte[]> classFiles) {
        Map<ReferenceType, byte[]> map = new HashMap<>();
        String className = null;
        for (Map.Entry<String, byte[]> e : classFiles.entrySet()) {
            className = e.getKey();
            map.put(toRefType(className), e.getValue());
        }
        if (className != null) {
            reload2(map, className + " etc.");
        }
    }

    private ReferenceType toRefType(String className) {
        List<ReferenceType> list = this.jvm.classesByName(className);
        if (list == null || list.isEmpty()) {
            throw new RuntimeException("no such class: " + className);
        }
        return list.get(0);
    }

    private void reload2(Map<ReferenceType, byte[]> map, String msg) {
        synchronized (this.trigger) {
            startDaemon();
            this.newClassFiles = map;
            this.request.enable();
            this.trigger.doSwap();
            this.request.disable();
            Map<ReferenceType, byte[]> ncf = this.newClassFiles;
            if (ncf != null) {
                this.newClassFiles = null;
                throw new RuntimeException("failed to reload: " + msg);
            }
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [javassist.util.HotSwapper$1] */
    private void startDaemon() {
        new Thread() { // from class: javassist.util.HotSwapper.1
            private void errorMsg(Throwable e) {
                System.err.print("Exception in thread \"HotSwap\" ");
                e.printStackTrace(System.err);
            }

            /* JADX WARN: Code restructure failed: missing block: B:8:0x0028, code lost:
                r3.this$0.hotswap();
             */
            @Override // java.lang.Thread, java.lang.Runnable
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct code enable 'Show inconsistent code' option in preferences
            */
            public void run() {
                /*
                    r3 = this;
                    r0 = 0
                    r4 = r0
                    r0 = r3
                    javassist.util.HotSwapper r0 = javassist.util.HotSwapper.this     // Catch: java.lang.Throwable -> L38
                    com.sun.jdi.event.EventSet r0 = r0.waitEvent()     // Catch: java.lang.Throwable -> L38
                    r4 = r0
                    r0 = r4
                    com.sun.jdi.event.EventIterator r0 = r0.eventIterator()     // Catch: java.lang.Throwable -> L38
                    r5 = r0
                L11:
                    r0 = r5
                    boolean r0 = r0.hasNext()     // Catch: java.lang.Throwable -> L38
                    if (r0 == 0) goto L35
                    r0 = r5
                    com.sun.jdi.event.Event r0 = r0.nextEvent()     // Catch: java.lang.Throwable -> L38
                    r6 = r0
                    r0 = r6
                    boolean r0 = r0 instanceof com.sun.jdi.event.MethodEntryEvent     // Catch: java.lang.Throwable -> L38
                    if (r0 == 0) goto L32
                    r0 = r3
                    javassist.util.HotSwapper r0 = javassist.util.HotSwapper.this     // Catch: java.lang.Throwable -> L38
                    r0.hotswap()     // Catch: java.lang.Throwable -> L38
                    goto L35
                L32:
                    goto L11
                L35:
                    goto L3e
                L38:
                    r5 = move-exception
                    r0 = r3
                    r1 = r5
                    r0.errorMsg(r1)
                L3e:
                    r0 = r4
                    if (r0 == 0) goto L48
                    r0 = r4
                    r0.resume()     // Catch: java.lang.Throwable -> L4b
                L48:
                    goto L51
                L4b:
                    r5 = move-exception
                    r0 = r3
                    r1 = r5
                    r0.errorMsg(r1)
                L51:
                    return
                */
                throw new UnsupportedOperationException("Method not decompiled: javassist.util.HotSwapper.C00251.run():void");
            }
        }.start();
    }

    EventSet waitEvent() throws InterruptedException {
        EventQueue queue = this.jvm.eventQueue();
        return queue.remove();
    }

    void hotswap() {
        Map<ReferenceType, byte[]> map = this.newClassFiles;
        this.jvm.redefineClasses(map);
        this.newClassFiles = null;
    }
}