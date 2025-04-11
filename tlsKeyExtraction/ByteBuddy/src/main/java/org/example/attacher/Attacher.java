package org.example.attacher;

import com.sun.tools.attach.VirtualMachine;

public class Attacher {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java Attacher <PID> <PATH-TO-AGENT.jar>");
            System.exit(1);
        }

        String pid = args[0];
        String path = args[1];

        try {
            System.out.println("Attaching to proess " + pid);
            VirtualMachine vm = VirtualMachine.attach(pid);
            System.out.println("Attached to " + pid);
            System.out.println("Loading Agent from " + path);
            vm.loadAgent(path);
            vm.detach();
            System.out.println("Agent loaded and detached");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
