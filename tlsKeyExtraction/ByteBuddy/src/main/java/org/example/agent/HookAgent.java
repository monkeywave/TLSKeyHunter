package org.example.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

import java.lang.instrument.Instrumentation;


import static net.bytebuddy.matcher.ElementMatchers.none;

public class HookAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        installHook(inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) throws InterruptedException {
        installHook(inst);
    }

    private static void installHook(Instrumentation inst) {
        new AgentBuilder.Default()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
            .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
            .disableClassFormatChanges()
            .with(AgentBuilder.Listener.StreamWriting.toSystemError().withTransformationsOnly())
            .with(AgentBuilder.InstallationListener.StreamWriting.toSystemError())
            .ignore(none())
            .type(ElementMatchers.named("sun.security.ssl.SSLSessionImpl"))
            .transform((builder, typeDescription, classLoader, javaModule, protectionDomain) -> builder
                    .visit(Advice.to(GetMasterSecretAdvice.class)
                            .on(ElementMatchers.named("getMasterSecret")))
            )
            .installOn(inst);

        new AgentBuilder.Default()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .disableClassFormatChanges()
                .with(AgentBuilder.Listener.StreamWriting.toSystemError().withTransformationsOnly())
                .with(AgentBuilder.InstallationListener.StreamWriting.toSystemError())
                .ignore(none())
                .type(ElementMatchers.named("sun.security.internal.spec.TlsKeyMaterialParameterSpec"))
                .transform((builder, typeDescription, classLoader, javaModule, protectionDomain) -> builder
                        .visit(Advice.to(GetClientRandomAdvice.class)
                                .on(ElementMatchers.named("getClientRandom")))
                )
                .installOn(inst);

        // TLS 1.3
        new AgentBuilder.Default()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .disableClassFormatChanges()
                .with(AgentBuilder.Listener.StreamWriting.toSystemError().withTransformationsOnly())
                .with(AgentBuilder.InstallationListener.StreamWriting.toSystemError())
                .ignore(none())
                .type(ElementMatchers.named("sun.security.ssl.SSLTrafficKeyDerivation"))
                .transform((builder, typeDescription, classLoader, javaModule, protectionDomain) -> builder
                        .visit(Advice.to(GetTrafficKeysAdvice.class)
                                .on(ElementMatchers.named("createKeyDerivation")))
                )
                .installOn(inst);
    }
}
