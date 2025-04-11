plugins {
    id("java")
    id("application")
    kotlin("jvm") version "1.8.10"
    id("com.github.johnrengelman.shadow") version "7.1.2"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("net.bytebuddy:byte-buddy:latest.release")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.test {
    useJUnitPlatform()
}

application {
    mainClass.set("org.example.attacher.Attacher")
}

tasks {
    jar {
        manifest {
            attributes(
                "Premain-Class" to "org.example.agent.HookAgent",
                "Agent-Class" to "org.example.agent.HookAgent",
                "Can-Redefine-Classes" to "true",
                "Can-Retransform-Classes" to "true"
            )
        }
    }

    shadowJar {
        archiveBaseName.set("HookAgent")
        archiveClassifier.set("")
        archiveVersion.set("")

        manifest {
            attributes(
                "Premain-Class" to "org.example.agent.HookAgent",
                "Agent-Class" to "org.example.agent.HookAgent",
                "Can-Redefine-Classes" to "true",
                "Can-Retransform-Classes" to "true"
            )
        }
    }

    build {
        dependsOn(shadowJar)
    }
}