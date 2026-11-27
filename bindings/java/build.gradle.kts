plugins {
    `java-library`
}

group = "io.github.tothanggtvt.openadblock"
version = "0.8.2"

java {
    withSourcesJar()
}

tasks.withType<JavaCompile>().configureEach {
    // Java 17 bytecode: Android (D8) and every current desktop JVM accept it.
    options.release.set(17)
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

// The smoke test needs the host JNI library; it runs through scripts/test-jvm.sh instead of the
// Gradle test task so this build stays dependency-free.
sourceSets { test { java.setSrcDirs(emptyList<String>()) } }
