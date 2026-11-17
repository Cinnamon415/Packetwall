plugins {
    id("com.android.application") version "9.1.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.2.10" apply false
    id("com.diffplug.spotless") version "7.0.4"
}

// Formatting: ./gradlew spotlessApply (fix) / spotlessCheck (verify)
spotless {
    kotlin {
        target("app/src/**/*.kt")
        ktlint("1.5.0")
    }
    kotlinGradle {
        target("*.gradle.kts", "app/*.gradle.kts")
        ktlint("1.5.0")
    }
}
