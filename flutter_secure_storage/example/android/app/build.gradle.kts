import java.util.Properties
import java.nio.file.Files
import java.nio.file.Path

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("dev.flutter.flutter-gradle-plugin")
}

val localProperties: Properties = Properties()
val localPropertiesFile: Path = rootProject.file("local.properties").toPath()
if (Files.exists(localPropertiesFile)) {
    Files.newBufferedReader(localPropertiesFile).use { reader ->
        localProperties.load(reader)
    }
}

val flutterRoot: String = localProperties.getProperty("flutter.sdk")
    ?: throw GradleException("Flutter SDK not found. Define location with flutter.sdk in the local.properties file.")

val flutterVersionCode: String = localProperties.getProperty("flutter.versionCode") ?: "1"
val flutterVersionName: String = localProperties.getProperty("flutter.versionName") ?: "1.0"

android {
    namespace = "com.it_nomads.fluttersecurestorageexample"

    compileSdk = 34

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    sourceSets {
        named("main") {
            java.srcDir("src/main/kotlin")
        }
    }

    defaultConfig {
        applicationId = "com.it_nomads.fluttersecurestorageexample"
        minSdk = flutter.minSdkVersion
        targetSdk = 34
        versionCode = flutterVersionCode.toInt()
        versionName = flutterVersionName
    }

    buildTypes {
        getByName("release") {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}
