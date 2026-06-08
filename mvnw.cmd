@echo off
setlocal

set "JAVA_HOME=C:\Program Files\Java\jdk-21"
set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"

if not exist "%JAVA_EXE%" (
    for /d %%D in ("C:\Program Files\Java\jdk-21*") do (
        if exist "%%D\bin\java.exe" (
            set "JAVA_HOME=%%D"
            set "JAVA_EXE=%%D\bin\java.exe"
            goto :java_found
        )
    )
    echo ERROR: Java 21 not found. Expected JDK at:
    echo   C:\Program Files\Java\jdk-21
    echo   or C:\Program Files\Java\jdk-21*
    echo Install JDK 21 or set JAVA_HOME to your JDK 21 installation.
    exit /b 1
)

:java_found
set "DIRNAME=%~dp0"
set "DIRNAME=%DIRNAME:~0,-1%"
set "WRAPPER_JAR=%DIRNAME%\.mvn\wrapper\maven-wrapper.jar"

if not exist "%WRAPPER_JAR%" (
    echo ERROR: Maven wrapper JAR not found at %WRAPPER_JAR%
    echo Run: powershell -File mvnw.ps1 to use PowerShell wrapper instead.
    exit /b 1
)

"%JAVA_EXE%" -classpath "%WRAPPER_JAR%" "-Dmaven.multiModuleProjectDirectory=%DIRNAME%" org.apache.maven.wrapper.MavenWrapperMain %*
exit /b %ERRORLEVEL%
