<#
.SYNOPSIS
    PowerShell Maven wrapper for SecureGate Nexus (Java 21)
.DESCRIPTION
    Use this instead of mvnw.cmd on Windows. It resolves JAVA_HOME to a local
    JDK 21 installation and invokes Maven through the wrapper JAR.
.EXAMPLE
    .\mvnw.ps1 spring-boot:run
    .\mvnw.ps1 clean compile
    .\mvnw.ps1 --version
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$MavenArgs
)

function Resolve-Jdk21Home {
    $candidates = @(
        "C:\Program Files\Java\jdk-21"
    )

    $versioned = Get-ChildItem -Path "C:\Program Files\Java" -Directory -Filter "jdk-21*" -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending

    foreach ($dir in $versioned) {
        $candidates += $dir.FullName
    }

    foreach ($home in $candidates) {
        $javaExe = Join-Path $home "bin\java.exe"
        if (Test-Path $javaExe) {
            return $home
        }
    }

    return $null
}

$JdkHome = Resolve-Jdk21Home
if (-not $JdkHome) {
    Write-Error @"
JDK 21 not found. Expected installation at:
  C:\Program Files\Java\jdk-21
  or C:\Program Files\Java\jdk-21*
Install JDK 21 or set JAVA_HOME to your JDK 21 installation.
"@
    exit 1
}

$env:JAVA_HOME = $JdkHome
$JavaExe = Join-Path $JdkHome "bin\java.exe"
$WrapperJar = Join-Path $PSScriptRoot ".mvn\wrapper\maven-wrapper.jar"

if (-not (Test-Path $WrapperJar)) {
    Write-Error "Maven wrapper JAR not found at $WrapperJar"
    exit 1
}

& $JavaExe -classpath $WrapperJar `
    "-Dmaven.multiModuleProjectDirectory=$PSScriptRoot" `
    org.apache.maven.wrapper.MavenWrapperMain @MavenArgs
exit $LASTEXITCODE
