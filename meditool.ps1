# Este script está diseñado como una herramienta de seguridad (Blue Team)
# para la verificación y corrección de vulnerabilidades comunes en sistemas Windows 10 y 11.
# Script version 3.4.0 (Versión Final con Flujo Corregido por Programeta)

# --- Lógica de autodescarga, elevación de permisos y limpieza ---
$scriptName = "meditool.ps1"
$scriptUrl = "https://raw.githubusercontent.com/HooKgHosT/meditool/main/meditool.ps1" # URL de ejemplo
$tempPath = Join-Path $env:TEMP $scriptName

function Test-AdminPrivileges {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (($MyInvocation.MyCommand.Path -ne $tempPath) -and (-not (Test-AdminPrivileges))) {
    try {
        Write-Host "Iniciando la descarga del script temporal..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
        Write-Host "Descargado en: $tempPath" -ForegroundColor Cyan
        Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempPath`"" -Verb RunAs
        exit
    } catch {
        Write-Host "Error al descargar o relanzar el script: $($_.Exception.Message)" -ForegroundColor Red
        Read-Host "Presione Enter para salir."
        exit 1
    }
}

# --- INICIO DEL BLOQUE QUE REQUIERE PERMISOS DE ADMINISTRADOR ---
if (Test-AdminPrivileges) {

    # Variables globales
    $global:ActionLog = [System.Collections.Generic.List[PSCustomObject]]::new()
    $global:InitialSystemState = $null
    $global:VirusTotalApiKey = $null
    $global:VirusTotalScans = [System.Collections.Generic.List[PSCustomObject]]::new()
    $OutputEncoding = [System.Text.UTF8Encoding]::new()

    # --- Funciones de Soporte ---
    function Add-LogEntry {
        param([string]$Message)
        $logEntry = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Action    = $Message
        }
        $global:ActionLog.Add($logEntry)
    }

    function Clean-ScriptFromTemp {
        if (Test-Path $tempPath) {
            try { Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

# --- Bloque de Todas las Funciones de Auditoría y Hardening ---

function Get-SafeAuthenticodeSignature { param([string]$Path) ; try { if (Test-Path -Path $Path -PathType Leaf) { return Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop } } catch { return [PSCustomObject]@{ Status = "Unknown" } }; return $null }
function Get-LastIncomingRDPLogon { try { $event = Get-WinEvent -FilterHashtable @{Logname='Security'; Id=4624; Data='3389'} -MaxEvents 1 -ErrorAction Stop; if ($event) { return [PSCustomObject]@{ Fecha = $event.TimeCreated; Usuario = $event.Properties[5].Value; Origen = $event.Properties[18].Value } } } catch { return $null }; return $null }
function Get-LastOutgoingRDPConnection { try { $event = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-TerminalServices-Client/Operational'; Id=1024} -MaxEvents 1 -ErrorAction Stop; if ($event) { return [PSCustomObject]@{ Host = $event.Properties[1].Value; Fecha = $event.TimeCreated } } } catch { return $null }; return $null }

function Get-RDPStatus {
    $rdpIn = Get-LastIncomingRDPLogon
    $rdpOut = Get-LastOutgoingRDPConnection
    $service = Get-Service -Name TermService -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") { Write-Host "Estado RDP: El servicio se está ejecutando." -ForegroundColor Yellow } 
        else { Write-Host "Estado RDP: El servicio está detenido." -ForegroundColor Green }
    } else { Write-Host "Estado RDP: El servicio no está instalado." -ForegroundColor Cyan }
    Write-Host "`nÚltima Conexión Entrante:"; if ($rdpIn) { $rdpIn | Format-List } else { Write-Host "  N/A" }
    Write-Host "`nÚltima Conexión Saliente:"; if ($rdpOut) { $rdpOut | Format-List } else { Write-Host "  N/A" }
}

function Get-VirusTotalReport {
    param([Parameter(Mandatory=$true)][string]$FilePath)
    if (-not (Test-Path $FilePath)) { Write-Host "Error: El archivo '$FilePath' no fue encontrado." -ForegroundColor Red; return }
    if ([string]::IsNullOrEmpty($global:VirusTotalApiKey)) {
        Write-Host "Para usar esta función, necesitas una clave API de VirusTotal." -ForegroundColor Yellow
        $global:VirusTotalApiKey = Read-Host "Por favor, ingresa tu clave API de VirusTotal"
    }
    try {
        Write-Host "Calculando hash del archivo..." -ForegroundColor Cyan
        $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $headers = @{ "x-apikey" = $global:VirusTotalApiKey }
        $uri = "https://www.virustotal.com/api/v3/files/$fileHash"
        Write-Host "Consultando la API de VirusTotal..." -ForegroundColor Cyan
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        $stats = $response.data.attributes.last_analysis_stats
        $detections = $stats.malicious
        $totalEngines = $stats.harmless + $stats.malicious + $stats.suspicious + $stats.undetected + $stats.timeout
        $scanResult = [PSCustomObject]@{ File = $FilePath; Hash = $fileHash; Detections = $detections; Total = $totalEngines; Status = "OK" }
        if ($detections -gt 0) {
            Write-Host "¡ALERTA! VirusTotal detectó este archivo como malicioso." -ForegroundColor Red
            Write-Host "Resultado: $detections / $totalEngines motores lo marcaron como malicioso." -ForegroundColor Red
            $scanResult.Status = "Malicioso"
        } else {
            Write-Host "El archivo parece seguro según VirusTotal." -ForegroundColor Green
            Write-Host "Resultado: $detections / $totalEngines motores lo marcaron como malicioso." -ForegroundColor Green
            $scanResult.Status = "Limpio"
        }
        $global:VirusTotalScans.Add($scanResult)
    } catch {
        Write-Host "Ocurrió un error al contactar con VirusTotal. Verifica tu API Key o conexión." -ForegroundColor Red
        $global:VirusTotalScans.Add([PSCustomObject]@{ File = $FilePath; Hash = "N/A"; Detections = "N/A"; Total = "N/A"; Status = "Error" })
    }
}

function Verify-FileSignatures {
    Write-Host "Verificando firmas de archivos en rutas críticas..." -ForegroundColor Yellow
    $criticalPaths = @("$env:SystemRoot\System32", "$env:ProgramFiles", "$env:ProgramFiles(x86)")
    $unsignedFiles = @()
    foreach ($path in $criticalPaths) {
        try {
            $files = Get-ChildItem -Path $path -Recurse -File -Include "*.exe", "*.dll" -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ((Get-SafeAuthenticodeSignature -Path $file.FullName).Status -ne "Valid") { $unsignedFiles += $file }
            }
        } catch { }
    }
    if ($unsignedFiles.Count -gt 0) {
        Write-Host "Se encontraron archivos sin firma digital o con firma inválida:" -ForegroundColor Red
        $unsignedFiles | Select-Object Name, DirectoryName, LastWriteTime | Format-Table -AutoSize
        Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
        Write-Host "1. Analizar un archivo de la lista con VirusTotal"
        Write-Host "0. Volver al menú principal"
        $option = Read-Host "Seleccione una opción"
        if ($option -eq "1") {
            $fileToScan = Read-Host "Ingrese la ruta completa del archivo que desea analizar"
            Get-VirusTotalReport -FilePath $fileToScan
        }
    } else {
        Write-Host "No se encontraron archivos críticos sin firmar." -ForegroundColor Green
    }
}

function Generate-HTMLReport {
    if ($null -eq $global:InitialSystemState) {
        Write-Host "El estado inicial no ha sido capturado. Realizando análisis ahora..." -ForegroundColor Yellow
        Capture-InitialState
    }
    
    Add-LogEntry -Message "Generando reporte de seguridad en HTML."
    Write-Host "Generando reporte de seguridad..." -ForegroundColor Yellow
    $reportData = $global:InitialSystemState
    
    # --- Estilo CSS para el Reporte ---
    $htmlHead = @"
<head>
<meta charset="UTF-8">
<title>Reporte de Seguridad - MediTool</title>
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; font-size: 12pt; }
    .container { max-width: 1200px; margin: auto; background: #fff; padding: 2em; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    h1, h2, h3 { color: #2a2a72; border-bottom: 2px solid #2a2a72; padding-bottom: 0.5em; }
    table { width: 100%; border-collapse: collapse; margin-top: 1em; }
    th, td { text-align: left; padding: 10px; border: 1px solid #ddd; word-break: break-word; }
    th { background-color: #4a4a8c; color: white; }
    .status-ok { color: #5cb85c; font-weight: bold; }
    .status-danger { color: #d9534f; font-weight: bold; }
    .status-warn { color: #f0ad4e; font-weight: bold; }
    p { line-height: 1.6; }
</style>
</head>
"@

    # --- Construcción del Cuerpo del Reporte ---
    $htmlBody = "<body><div class='container'>"
    $htmlBody += "<h1>Reporte de Seguridad del Sistema - MediTool</h1>"
    $htmlBody += "<p><strong>Fecha de Generación del Reporte:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>"
    $htmlBody += "<p><strong>Usuario:</strong> $($reportData.InformacionSistema.UsuarioActual)</p>"
    $htmlBody += "<p><strong>Equipo:</strong> $($reportData.InformacionSistema.NombreEquipo)</p>"

    # Función auxiliar para crear tablas
    function ConvertTo-HtmlTable {
        param($Title, $Data)
        $html = "<h2>$Title</h2>"
        if ($Data) {
            $html += $Data | ConvertTo-Html -Fragment
        } else {
            $html += "<p>No se encontraron elementos para esta categoría.</p>"
        }
        return $html
    }

    # --- Secciones del Reporte ---
    $htmlBody += ConvertTo-HtmlTable "Reglas de Firewall Inseguras (Estado Inicial)" $reportData.ReglasFirewallInseguras
    $htmlBody += ConvertTo-HtmlTable "Tareas Programadas Sospechosas" $reportData.TareasProgramadasSospechosas
    $htmlBody += ConvertTo-HtmlTable "Procesos en Ejecución sin Firma" $reportData.ProcesosSinFirma
    $htmlBody += ConvertTo-HtmlTable "Entradas de Inicio Automático (Autorun) Sospechosas" $reportData.EntradasAutorunSospechosas
    
    # --- Sección de Hardening ---
    $htmlBody += "<h2>Resultados de Chequeos de Hardening</h2>"
    $htmlBody += "<h3>Anti-PEAS (Enumeración)</h3>"
    $htmlBody += $reportData.ResultadosAntiPEAS | ConvertTo-Html -Fragment
    $htmlBody += "<h3>Anti-Robo-Credenciales</h3>"
    $htmlBody += $reportData.ResultadosAntiCredenciales | ConvertTo-Html -Fragment
    $htmlBody += "<h3>Políticas de Seguridad Locales</h3>"
    $htmlBody += $reportData.ResultadosPoliticasLocales | ConvertTo-Html -Fragment

    # --- Sección de Eventos Críticos ---
    $htmlBody += "<h2>Auditoría de Eventos Críticos</h2>"
    $htmlBody += $reportData.ResultadosEventosCriticos | ConvertTo-Html -Fragment

    # --- Sección de VirusTotal ---
    $htmlBody += "<h2>Resultados de Análisis con VirusTotal</h2>"
    if ($global:VirusTotalScans.Count -gt 0) {
        $htmlBody += $global:VirusTotalScans | ConvertTo-Html -Fragment
    } else {
        $htmlBody += "<p>No se realizaron análisis con VirusTotal durante esta sesión.</p>"
    }

    # --- Log de Acciones del Usuario ---
    $htmlBody += "<h2>Registro de Acciones Realizadas Durante la Sesión</h2>"
    if ($global:ActionLog.Count -gt 0) {
        $htmlBody += $global:ActionLog | ConvertTo-Html -Fragment
    } else {
        $htmlBody += "<p>No se realizaron acciones manuales durante esta sesión.</p>"
    }

    $htmlBody += "</div></body>"

    # --- Guardar y Abrir el Archivo HTML ---
    $reportPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath "Security_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    try {
        ConvertTo-Html -Head $htmlHead -Body $htmlBody | Out-File -FilePath $reportPath -Encoding utf8 -ErrorAction Stop
        Write-Host "Reporte generado con éxito en: $reportPath" -ForegroundColor Green
        Invoke-Item $reportPath
    } catch {
        Write-Host "Error al guardar el reporte en el escritorio: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-VirusTotalReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        Write-Host "Error: El archivo '$FilePath' no fue encontrado." -ForegroundColor Red
        Add-LogEntry -Message "Error: Intento de análisis de VirusTotal en un archivo no existente: $FilePath"
        return
    }

    if ([string]::IsNullOrEmpty($global:VirusTotalApiKey)) {
        Write-Host "Para usar esta función, necesitas una clave API de VirusTotal." -ForegroundColor Yellow
        Write-Host "Puedes obtener una gratis registrándote en www.virustotal.com" -ForegroundColor Yellow
        $global:VirusTotalApiKey = Read-Host "Por favor, ingresa tu clave API de VirusTotal"
    }

    try {
        Write-Host "Calculando hash del archivo..." -ForegroundColor Cyan
        $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        Write-Host "Hash (SHA256): $fileHash" -ForegroundColor Cyan
        Add-LogEntry -Message "Calculado hash SHA256 para '$FilePath': $fileHash"

        $headers = @{ "x-apikey" = $global:VirusTotalApiKey }
        $uri = "https://www.virustotal.com/api/v3/files/$fileHash"

        Write-Host "Consultando la API de VirusTotal..." -ForegroundColor Cyan
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

        $stats = $response.data.attributes.last_analysis_stats
        $detections = $stats.malicious
        $totalEngines = $stats.harmless + $stats.malicious + $stats.suspicious + $stats.undetected + $stats.timeout

        $scanResult = [PSCustomObject]@{
            File = $FilePath
            Hash = $fileHash
            Detections = $detections
            Total = $totalEngines
            Status = "OK"
        }

        if ($detections -gt 0) {
            Write-Host "¡ALERTA! VirusTotal detectó este archivo como malicioso." -ForegroundColor Red
            Write-Host "Resultado: $detections / $totalEngines motores de antivirus lo marcaron como malicioso." -ForegroundColor Red
            $scanResult.Status = "Malicioso"
            Add-LogEntry -Message "ALERTA VirusTotal: '$FilePath' detectado como malicioso ($detections/$totalEngines)."
        } else {
            Write-Host "El archivo parece seguro según VirusTotal." -ForegroundColor Green
            Write-Host "Resultado: $detections / $totalEngines motores de antivirus lo marcaron como malicioso." -ForegroundColor Green
            $scanResult.Status = "Limpio"
            Add-LogEntry -Message "Análisis VirusTotal OK para '$FilePath' ($detections/$totalEngines)."
        }
        $global:VirusTotalScans.Add($scanResult) # Se agrega al log para el reporte HTML

    } catch {
        Write-Host "Ocurrió un error al contactar con VirusTotal." -ForegroundColor Red
        Write-Host "Detalles: $($_.Exception.Message)" -ForegroundColor Red
        Add-LogEntry -Message "Error en la consulta a VirusTotal para '$FilePath': $($_.Exception.Message)"
        $global:VirusTotalScans.Add([PSCustomObject]@{ File = $FilePath; Hash = "N/A"; Detections = "N/A"; Total = "N/A"; Status = "Error" })
    }
}

function Invoke-PeasHardeningChecks {
    Write-Host "`n--- Realizando Chequeos de Hardening contra Herramientas de Enumeración (PEAS) ---" -ForegroundColor Cyan
    Write-Host "`n[1] Buscando rutas de servicio sin comillas..." -ForegroundColor Yellow
    $unquotedServices = Get-CimInstance Win32_Service | Where-Object { $_.PathName -like '* *' -and $_.PathName -notlike '"*' }
    if ($unquotedServices) {
        Write-Host "[VULNERABLE] Se encontraron servicios con rutas sin comillas. Esto puede permitir escalada de privilegios:" -ForegroundColor Red
        $unquotedServices | Format-Table Name, PathName -AutoSize
    } else { Write-Host "[OK] No se encontraron servicios con rutas vulnerables." -ForegroundColor Green }
    Write-Host "`n[2] Verificando la política 'AlwaysInstallElevated'..." -ForegroundColor Yellow
    $keyPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; $keyPath2 = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
    $value1 = Get-ItemPropertyValue -Path $keyPath1 -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $value2 = Get-ItemPropertyValue -Path $keyPath2 -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    if ($value1 -eq 1 -and $value2 -eq 1) {
        Write-Host "[VULNERABLE] La política 'AlwaysInstallElevated' está activada." -ForegroundColor Red
        $fix = Read-Host "¿Desea deshabilitar esta política ahora? (S/N)"; if ($fix -eq 's') { Set-ItemProperty -Path $keyPath1 -Name "AlwaysInstallElevated" -Value 0; Set-ItemProperty -Path $keyPath2 -Name "AlwaysInstallElevated" -Value 0; Write-Host "[CORREGIDO] La política ha sido deshabilitada." -ForegroundColor Green; Add-LogEntry -Message "Política 'AlwaysInstallElevated' deshabilitada." }
    } else { Write-Host "[OK] La política 'AlwaysInstallElevated' no está activada." -ForegroundColor Green }
    Write-Host "`n[3] Listando credenciales guardadas por el sistema (cmdkey)..." -ForegroundColor Yellow
    $credList = cmdkey /list
    if ($credList -match "Currently stored credentials") { Write-Host "[INFO] Se encontraron las siguientes credenciales guardadas. Revise si son necesarias:" -ForegroundColor Cyan; $credList } 
    else { Write-Host "[OK] No se encontraron credenciales guardadas con cmdkey." -ForegroundColor Green }
    Write-Host "`n[4] Verificando si el motor de PowerShell v2 está habilitado..." -ForegroundColor Yellow
    $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
    if ($psv2Feature.State -eq 'Enabled') { Write-Host "[ADVERTENCIA] El motor de PowerShell v2 está HABILITADO. Se recomienda deshabilitarlo." -ForegroundColor Yellow } 
    else { Write-Host "[OK] El motor de PowerShell v2 está deshabilitado." -ForegroundColor Green }
    Write-Host "`n--- Chequeo de Hardening finalizado ---" -ForegroundColor Cyan
}

function Invoke-CredentialHardeningChecks {
    Write-Host "`n--- Realizando Chequeos de Hardening contra Robo de Credenciales (Mimikatz) ---" -ForegroundColor Cyan
    
    # 1. Verificar si la Protección LSA (Local Security Authority) está activada
    Write-Host "`n[1] Verificando la Protección LSA (RunAsPPL)..." -ForegroundColor Yellow
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lsaProtection = Get-ItemPropertyValue -Path $lsaKey -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($lsaProtection -eq 1) { 
        Write-Host "[OK] La Protección LSA está HABILITADA." -ForegroundColor Green 
    } else { 
        Write-Host "[VULNERABLE] La Protección LSA está DESHABILITADA." -ForegroundColor Red
        $fix = Read-Host "¿Desea HABILITAR la Protección LSA ahora (requiere reiniciar)? (S/N)"
        if ($fix -eq 's') { 
            Set-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value 1 -Type DWord
            Write-Host "[CORREGIDO] Protección LSA habilitada. REINICIE el equipo para que el cambio surta efecto." -ForegroundColor Green
            Add-LogEntry -Message "Protección LSA (RunAsPP) habilitada." 
        } 
    }
    
    # 2. Verificar si WDigest está deshabilitado (LÓGICA CORREGIDA)
    Write-Host "`n[2] Verificando el proveedor de seguridad WDigest..." -ForegroundColor Yellow
    $wdigestKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $useLogonCred = Get-ItemPropertyValue -Path $wdigestKey -Name "UseLogonCredential" -ErrorAction SilentlyContinue

    if ($useLogonCred -eq 1) {
        # Este es el único caso VULNERABLE
        Write-Host "[VULNERABLE] WDigest está configurado para almacenar credenciales en texto claro en memoria." -ForegroundColor Red
        $fix = Read-Host "¿Desea forzar la DESHABILITACIÓN de WDigest ahora? (S/N)"
        if ($fix -eq 's') {
            if (-not (Test-Path $wdigestKey)) { New-Item -Path $wdigestKey -Force | Out-Null }
            Set-ItemProperty -Path $wdigestKey -Name "UseLogonCredential" -Value 0 -Type DWord
            Write-Host "[CORREGIDO] El almacenamiento de credenciales de WDigest ha sido deshabilitado." -ForegroundColor Green
            Add-LogEntry -Message "Almacenamiento de credenciales de WDigest deshabilitado."
        }
    } else {
        # Si la clave no existe ($useLogonCred es $null) o es 0, es SEGURO
        Write-Host "[OK] WDigest está correctamente configurado para no almacenar credenciales en memoria." -ForegroundColor Green
    }

    # 3. Comprobar si Credential Guard está activo
    Write-Host "`n[3] Verificando el estado de Credential Guard..." -ForegroundColor Yellow
    try { 
        $cgStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
        if ($cgStatus -contains "Credential Guard") { Write-Host "[OK] Credential Guard está activo." -ForegroundColor Green } 
        else { Write-Host "[INFO] Credential Guard no está activo." -ForegroundColor Cyan } 
    } catch { 
        Write-Host "[INFO] No se pudo determinar el estado de Credential Guard." -ForegroundColor Cyan 
    }
    
    # 4. Revisar la política de caché de credenciales de dominio
    Write-Host "`n[4] Verificando la política de caché de credenciales de dominio..." -ForegroundColor Yellow
    $cacheKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $cachedLogons = Get-ItemPropertyValue -Path $cacheKey -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
    if (!($cachedLogons)) { $cachedLogons = "No definido (defecto 10)"}
    if ($cachedLogons -gt 4 -or $cachedLogons -like "*defecto*") { 
        Write-Host "[ADVERTENCIA] El sistema almacena en caché '$($cachedLogons)' inicios de sesión." -ForegroundColor Yellow 
    } else { 
        Write-Host "[OK] La política de caché de credenciales está en un nivel aceptable (Valor: $cachedLogons)." -ForegroundColor Green 
    }
    
    Write-Host "`n--- Chequeo de Credenciales finalizado ---" -ForegroundColor Cyan
}

function Invoke-CriticalEventsAudit {
    Write-Host "`n--- Realizando Auditoría de Eventos de Seguridad Críticos ---" -ForegroundColor Cyan
    Write-Host "`n[1] Buscando intentos de borrado de huellas (Log de Seguridad)..." -ForegroundColor Yellow
    try { $clearedLogs = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -ErrorAction Stop; if ($clearedLogs) { Write-Host "[ALERTA] ¡Se ha detectado que el registro de seguridad ha sido borrado!" -ForegroundColor Red; $clearedLogs | Select-Object TimeCreated, Id, Message | Format-List } else { Write-Host "[OK] No se encontraron eventos de borrado del registro de seguridad." -ForegroundColor Green } } catch { Write-Host "[INFO] No se encontraron eventos de borrado o no se pudo acceder al log de seguridad." -ForegroundColor Cyan }
    Write-Host "`n--- Auditoría de Eventos Críticos finalizada ---" -ForegroundColor Cyan
}

function Invoke-LocalPolicyChecks {
    Write-Host "`n--- Verificando Políticas de Seguridad Locales Fundamentales ---" -ForegroundColor Cyan
    Write-Host "`n[1] Verificando estado de User Account Control (UAC)..." -ForegroundColor Yellow
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacEnabled = Get-ItemPropertyValue -Path $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uacEnabled -eq 1) { Write-Host "[OK] User Account Control (UAC) está HABILITADO." -ForegroundColor Green } else { Write-Host "[VULNERABLE] User Account Control (UAC) está DESHABILITADO." -ForegroundColor Red }
    Write-Host "`n[2] Verificando estado de cifrado de disco (BitLocker)..." -ForegroundColor Yellow
    try { $bitlockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; if ($bitlockerVolume.ProtectionStatus -eq 'On') { Write-Host "[OK] La unidad del sistema ($($env:SystemDrive)) está CIFRADA." -ForegroundColor Green } else { Write-Host "[ADVERTENCIA] La unidad del sistema ($($env:SystemDrive)) NO está cifrada." -ForegroundColor Yellow } } catch { Write-Host "[INFO] No se pudo determinar el estado de BitLocker." -ForegroundColor Cyan }
    Write-Host "`n[3] Mostrando política de contraseñas local..." -ForegroundColor Yellow
    $netAccounts = net accounts
    if ($netAccounts) { Write-Host "[INFO] La política de contraseñas configurada en este equipo es:" -ForegroundColor Cyan; $netAccounts } else { Write-Host "[ERROR] No se pudo obtener la política de contraseñas." -ForegroundColor Red }
    Write-Host "`n--- Verificación de Políticas Locales finalizada ---" -ForegroundColor Cyan
}


##### MODULO FIREWALL

function Get-FirewallStatus {
    $shouldContinue = $true
    do {
        Write-Host "`nMostrando reglas de firewall de entrada activas..." -ForegroundColor Yellow
        try {
            $allRules = Get-NetFirewallRule | Where-Object { 
                $_.Enabled -eq "True" -and ($_.Direction -eq "Inbound" -or $_.Direction -eq "Both") -and ($_.Action -eq "Allow")
            }

            if ($allRules.Count -gt 0) {
                Write-Host "Se encontraron las siguientes reglas de firewall:" -ForegroundColor Green
                $allRules | ForEach-Object {
                    $rule = $_
                    $programName = if ($rule.Program) { Split-Path -Path $rule.Program -Leaf } else { "N/A" }
                    $process = if ($programName -ne "N/A") { Get-Process -Name $programName -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null }
                    $pid = if ($process) { $process.Id } else { "N/A" }
                    
                    Write-Host "Regla: $($rule.DisplayName)" -ForegroundColor White
                    Write-Host "  - Programa: $programName" -ForegroundColor Cyan
                    Write-Host "  - PID: $pid" -ForegroundColor Cyan
                    Write-Host "  - Protocolo: $($rule.Protocol)" -ForegroundColor Cyan
                    Write-Host "  - Puerto: $($rule.LocalPort)" -ForegroundColor Cyan
                    Write-Host "--------------------------------"
                }
            } else {
                Write-Host "No se encontraron reglas de firewall que permitan conexiones entrantes." -ForegroundColor Green
            }
        } catch {
            Write-Host "Error al obtener las reglas del Firewall." -ForegroundColor Red
        }

        Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
        Write-Host "1. Volver a escanear"
        Write-Host "2. Cerrar un proceso por PID"
        Write-Host "3. Bloquear un proceso por PID"
        Write-Host "0. Volver al menú principal"
        
        $choice = Read-Host "Seleccione una opción"
        
        switch ($choice) {
            "1" {}
            "2" {
                $pidToClose = Read-Host "PID del proceso a cerrar"
                Stop-OrBlock-Process -pid $pidToClose -action "close"
            }
            "3" {
                $pidToBlock = Read-Host "PID del proceso a bloquear"
                Stop-OrBlock-Process -pid $pidToBlock -action "block"
            }
            "0" { $shouldContinue = $false }
            default { Write-Host "Opción no válida." -ForegroundColor Red }
        }
    } while ($shouldContinue)
}

function Stop-OrBlock-Process {
    param (
        [Parameter(Mandatory=$true)]
        [int]$pid,
        [Parameter(Mandatory=$true)]
        [string]$action
    )
    try {
        $process = Get-Process -Id $pid -ErrorAction Stop
        $processPath = $process.Path
        $programName = Split-Path -Path $processPath -Leaf

        if ($action -eq "close") {
            Stop-Process -Id $pid -Force
            Write-Host "Proceso '$programName' con PID $pid cerrado." -ForegroundColor Green
        } elseif ($action -eq "block") {
            $ruleName = "Bloqueado por MediTool - $programName"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $processPath -Action Block
                Write-Host "Regla de firewall creada para '$programName'." -ForegroundColor Green
            } else {
                Write-Host "Una regla para '$programName' ya existe." -ForegroundColor Yellow
            }
            Stop-Process -Id $pid -Force
            Write-Host "Proceso '$programName' cerrado." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: No se pudo manipular el proceso con PID $pid." -ForegroundColor Red
    }
}

function Fix-FirewallPorts {
    Write-Host "Cerrando puertos inseguros (RDP/WinRM)..." -ForegroundColor Yellow
    try {
        $rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and ($_.LocalPort -in @("3389", "5985", "5986")) }
        if ($rules.Count -gt 0) {
            $rules | Remove-NetFirewallRule -Confirm:$false
            Write-Host "Puertos cerrados exitosamente." -ForegroundColor Green
        } else {
            Write-Host "No se encontraron reglas de firewall inseguras." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error al cerrar los puertos." -ForegroundColor Red
    }
}

##### FIN FIREWALL

function Manage-RDP {
    Write-Host "`n Estado actual del RDP: $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections').fDenyTSConnections)"
    Write-Host ""
    Write-Host "1. Habilitar RDP"
    Write-Host "2. Deshabilitar RDP"
    Write-Host "0. Volver al menú principal`n"
    $rdpOption = Read-Host "Seleccione una opción: "
    
    try {
        if ($rdpOption -eq "1") {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
            Write-Host "RDP habilitado.`n" -ForegroundColor Green
        } elseif ($rdpOption -eq "2") {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
            Write-Host "RDP deshabilitado.`n" -ForegroundColor Yellow
        } elseif ($rdpOption -eq "0") {
            # Volver al menú principal.
        } else {
            Write-Host "Opción no válida." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al cambiar el estado del RDP. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
    }
}

function Get-TelemetryStatus {
    try {
        $regValue = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue
        
        if ($null -eq $regValue) {
            return "`n No configurada/Deshabilitada"
        }
        
        if ($regValue -eq 0) {
            return "Deshabilitada"
        } else {
            return "Habilitada"
        }
    } catch {
        return "No configurada/Error"
    }
}

function Manage-WindowsTelemetry {
    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    $regProperty = 'AllowTelemetry'

    try {
        $regValue = Get-ItemPropertyValue -Path $regPath -Name $regProperty -ErrorAction Stop
        Write-Host "`nEstado actual de la telemetría de Windows: $regValue"
    } catch {
        Write-Host "`nEstado actual de la telemetría de Windows: No configurada"
    }
    
    Write-Host ""
    Write-Host "1. Habilitar Telemetría"
    Write-Host "2. Deshabilitar Telemetría"
    Write-Host "0. Volver al menú principal"
    $telemetryOption = Read-Host "`nSeleccione una opción"
    
    try {
        if (-not (Test-Path -Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        if ($telemetryOption -eq "1") {
            Set-ItemProperty -Path $regPath -Name $regProperty -Value 1 -Type DWORD -Force
            Write-Host "`nTelemetría habilitada." -ForegroundColor Green
        } elseif ($telemetryOption -eq "2") {
            Set-ItemProperty -Path $regPath -Name $regProperty -Value 0 -Type DWORD -Force
            Write-Host "`nTelemetría deshabilitada." -ForegroundColor Yellow
        } elseif ($telemetryOption -eq "0") {
            # Volver al menú principal.
        } else {
            Write-Host "Opción no válida." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al cambiar el estado de la telemetría. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
    }
}

function Find-MaliciousScheduledTasks {
    Write-Host "`nBuscando tareas programadas con alto riesgo..." -ForegroundColor Yellow
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notlike "\Microsoft\Windows\*" -and $_.TaskPath -notlike "\Microsoft\Office\*" }
        $suspiciousTasks = @()
        foreach ($task in $tasks) {
            $action = $task.Actions[0]
            if ($action -and $action.Path -and ($action.Path.ToLower() -notmatch "c:\\windows") -and ($action.Path.ToLower() -notmatch "c:\\program files")) {
                $suspiciousTasks += $task
            }
        }
        return $suspiciousTasks | Select-Object TaskName, State, TaskPath, @{Name="ActionPath";Expression={$_.Actions.Path}}
    } catch {
        Write-Host "Error al auditar tareas programadas. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
        return $null
    }
}

function Audit-NonEssentialServices {
    $shouldContinue = $true
    do {
        Write-Host "`nAuditoría de servicios no esenciales en ejecución..." -ForegroundColor Yellow
        
        # Lista de servicios no esenciales que comúnmente se pueden deshabilitar
        $nonEssentialServices = @(
            "Fax", "HomeGroupProvider", "Spooler", "Themes", "WSearch", 
            "DiagTrack", "CDPSvc", "PcaSvc", "RemoteRegistry", "SensorService"
        )
    
        $runningNonEssential = Get-Service -Name $nonEssentialServices -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }

        if ($runningNonEssential.Count -gt 0) {
            Write-Host "Se encontraron los siguientes servicios no esenciales en ejecución:" -ForegroundColor Red
            $runningNonEssential | Select-Object Name, DisplayName, Status | Format-Table -AutoSize
            Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
            Write-Host "1. Gestionar un servicio de esta lista"
            Write-Host "0. Volver al menú principal"
            
            $choice = Read-Host "Seleccione una opción"
            
            if ($choice -eq "1") {
                Write-Host "`nOpciones para gestionar un servicio:" -ForegroundColor Cyan
                Write-Host "1. Iniciar servicio"
                Write-Host "2. Detener servicio"
                Write-Host "3. Deshabilitar servicio"
                Write-Host "4. Eliminar servicio (Advertencia)"
                $serviceAction = Read-Host "Seleccione una acción"
                
                $serviceName = Read-Host "Ingrese el nombre del servicio que desea gestionar"
                
                try {
                    $service = Get-Service -Name $serviceName -ErrorAction Stop
                    
                    switch ($serviceAction) {
                        "1" {
                            if ($service.Status -ne "Running") {
                                Start-Service -InputObject $service -ErrorAction Stop
                                Write-Host "Servicio '$serviceName' iniciado exitosamente." -ForegroundColor Green
                            } else {
                                Write-Host "El servicio '$serviceName' ya está en ejecución." -ForegroundColor Yellow
                            }
                        }
                        "2" {
                            if ($service.Status -ne "Stopped") {
                                Stop-Service -InputObject $service -ErrorAction Stop
                                Write-Host "Servicio '$serviceName' detenido exitosamente." -ForegroundColor Green
                            } else {
                                Write-Host "El servicio '$serviceName' ya está detenido." -ForegroundColor Yellow
                            }
                        }
                        "3" {
                            Set-Service -InputObject $service -StartupType Disabled -ErrorAction Stop
                            Write-Host "Servicio '$serviceName' deshabilitado exitosamente." -ForegroundColor Green
                        }
                        "4" {
                            Write-Host "ADVERTENCIA: ¿Está seguro de que quiere eliminar el servicio '$serviceName'? (S/N)" -ForegroundColor Red
                            $confirm = Read-Host
                            if ($confirm -eq "S" -or $confirm -eq "s") {
                                Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" | Invoke-CimMethod -MethodName Delete -ErrorAction Stop
                                Write-Host "Servicio '$serviceName' eliminado exitosamente." -ForegroundColor Green
                            } else {
                                Write-Host "Operación de eliminación cancelada." -ForegroundColor Yellow
                            }
                        }
                        default {
                            Write-Host "Acción no válida." -ForegroundColor Red
                        }
                    }
                } catch {
                    Write-Host "Error: No se pudo encontrar o manipular el servicio '$serviceName'." -ForegroundColor Red
                }
            } elseif ($choice -eq "0") {
                $shouldContinue = $false
            } else {
                Write-Host "Opción no válida. Intente de nuevo." -ForegroundColor Red
            }
        } else {
            Write-Host "No se encontraron servicios no esenciales en ejecución." -ForegroundColor Green
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
            $shouldContinue = $false
        }
    } while ($shouldContinue)
}

function Find-InactiveUsers {
    Write-Host "`nBuscando usuarios inactivos..." -ForegroundColor Yellow
    try {
        $inactiveUsers = Get-LocalUser | Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-90) }
        return $inactiveUsers | Select-Object Name, LastLogon, Enabled
    } catch {
        Write-Host "Error al buscar usuarios inactivos. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
        return $null
    }
}

function Verify-FileSignatures {
    Write-Host "Verificando firmas de archivos en rutas críticas... (Esto puede tardar unos minutos)" -ForegroundColor Yellow
    
    $criticalPaths = @("$env:SystemRoot\System32", "$env:ProgramFiles", "$env:ProgramFiles(x86)")
    $unsignedFiles = @()

    foreach ($path in $criticalPaths) {
        Write-Host "  - Analizando ruta: $path" -ForegroundColor Gray
        try {
            $files = Get-ChildItem -Path $path -Recurse -File -Include "*.exe", "*.dll" -ErrorAction SilentlyContinue
            
            foreach ($file in $files) {
                $signature = Get-SafeAuthenticodeSignature -Path $file.FullName
                if ($signature.Status -ne "Valid") {
                    $unsignedFiles += $file
                }
            }
        } catch { }
    }
    
    Write-Host "Verificación de firmas de archivos completada." -ForegroundColor Green
    
    if ($unsignedFiles.Count -gt 0) {
        Write-Host "Se encontraron archivos sin firma digital o con firma inválida:" -ForegroundColor Red
        $unsignedFiles | Select-Object Name, DirectoryName, LastWriteTime | Format-Table -AutoSize

        Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
        Write-Host "1. Analizar un archivo con VirusTotal"
        Write-Host "0. Volver al menú principal"
        
        $option = Read-Host "Seleccione una opción"
        
        switch ($option) {
            "1" {
                Add-LogEntry -Message "Usuario seleccionó 'Analizar con VirusTotal' desde el menú de firmas."
                $fileToScan = Read-Host "Ingrese la ruta completa del archivo que desea analizar"
                Get-VirusTotalReport -FilePath $fileToScan
            }
            "0" { }
            default {
                Write-Host "Opción no válida." -ForegroundColor Red
            }
        }
    }
}

function Find-UnsignedProcesses {
    Write-Host "`nBuscando procesos en ejecución sin firma digital..." -ForegroundColor Yellow
    
    $unsignedProcesses = @()
    # Excluir procesos comunes que a menudo no están firmados para reducir falsos positivos
    $excludedProcesses = @("steam", "steamwebhelper", "Discord", "RiotClientServices", "LeagueClient", "EpicGamesLauncher", "zoom", "chrome", "firefox", "msedge")

    $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ($excludedProcesses -notcontains $_.ProcessName) }

    foreach ($process in $processes) {
        try {
            $signature = Get-SafeAuthenticodeSignature -Path $process.Path
            if ($signature.Status -ne "Valid") {
                $unsignedProcesses += $process
            }
        } catch { }
    }
    Write-Host "`nBúsqueda de procesos sin firma completada." -ForegroundColor Green
    return $unsignedProcesses
}

function Stop-SuspiciousProcess {
    Write-Host "`nDeteniendo procesos sospechosos..." -ForegroundColor Yellow
    $processes = Find-UnsignedProcesses
    
    if ($processes.Count -eq 0) {
        Write-Host "No se encontraron procesos sin firma para detener." -ForegroundColor Green
        return
    }
    
    Write-Host "Se encontraron los siguientes procesos sin firma digital:" -ForegroundColor Red
    $processes | Select-Object ProcessName, Path, ID, StartTime | Format-Table -AutoSize
    
    $pidToStop = Read-Host "`nIngrese el PID del proceso que desea detener o presione '0' para volver"
    
    if ($pidToStop -eq "0") {
        Write-Host "Operación cancelada." -ForegroundColor Yellow
        return
    }
    
    try {
        Stop-Process -Id $pidToStop -Force -ErrorAction Stop
        Write-Host "Proceso con PID $pidToStop detenido exitosamente." -ForegroundColor Green
    } catch {
        Write-Host "No se pudo detener el proceso. Verifique el PID y los permisos." -ForegroundColor Red
    }
}

function Block-FileExecution {
    $FileToBlock = Read-Host "Ingrese la ruta del archivo que desea bloquear (ej. C:\malware.exe)"

    if ([string]::IsNullOrEmpty($FileToBlock)) {
        Write-Host "Error: No se ha proporcionado una ruta de archivo." -ForegroundColor Red
        return
    }
    
    if (-not (Test-Path $FileToBlock)) {
        Write-Host "Error: El archivo no existe." -ForegroundColor Red
        return
    }
    try {
        $ruleName = "BlockExecution_$(Get-Random)"
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $FileToBlock -Action Block
        Write-Host "Regla de Firewall '$ruleName' creada para bloquear la ejecución de '$FileToBlock'." -ForegroundColor Green
    } catch {
        Write-Host "Error al crear la regla de Firewall." -ForegroundColor Red
    }
}

function Find-RegistryAutorun {
    Write-Host "Buscando entradas de inicio automático sospechosas..." -ForegroundColor Yellow
    $suspiciousEntries = GetData-RegistryAutorun 
    
    if ($suspiciousEntries.Count -gt 0) {
        Write-Host "Se encontraron las siguientes entradas de Autorun sospechosas:" -ForegroundColor Red
        $suspiciousEntries | Format-Table -AutoSize
        
        Write-Host "`n¿Desea eliminar una entrada de la lista? (S/N)" -ForegroundColor Cyan
        $choice = Read-Host
        if ($choice -eq 's') {
            $keyToRemove = Read-Host "Ingrese el nombre de la 'Clave' que desea eliminar"
            $entryToRemove = $suspiciousEntries | Where-Object { $_.Clave -eq $keyToRemove } | Select-Object -First 1
            
            if ($entryToRemove) {
                try {
                    Remove-ItemProperty -Path $entryToRemove.Ubicacion -Name $entryToRemove.Clave -Force -ErrorAction Stop
                    Write-Host "Clave del registro eliminada exitosamente." -ForegroundColor Green
                } catch {
                    Write-Host "Error al eliminar la clave." -ForegroundColor Red
                }
            } else {
                Write-Host "No se encontró la clave especificada." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No se encontraron entradas de inicio automático sospechosas." -ForegroundColor Green
    }
}

function Manage-RegistryAutorun {
    Write-Host "Buscando entradas de inicio automático sospechosas..." -ForegroundColor Yellow
    $suspiciousEntries = GetData-RegistryAutorun 
    
    if ($suspiciousEntries.Count -gt 0) {
        Write-Host "Se encontraron las siguientes entradas de Autorun sospechosas:" -ForegroundColor Red
        $suspiciousEntries | Format-Table -AutoSize
        
        Write-Host "`n¿Desea eliminar una entrada de la lista? (S/N)" -ForegroundColor Cyan
        $choice = Read-Host
        if ($choice -eq 's') {
            $keyToRemove = Read-Host "Ingrese el nombre de la 'Clave' que desea eliminar"
            $entryToRemove = $suspiciousEntries | Where-Object { $_.Clave -eq $keyToRemove } | Select-Object -First 1
            
            if ($entryToRemove) {
                try {
                    Remove-ItemProperty -Path $entryToRemove.Ubicacion -Name $entryToRemove.Clave -Force -ErrorAction Stop
                    Write-Host "Clave del registro eliminada exitosamente." -ForegroundColor Green
                } catch {
                    Write-Host "Error al eliminar la clave." -ForegroundColor Red
                }
            } else {
                Write-Host "No se encontró la clave especificada." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No se encontraron entradas de inicio automático sospechosas." -ForegroundColor Green
    }
}

function Analyze-NetworkConnections {
    Write-Host "`nAnalizando la configuracion de red..." -ForegroundColor Yellow
    
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
        if ($adapters.Count -gt 0) {
            foreach ($adapter in $adapters) {
                Write-Host "`n--- Adaptador: $($adapter.Name) ---" -ForegroundColor Cyan
                $ipAddress = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object { $_.AddressFamily -eq 'IPv4' }
                $gateway = Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
                $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                
                if ($ipAddress) {
                    Write-Host "  - Direccion IP: $($ipAddress.IPAddress)" -ForegroundColor White
                } else { Write-Host "  - Direccion IP: No disponible" -ForegroundColor Red }
                
                if ($gateway) {
                    Write-Host "  - Puerta de Enlace: $($gateway.NextHop)" -ForegroundColor White
                } else { Write-Host "  - Puerta de Enlace: No disponible" -ForegroundColor Red }

                if ($dns) {
                    $dnsServers = $dns.ServerAddresses -join ", "
                    Write-Host "  - Servidores DNS: $($dnsServers)" -ForegroundColor White
                } else { Write-Host "  - Servidores DNS: No disponible" -ForegroundColor Red }
            }
        } else {
            Write-Host "No se encontraron adaptadores de red activos." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al obtener informacion de la red: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`n`nAnalizando conexiones de red en busca de actividad sospechosa..." -ForegroundColor Yellow
    
    $suspiciousPorts = @(31337, 21, 22, 23, 8080, 4444, 5900, 5901)
    
    try {
        $allConnections = Get-NetTCPConnection
        $unsignedProcesses = Find-UnsignedProcesses
        
        $suspiciousConnections = $allConnections | Where-Object { 
            ($_.RemotePort -in $suspiciousPorts) -or
            ($_.State -eq "CloseWait") -or
            ($unsignedProcesses | Where-Object { $_.Id -eq $_.OwningProcess }).Count -gt 0
        }

        if ($suspiciousConnections.Count -gt 0) {
            Write-Host "Se encontraron las siguientes conexiones sospechosas:" -ForegroundColor Red
            $suspiciousConnections | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
            
            $pidToClose = Read-Host "`nPara cerrar una conexion, ingresa el PID (OwningProcess) o '0' para cancelar"
            if ($pidToClose -ne "0" -and $pidToClose) {
                try {
                    Stop-Process -Id $pidToClose -Force -ErrorAction Stop
                    Write-Host "Proceso con PID $pidToClose y sus conexiones cerradas." -ForegroundColor Green
                } catch { Write-Host "No se pudo cerrar el proceso con PID $pidToClose." -ForegroundColor Red }
            }
        } else {
            Write-Host "No se encontro actividad de red sospechosa." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error al analizar las conexiones de red." -ForegroundColor Red
    }
}

function Find-HiddenFilesAndScan {
    Write-Host "`nBuscando archivos ocultos en Programdata y Usuarios..." -ForegroundColor Yellow
    
    $suspiciousPaths = @("C:\ProgramData", "$env:USERPROFILE\AppData\Local")
    $foundFiles = @()

    foreach ($path in $suspiciousPaths) {
        if (Test-Path -Path $path) {
            try {
                $foundFiles += Get-ChildItem -Path $path -Recurse -Hidden -Force -ErrorAction Stop | Where-Object { !$_.PSIsContainer }
            } catch { }
        }
    }
    
    if ($foundFiles.Count -gt 0) {
        Write-Host "`nSe encontraron archivos ocultos:" -ForegroundColor Red
        $foundFiles | Format-Table Name, Directory, CreationTime -AutoSize
        
        Write-Host "`n¿Deseas escanear estos archivos con Windows Defender? (S/N)"
        $scanChoice = Read-Host
        if ($scanChoice -eq "S" -or $scanChoice -eq "s") {
            Write-Host "Iniciando escaneo con Windows Defender. Esto puede tardar." -ForegroundColor Green
            foreach ($file in $foundFiles) {
                Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-Scan -ScanType 3 -File `"$($file.FullName)`"" -Wait
            }
            Write-Host "`n¡Escaneo completado!" -ForegroundColor Green
        }
    } else {
        Write-Host "`nNo se encontraron archivos ocultos sospechosos." -ForegroundColor Green
    }
}

function Audit-FailedLogons {
    Write-Host "`nAuditando inicios de sesión fallidos de las últimas 24 horas..." -ForegroundColor Yellow
    $lastDay = (Get-Date).AddDays(-1)
    
    $failedLogons = Get-WinEvent -FilterHashtable @{ 
        Logname = 'Security'; 
        Id = 4625; 
        StartTime = $lastDay 
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{ Name = 'Usuario'; Expression = { $_.Properties[5].Value } }, @{ Name = 'Origen'; Expression = { $_.Properties[18].Value } }
    
    if ($failedLogons) {
        Write-Host "Se encontraron los siguientes intentos de inicio de sesión fallidos:" -ForegroundColor Red
        $failedLogons | Format-Table -AutoSize
    } else {
        Write-Host "No se encontraron intentos de inicio de sesión fallidos en las últimas 24 horas." -ForegroundColor Green
    }
}

function Activate-Windows {
    Write-Host "ADVERTENCIA: Va a ejecutar un script de activación NO OFICIAL de Internet." -ForegroundColor Red
    $confirm = Read-Host "Para continuar, presione 'S'. Para cancelar, presione cualquier otra tecla."

    if ($confirm -eq "S" -or $confirm -eq "s") {
        try {
            irm https://get.activated.win | iex
        } catch {
            Write-Host "Error al ejecutar el comando de activación." -ForegroundColor Red
        }
    } else {
        Write-Host "Activación cancelada." -ForegroundColor Yellow
    }
}

function Generate-HTMLReport {
    if ($null -eq $global:InitialSystemState) {
        Write-Host "Primero se debe realizar un análisis completo (Opción 27)." -ForegroundColor Yellow
        Write-Host "Iniciando análisis ahora. Esto puede tardar varios minutos..." -ForegroundColor Yellow
        Capture-InitialState
    }
    
    Add-LogEntry -Message "Generando reporte de seguridad en HTML."
    Write-Host "Generando reporte de seguridad..." -ForegroundColor Yellow
    $reportData = $global:InitialSystemState
    
    $head = @"
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }
h1, h2 { color: #2a2a72; border-bottom: 2px solid #2a2a72; padding-bottom: 0.5em; }
table { width: 100%; border-collapse: collapse; margin-top: 1em; }
th, td { text-align: left; padding: 8px; border: 1px solid #ddd; word-break: break-all; }
th { background-color: #4a4a8c; color: white; }
</style>
"@

    $body = "<h1>Reporte de Seguridad - MediTool</h1><p><strong>Fecha:</strong> $(Get-Date)</p>"
    $body += "<h2>Configuración Inicial</h2><p><strong>Usuario:</strong> $($reportData.InformacionSistema.UsuarioActual)</p><p><strong>Equipo:</strong> $($reportData.InformacionSistema.NombreEquipo)</p>"
    $body += "<h3>Tareas Programadas Sospechosas</h3>" + ($reportData.TareasProgramadasSospechosas | ConvertTo-Html -Fragment)
    $body += "<h3>Procesos sin Firma</h3>" + ($reportData.ProcesosSinFirma | Select-Object ProcessName, ID, Path, StartTime | ConvertTo-Html -Fragment)
    $body += "<h3>Archivos Críticos sin Firma</h3>" + ($reportData.ArchivosSinFirmaCriticos | Select-Object Name, DirectoryName, LastWriteTime | ConvertTo-Html -Fragment)
    $body += "<h3>Entradas de Autorun Sospechosas</h3>" + ($reportData.EntradasAutorunSospechosas | ConvertTo-Html -Fragment)
    $body += "<h2>Registro de Acciones Realizadas</h2>" + ($global:ActionLog | ConvertTo-Html -Fragment)
    
    $reportPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath "Security_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    try {
        ConvertTo-Html -Head $head -Body $body | Out-File -FilePath $reportPath -Encoding utf8 -ErrorAction Stop
        Write-Host "Reporte generado con éxito en: $reportPath" -ForegroundColor Green
        Invoke-Item $reportPath
    } catch {
        Write-Host "Error al guardar el reporte: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Funciones de Soporte para el Reporte ---
function GetData-FirewallRules {
    try {
        return Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and ($_.LocalPort -in @("3389", "5985", "5986")) }
    } catch { return @() }
}

function GetData-RegistryAutorun {
    $autorunPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    $suspiciousEntries = @()
    $excludedPrograms = @("discord", "spotify", "riot", "steam", "epic", "zoom", "microsoft", "google", "brave", "opera", "teams")
    foreach ($path in $autorunPaths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | ForEach-Object {
                $propName = $_.Name
                if ($propName -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $propValue = (Get-ItemProperty -Path $path)."$propName"
                    $isExcluded = $false
                    foreach ($excluded in $excludedPrograms) {
                        if ($propValue -like "*$excluded*") { $isExcluded = $true; break }
                    }
                    if (-not $isExcluded) {
                        $suspiciousEntries += [PSCustomObject]@{ "Clave" = $propName; "Ruta" = $propValue; "Ubicacion" = $path }
                    }
                }
            }
        } catch {}
    }
    return $suspiciousEntries
}

function GetData-UnsignedFiles {
    Write-Host "Analizando firmas de archivos críticos... (Esto es lento)" -ForegroundColor Cyan
    $criticalPaths = @("$env:SystemRoot\System32", "$env:ProgramFiles", "$env:ProgramFiles(x86)")
    $unsignedFiles = @()
    foreach ($path in $criticalPaths) {
        try {
            $files = Get-ChildItem -Path $path -Recurse -File -Include "*.exe", "*.dll" -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ((Get-SafeAuthenticodeSignature -Path $file.FullName).Status -ne "Valid") {
                    $unsignedFiles += $file
                }
            }
        } catch { }
    }
    return $unsignedFiles
}

function Capture-InitialState {
    Write-Host "Capturando estado inicial del sistema para el reporte..." -ForegroundColor Cyan
    $global:InitialSystemState = [PSCustomObject]@{
        FechaAnalisis                 = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        InformacionSistema            = Get-UserInfo
        EstadoRDP                     = Get-RDPStatus # Simplificado para el reporte
        ReglasFirewallInseguras       = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and ($_.LocalPort -in @("3389", "5985", "5986")) } | Select-Object DisplayName, Protocol, LocalPort, Program
        TareasProgramadasSospechosas  = Find-MaliciousScheduledTasks 
        ProcesosSinFirma              = Find-UnsignedProcesses | Select-Object ProcessName, ID, Path, StartTime
        ArchivosSinFirmaCriticos      = (Get-ChildItem -Path @("$env:SystemRoot\System32", "$env:ProgramFiles", "$env:ProgramFiles(x86)") -Recurse -File -Include "*.exe", "*.dll" -ErrorAction SilentlyContinue | Where-Object { (Get-SafeAuthenticodeSignature -Path $_.FullName).Status -ne "Valid" }) | Select-Object Name, DirectoryName, LastWriteTime
        EntradasAutorunSospechosas    = GetData-RegistryAutorun -Silent
        ResultadosAntiPEAS            = Invoke-PeasHardeningChecks -ForReport
        ResultadosAntiCredenciales    = Invoke-CredentialHardeningChecks -ForReport
        ResultadosEventosCriticos     = Invoke-CriticalEventsAudit -ForReport
        ResultadosPoliticasLocales    = Invoke-LocalPolicyChecks -ForReport
    }
    Add-LogEntry -Message "Se ha capturado el estado de configuración inicial del sistema."
}

function Get-UserInfo {
    try {
        $adminGroup = (Get-LocalGroup | Where-Object { $_.SID -eq "S-1-5-32-544" }).Name
        $adminMembers = (Get-LocalGroupMember -Group $adminGroup).Name
    } catch { $adminMembers = "No se pudo obtener" }
    
    return [PSCustomObject]@{
        "UsuarioActual"        = $env:USERNAME
        "NombreEquipo"         = $env:COMPUTERNAME
        "AdministradoresLocales" = $adminMembers
    }
}

# --- Funciones Adicionales Restauradas ---

function Update-AllWingetApps {
    Write-Host "Iniciando la actualización de todas las aplicaciones con winget..." -ForegroundColor Green
    Write-Host "Esto puede tardar varios minutos." -ForegroundColor Yellow
    try {
        winget upgrade --all --include-unknown --force --accept-package-agreements --accept-source-agreements
        Write-Host "`nTodas las aplicaciones se han actualizado." -ForegroundColor Green
    } catch {
        Write-Host "`nOcurrió un error al ejecutar winget." -ForegroundColor Red
    }
}

function Clean-SystemJunk {
    Write-Host "`nLimpiando archivos temporales y caches del sistema..." -ForegroundColor Yellow
    $tempFolders = @("$env:TEMP", "$env:SystemRoot\Temp", "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache")
    
    foreach ($folder in $tempFolders) {
        if (Test-Path -Path $folder) {
            Write-Host "Limpiando $folder..." -ForegroundColor Yellow
            Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "`nLimpieza de carpetas temporales completada." -ForegroundColor Green
}

function Invoke-CredentialHardeningChecks {
    Write-Host "`n--- Realizando Chequeos de Hardening contra Robo de Credenciales (Mimikatz) ---" -ForegroundColor Cyan
    
    # 1. Verificar si la Protección LSA (Local Security Authority) está activada
    Write-Host "`n[1] Verificando la Protección LSA (RunAsPPL)..." -ForegroundColor Yellow
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lsaProtection = Get-ItemPropertyValue -Path $lsaKey -Name "RunAsPPL" -ErrorAction SilentlyContinue
    if ($lsaProtection -eq 1) {
        Write-Host "[OK] La Protección LSA está HABILITADA. lsass.exe se ejecuta como un proceso protegido." -ForegroundColor Green
    } else {
        Write-Host "[VULNERABLE] La Protección LSA está DESHABILITADA. Esto facilita que herramientas como Mimikatz extraigan credenciales de la memoria." -ForegroundColor Red
        $fix = Read-Host "¿Desea HABILITAR la Protección LSA ahora (requiere reiniciar)? (S/N)"
        if ($fix -eq 's') {
            Set-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value 1 -Type DWord
            Write-Host "[CORREGIDO] Protección LSA habilitada. Por favor, REINICIE el equipo para que el cambio surta efecto." -ForegroundColor Green
            Add-LogEntry -Message "Protección LSA (RunAsPPL) habilitada."
        }
    }
    
    # 2. Verificar si WDigest está deshabilitado
    Write-Host "`n[2] Verificando el proveedor de seguridad WDigest..." -ForegroundColor Yellow
    $wdigestKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $useLogonCred = Get-ItemPropertyValue -Path $wdigestKey -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    if ($useLogonCred -eq 0) {
        Write-Host "[OK] WDigest está correctamente configurado para no almacenar credenciales en memoria." -ForegroundColor Green
    } else {
        Write-Host "[VULNERABLE] WDigest podría estar almacenando credenciales en texto claro en memoria." -ForegroundColor Red
        $fix = Read-Host "¿Desea forzar la DESHABILITACIÓN de WDigest ahora? (S/N)"
        if ($fix -eq 's') {
            Set-ItemProperty -Path $wdigestKey -Name "UseLogonCredential" -Value 0 -Type DWord
            Write-Host "[CORREGIDO] El almacenamiento de credenciales de WDigest ha sido deshabilitado." -ForegroundColor Green
            Add-LogEntry -Message "Almacenamiento de credenciales de WDigest deshabilitado."
        }
    }

    # 3. Comprobar si Credential Guard está activo
    Write-Host "`n[3] Verificando el estado de Credential Guard (basado en virtualización)..." -ForegroundColor Yellow
    try {
        $cgStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
        if ($cgStatus -contains "Credential Guard") {
            Write-Host "[OK] Credential Guard está activo y protegiendo las credenciales." -ForegroundColor Green
        } else {
            Write-Host "[INFO] Credential Guard no está activo. Esta es una característica de alta seguridad para Windows Enterprise/Education." -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[INFO] No se pudo determinar el estado de Credential Guard. La característica puede no ser compatible." -ForegroundColor Cyan
    }

    # 4. Revisar la política de caché de credenciales de dominio
    Write-Host "`n[4] Verificando la política de caché de credenciales de dominio..." -ForegroundColor Yellow
    $cacheKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $cachedLogons = Get-ItemPropertyValue -Path $cacheKey -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
    if (!($cachedLogons)) { $cachedLogons = "No definido (defecto 10)"}
    if ($cachedLogons -gt 4 -or $cachedLogons -like "*defecto*") {
        Write-Host "[ADVERTENCIA] El sistema está configurado para almacenar en caché '$($cachedLogons)' inicios de sesión. Se recomienda un valor bajo (ej. 2 o 0)." -ForegroundColor Yellow
    } else {
        Write-Host "[OK] La política de caché de credenciales está en un nivel aceptable (Valor: $cachedLogons)." -ForegroundColor Green
    }

    Write-Host "`n--- Chequeo de Credenciales finalizado ---" -ForegroundColor Cyan
}

function Clean-ScriptFromTemp {
    $tempFile = Join-Path $env:TEMP $scriptName
    if (Test-Path $tempFile) {
        try {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            Write-Host "Script temporal eliminado de $env:TEMP" -ForegroundColor Cyan
        } catch {
            Write-Host "No se pudo eliminar el script temporal." -ForegroundColor Red
        }
    }
}

function Find-OrphanedAndZeroByteFiles {
    Write-Host "`nBuscando archivos de 0 bytes..." -ForegroundColor Yellow
    $suspiciousPaths = @("$env:USERPROFILE", "C:\ProgramData")
    $foundFiles = @()

    foreach ($path in $suspiciousPaths) {
        try {
            $foundFiles += Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -eq 0 }
        } catch { }
    }

    if ($foundFiles.Count -gt 0) {
        Write-Host "`nSe encontraron los siguientes archivos de 0 bytes:" -ForegroundColor Red
        $foundFiles | Select-Object Name, Directory, LastWriteTime | Format-Table -AutoSize
        
        $choice = Read-Host "`n¿Deseas eliminar estos archivos? (S/N)"
        if ($choice -eq "S" -or $choice -eq "s") {
            $foundFiles | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Host "Archivos eliminados." -ForegroundColor Green
        }
    } else {
        Write-Host "No se encontraron archivos de 0 bytes." -ForegroundColor Green
    }
}

function Analyze-SystemMemory {
    Write-Host "`nIniciando análisis de memoria del sistema..." -ForegroundColor Yellow
    
    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId, Name, ParentProcessId, ExecutablePath
    $suspiciousProcesses = @()
    foreach ($proc in $processes) {
        if ($proc.Name -eq "svchost.exe") {
            $parent = $processes | Where-Object { $_.ProcessId -eq $proc.ParentProcessId }
            if ($parent.Name -ne "services.exe") {
                $suspiciousProcesses += [PSCustomObject]@{
                    ProcessName = $proc.Name; PID = $proc.ProcessId; ParentName = $parent.Name; Reason = "svchost.exe con un padre inusual"
                }
            }
        }
    }
    
    Write-Host "`nAnálisis de memoria completado." -ForegroundColor Green
    if ($suspiciousProcesses.Count -gt 0) {
        Write-Host "Se encontraron las siguientes anomalías en memoria:" -ForegroundColor Red
        $suspiciousProcesses | Format-Table -AutoSize
    } else {
        Write-Host "No se encontraron anomalías obvias en la memoria." -ForegroundColor Green
    }
}

function Check-ISO27001Status {
    Write-Host "`n--------------------------------------------------" -ForegroundColor Cyan
    Write-Host "--- Estado de Seguridad (Basado en ISO 27001) ---" -ForegroundColor Cyan
    
    # Control A.12.2.1: Controles contra el malware
    try {
        if ((Get-MpComputerStatus).AntivirusEnabled) {
            Write-Host "[ok] Antivirus (Windows Defender) está activo." -ForegroundColor Green
        } else {
            Write-Host "[X] Antivirus (Windows Defender) está deshabilitado." -ForegroundColor Red
        }
    } catch {
        Write-Host "[X] No se pudo verificar el estado del antivirus." -ForegroundColor Red
    }

    # Control A.13.2.1: Procedimientos de inicio de sesión seguros
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue) -eq 1) {
        Write-Host "[ok] El servicio RDP está deshabilitado." -ForegroundColor Green
    } else {
        Write-Host "[!] El servicio RDP está habilitado. Asegúrese de que sea necesario." -ForegroundColor Yellow
    }
    Write-Host "----------------------------------------------------" -ForegroundColor Cyan
}

# --- MENÚ PRINCIPAL ---
function Show-MainMenu {
    Clear-Host
    Write-Host "`n=====================================================" -ForegroundColor Green
    Write-Host "=         Herramienta de Auditoría MediTool         =" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host "Versión 1.4.0 (Final) - por h00kGh0st"
    Write-Host ""
    
    $menuOptions = @(
        [PSCustomObject]@{ "ID" = 1; "Opcion" = "Revisar Estado de RDP y Ultimas Conexiones" },
        [PSCustomObject]@{ "ID" = 2; "Opcion" = "Auditar Reglas de Firewall Inseguras" },
        [PSCustomObject]@{ "ID" = 3; "Opcion" = "Cerrar Puertos Inseguros (RDP/WinRM)" },
        [PSCustomObject]@{ "ID" = 4; "Opcion" = "Administrar el servicio de RDP" },
        [PSCustomObject]@{ "ID" = 5; "Opcion" = "Administrar la Telemetria de Windows" },
        [PSCustomObject]@{ "ID" = 6; "Opcion" = "Buscar Tareas Programadas Maliciosas" },
        [PSCustomObject]@{ "ID" = 7; "Opcion" = "Auditar Servicios No Esenciales" },      
        [PSCustomObject]@{ "ID" = 8; "Opcion" = "Buscar Cuentas de Usuario Inactivas" },
        [PSCustomObject]@{ "ID" = 9; "Opcion" = "Verificar Firmas de Archivos Criticos" },
        [PSCustomObject]@{ "ID" = 10; "Opcion" = "Verificar Procesos en Ejecucion sin Firma" },
        [PSCustomObject]@{ "ID" = 11; "Opcion" = "Detener Procesos Sin Firma" },
        [PSCustomObject]@{ "ID" = 12; "Opcion" = "Bloquear Ejecucion de Archivo" },
        [PSCustomObject]@{ "ID" = 13; "Opcion" = "Auditar Registro de Inicio Automatico (Autorun)" },
        [PSCustomObject]@{ "ID" = 14; "Opcion" = "Analizar Conexiones de Red" },
        [PSCustomObject]@{ "ID" = 16; "Opcion" = "Buscar Archivos Ocultos" },
        [PSCustomObject]@{ "ID" = 17; "Opcion" = "Auditar Inicios de Sesion Fallidos" },
        [PSCustomObject]@{ "ID" = 19; "Opcion" = "Generar Reporte de Seguridad (HTML)" },
        [PSCustomObject]@{ "ID" = 20; "Opcion" = "Informacion del Usuario y Sistema" },
        [PSCustomObject]@{ "ID" = 22; "Opcion" = "Actualizar todas las aplicaciones (winget)" },
        [PSCustomObject]@{ "ID" = 23; "Opcion" = "Verificacion de Estado (ISO 27001 simplificado)" },
        [PSCustomObject]@{ "ID" = 24; "Opcion" = "Limpiar Archivos Temporales del Sistema" },
        [PSCustomObject]@{ "ID" = 25; "Opcion" = "Buscar Archivos de 0 Bytes" },
        [PSCustomObject]@{ "ID" = 26; "Opcion" = "Analizar Memoria del Sistema" },
        [PSCustomObject]@{ "ID" = 27; "Opcion" = "Realizar Análisis Completo del Sistema (Necesario para Reporte)" },
        [PSCustomObject]@{ "ID" = 28; "Opcion" = "Realizar Chequeo Anti-PEAS (Hardening)" },
        [PSCustomObject]@{ "ID" = 29; "Opcion" = "Realizar Chequeo Anti-Robo-Credenciales (Hardening)" },
        [PSCustomObject]@{ "ID" = 30; "Opcion" = "Auditar Eventos Críticos (Borrado de Logs)" },
        [PSCustomObject]@{ "ID" = 31; "Opcion" = "Verificar Políticas de Seguridad Locales (UAC, BitLocker)" },
        [PSCustomObject]@{ "ID" = 88; "Opcion" = "Activar Windows (Advertencia de Seguridad)" },
        [PSCustomObject]@{ "ID" = 99; "Opcion" = "Mensaje del Creador" },
        [PSCustomObject]@{ "ID" = 0; "Opcion" = "Salir" }
    )
    
    $script:menuOptions = $menuOptions 
    $menuOptions | Format-Table -Property @{Expression="ID"; Width=4}, Opcion -HideTableHeaders
    
    $selection = Read-Host "Ingresa el numero de la opcion que deseas ejecutar"
    return $selection
}
# El script ahora inicia directamente en el menú.
# La función Capture-InitialState se llama desde la Opción 27 o desde la 19 (Reporte).
# --- BUCLE PRINCIPAL ---
    Write-Host "El script se está ejecutando con permisos de Administrador." -ForegroundColor Green
    # (Captura de estado inicial)
    # Capture-InitialState # Puedes descomentar esto si quieres que se ejecute al inicio

    while ($true) {
        $selection = Show-MainMenu
        
        switch ($selection) {
        "1" { Get-RDPStatus }
        "2" { Get-FirewallStatus }
        "3" { Fix-FirewallPorts }
        "4" { Manage-RDP }
        "5" { Manage-WindowsTelemetry }
        "6" { Find-MaliciousScheduledTasks | Format-Table -AutoSize }
        "7" { Audit-NonEssentialServices }
        "8" { Find-InactiveUsers | Format-Table -AutoSize }
        "9" { Verify-FileSignatures }
        "10" { Find-UnsignedProcesses | Format-Table -AutoSize }
        "11" { Stop-SuspiciousProcess }
        "12" { Block-FileExecution }
        "13" { Manage-RegistryAutorun }
        "14" { Analyze-NetworkConnections }
        "16" { Find-HiddenFilesAndScan }
        "17" { Audit-FailedLogons }
        "19" { Generate-HTMLReport }
        "20" { Get-UserInfo | Format-List }
        "22" { Update-AllWingetApps }
        "23" { Check-ISO27001Status }
        "24" { Clean-SystemJunk }
        "25" { Find-OrphanedAndZeroByteFiles }
        "26" { Analyze-SystemMemory }
        "27" {
            Write-Host "Iniciando análisis completo del sistema. Esto puede tardar varios minutos..." -ForegroundColor Yellow
            Capture-InitialState
            Write-Host "Análisis completo y captura de estado finalizados." -ForegroundColor Green
        }
        "28" { Invoke-PeasHardeningChecks }
        "29" { Invoke-CredentialHardeningChecks }
        "30" { Invoke-CriticalEventsAudit }
        "31" { Invoke-LocalPolicyChecks }
        "88" { Activate-Windows }
        "99" { Write-Host "Copyright (c) 2023 h00kGh0st" -ForegroundColor Cyan }
        "0" {
            Clean-ScriptFromTemp
            Write-Host "Saliendo del programa. ¡Adiós!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host "Opción no válida. Por favor, intente de nuevo." -ForegroundColor Red
        }
    }

    # Pausa para que el usuario pueda ver el resultado antes de volver al menú
    if ($selection -ne "0") {
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
}
