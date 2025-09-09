# Este script está diseñado como una herramienta de seguridad (Blue Team)
# para la verificación y corrección de vulnerabilidades comunes en sistemas Windows 10 y 11.
# Script version 6.0.0 (Edición Definitiva y Completa por Programeta)

# --- Lógica de autodescarga, elevación de permisos y limpieza ---
$scriptName = "meditool.ps1"
$scriptUrl = "https://raw.githubusercontent.com/HooKgHosT/meditool/main/meditool.ps1"
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
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempPath`"" -Verb RunAs
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
    
    function Get-SafeAuthenticodeSignature { 
        param([string]$Path)
        try { 
            if (Test-Path -Path $Path -PathType Leaf) { 
                return Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop 
            } 
        } catch { 
            return [PSCustomObject]@{ Status = "Unknown" } 
        }
        return $null 
    }

    function Get-LastIncomingRDPLogon { 
        try { 
            $event = Get-WinEvent -FilterHashtable @{Logname='Security'; Id=4624; Data='3389'} -MaxEvents 1 -ErrorAction Stop
            if ($event) { 
                return [PSCustomObject]@{ 
                    Fecha = $event.TimeCreated
                    Usuario = $event.Properties[5].Value
                    Origen = $event.Properties[18].Value 
                } 
            } 
        } catch { 
            return $null 
        }
        return $null 
    }

    function Get-LastOutgoingRDPConnection { 
        try { 
            $event = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-TerminalServices-Client/Operational'; Id=1024} -MaxEvents 1 -ErrorAction Stop
            if ($event) { 
                return [PSCustomObject]@{ 
                    Host = $event.Properties[1].Value
                    Fecha = $event.TimeCreated 
                } 
            } 
        } catch { 
            return $null 
        }
        return $null 
    }

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

    function Get-FirewallStatus {
        Write-Host "`nMostrando reglas de firewall de entrada activas..." -ForegroundColor Yellow
        try {
            $allRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" }
            if ($allRules.Count -gt 0) {
                $allRules | Select-Object DisplayName, Group, Protocol, LocalPort, Program | Format-Table -AutoSize
            } else {
                Write-Host "No se encontraron reglas de firewall que permitan conexiones entrantes." -ForegroundColor Green
            }
        } catch {
            Write-Host "Error al obtener las reglas del Firewall." -ForegroundColor Red
        }
    }

    function Fix-FirewallPorts {
        Write-Host "Cerrando puertos inseguros (RDP/WinRM)..." -ForegroundColor Yellow
        try {
            $rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and ($_.LocalPort -in @("3389", "5985", "5986")) }
            if ($rules.Count -gt 0) {
                $rules | Remove-NetFirewallRule -Confirm:$false
                Write-Host "Puertos cerrados exitosamente." -ForegroundColor Green
                Add-LogEntry -Message "Puertos inseguros cerrados: RDP(3389), WinRM(5985, 5986)"
            } else {
                Write-Host "No se encontraron reglas de firewall inseguras para cerrar." -ForegroundColor Green
            }
        } catch {
            Write-Host "Error al cerrar los puertos." -ForegroundColor Red
        }
    }

    function Manage-RDP {
        $rdpStatus = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
        Write-Host "`nEstado actual del RDP (0=Habilitado, 1=Deshabilitado): $rdpStatus" -ForegroundColor Cyan
        Write-Host "1. Habilitar RDP"
        Write-Host "2. Deshabilitar RDP"
        Write-Host "0. Volver"
        $rdpOption = Read-Host "Seleccione una opción"
        try {
            switch ($rdpOption) {
                "1" { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0; Write-Host "RDP habilitado." -ForegroundColor Green; Add-LogEntry "RDP habilitado" }
                "2" { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1; Write-Host "RDP deshabilitado." -ForegroundColor Yellow; Add-LogEntry "RDP deshabilitado" }
            }
        } catch {
            Write-Host "Error al cambiar el estado del RDP." -ForegroundColor Red
        }
    }
    
    function Find-MaliciousScheduledTasks {
        Write-Host "`nBuscando tareas programadas con alto riesgo..." -ForegroundColor Yellow
        try {
            $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notlike "\Microsoft\Windows\*" -and $_.TaskPath -notlike "\Microsoft\Office\*" }
            $suspiciousTasks = @()
            foreach ($task in $tasks) {
                foreach ($action in $task.Actions) {
                    if ($action.Path -and ($action.Path.ToLower() -notmatch "c:\\windows") -and ($action.Path.ToLower() -notmatch "c:\\program files")) {
                        $suspiciousTasks += [PSCustomObject]@{TaskName=$task.TaskName; State=$task.State; Path=$task.TaskPath; ActionPath=$action.Path}
                        break 
                    }
                }
            }
            if ($suspiciousTasks.Count -gt 0) {
                Write-Host "Se encontraron tareas programadas sospechosas:" -ForegroundColor Red
                return $suspiciousTasks
            } else {
                Write-Host "No se encontraron tareas programadas sospechosas." -ForegroundColor Green
                return $null
            }
        } catch {
            Write-Host "Error al auditar tareas programadas." -ForegroundColor Red
            return $null
        }
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
            $scanResult = [PSCustomObject]@{ File = (Split-Path $FilePath -Leaf); Path = $FilePath; Hash = $fileHash; Detections = $detections; Total = $totalEngines; Status = "OK" }
            if ($detections -gt 0) {
                Write-Host "¡ALERTA! VirusTotal detectó este archivo como malicioso." -ForegroundColor Red
                $scanResult.Status = "Malicioso"
            } else {
                Write-Host "El archivo parece seguro según VirusTotal." -ForegroundColor Green
                $scanResult.Status = "Limpio"
            }
            Write-Host "Resultado: $detections / $totalEngines motores lo marcaron como malicioso."
            $global:VirusTotalScans.Add($scanResult)
        } catch {
            Write-Host "Ocurrió un error al contactar con VirusTotal. Verifica tu API Key o conexión." -ForegroundColor Red
            $global:VirusTotalScans.Add([PSCustomObject]@{ File = (Split-Path $FilePath -Leaf); Path = $FilePath; Hash = "N/A"; Detections = "N/A"; Total = "N/A"; Status = "Error" })
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
                    if ($ipAddress) { Write-Host "  - Direccion IP: $($ipAddress.IPAddress)" -ForegroundColor White } else { Write-Host "  - Direccion IP: No disponible" -ForegroundColor Red }
                    if ($gateway) { Write-Host "  - Puerta de Enlace: $($gateway.NextHop)" -ForegroundColor White } else { Write-Host "  - Puerta de Enlace: No disponible" -ForegroundColor Red }
                    if ($dns) { $dnsServers = $dns.ServerAddresses -join ", "; Write-Host "  - Servidores DNS: $($dnsServers)" -ForegroundColor White } else { Write-Host "  - Servidores DNS: No disponible" -ForegroundColor Red }
                }
            } else { Write-Host "No se encontraron adaptadores de red activos." -ForegroundColor Red }
        } catch { Write-Host "Error al obtener informacion de la red: $($_.Exception.Message)" -ForegroundColor Red }

        Write-Host "`n`nAnalizando conexiones de red en busca de actividad sospechosa..." -ForegroundColor Yellow
        $suspiciousPorts = @(31337, 21, 22, 23, 8080, 4444, 5900, 5901)
        try {
            $allConnections = Get-NetTCPConnection
            $suspiciousConnections = $allConnections | Where-Object { ($_.RemotePort -in $suspiciousPorts) -or ($_.State -eq "CloseWait") }
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
            } else { Write-Host "No se encontro actividad de red sospechosa." -ForegroundColor Green }
        } catch { Write-Host "Error al analizar las conexiones de red." -ForegroundColor Red }
    }
    
    function Generate-HTMLReport {
        if ($null -eq $global:InitialSystemState) {
            Write-Host "El estado inicial no ha sido capturado. Realizando análisis ahora..." -ForegroundColor Yellow
            Capture-InitialState
        }
        Add-LogEntry -Message "Generando reporte de seguridad en HTML."
        Write-Host "Generando reporte de seguridad..." -ForegroundColor Yellow
        $reportData = $global:InitialSystemState
        
        $htmlHead = @"
<head>
<meta charset="UTF-8">
<title>Reporte de Seguridad - MediTool</title>
<style>
    body { font-family: 'Segoe UI', sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }
    .container { max-width: 1200px; margin: auto; background: #fff; padding: 2em; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    h1, h2, h3 { color: #2a2a72; border-bottom: 2px solid #2a2a72; padding-bottom: 0.5em; }
    table { width: 100%; border-collapse: collapse; margin-top: 1em; }
    th, td { text-align: left; padding: 8px; border: 1px solid #ddd; word-break: break-all; }
    th { background-color: #4a4a8c; color: white; }
    .status-danger { color: #d9534f; font-weight: bold; }
    .status-warn { color: #f0ad4e; font-weight: bold; }
</style>
</head>
"@
        function ConvertTo-HtmlTable {
            param($Title, $Data)
            $html = "<h2>$Title</h2>"
            if ($Data -and ($Data | Measure-Object).Count -gt 0) {
                $html += $Data | ConvertTo-Html -Fragment
            } else {
                $html += "<p>No se encontraron elementos para esta categoría.</p>"
            }
            return $html
        }

        $body = "<body><div class='container'>"
        $body += "<h1>Reporte de Seguridad del Sistema</h1><p><strong>Fecha:</strong> $(Get-Date)</p>"
        $body += ConvertTo-HtmlTable "Tareas Programadas Sospechosas" $reportData.TareasProgramadasSospechosas
        
        $body += "<h2>Resultados de Análisis con VirusTotal</h2>"
        if ($global:VirusTotalScans.Count -gt 0) {
            $body += $global:VirusTotalScans | ConvertTo-Html -Fragment
        } else {
            $body += "<p>No se realizaron análisis con VirusTotal durante esta sesión.</p>"
        }
        
        $body += ConvertTo-HtmlTable "Registro de Acciones Realizadas" $global:ActionLog
        $body += "</div></body>"

        $reportPath = Join-Path -Path ([Environment]::GetFolderPath("Desktop")) -ChildPath "Security_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        try {
            ConvertTo-Html -Head $htmlHead -Body $body | Out-File -FilePath $reportPath -Encoding utf8
            Write-Host "Reporte generado con éxito en: $reportPath" -ForegroundColor Green
            Invoke-Item $reportPath
        } catch {
            Write-Host "Error al guardar el reporte: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    function Invoke-PeasHardeningChecks {
        Write-Host "`n--- Realizando Chequeos de Hardening contra Herramientas de Enumeración (PEAS) ---" -ForegroundColor Cyan
        Write-Host "`n[1] Buscando rutas de servicio sin comillas..." -ForegroundColor Yellow
        $unquotedServices = Get-CimInstance Win32_Service | Where-Object { $_.PathName -like '* *' -and $_.PathName -notlike '"*' }
        if ($unquotedServices) {
            Write-Host "[VULNERABLE] Se encontraron servicios con rutas sin comillas." -ForegroundColor Red; $unquotedServices | Format-Table Name, PathName -AutoSize
        } else { Write-Host "[OK] No se encontraron servicios con rutas vulnerables." -ForegroundColor Green }
        
        Write-Host "`n[2] Verificando la política 'AlwaysInstallElevated'..." -ForegroundColor Yellow
        $keyPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; $keyPath2 = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
        $value1 = Get-ItemPropertyValue -Path $keyPath1 -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        $value2 = Get-ItemPropertyValue -Path $keyPath2 -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        if ($value1 -eq 1 -and $value2 -eq 1) {
            Write-Host "[VULNERABLE] La política 'AlwaysInstallElevated' está activada." -ForegroundColor Red
            $fix = Read-Host "¿Desea deshabilitar esta política ahora? (S/N)"; if ($fix -eq 's') { Set-ItemProperty -Path $keyPath1 -Name "AlwaysInstallElevated" -Value 0; Set-ItemProperty -Path $keyPath2 -Name "AlwaysInstallElevated" -Value 0; Write-Host "[CORREGIDO] La política ha sido deshabilitada." -ForegroundColor Green; Add-LogEntry "Política 'AlwaysInstallElevated' deshabilitada." }
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
        Write-Host "`n[1] Verificando la Protección LSA (RunAsPPL)..." -ForegroundColor Yellow
        $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $lsaProtection = Get-ItemPropertyValue -Path $lsaKey -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if ($lsaProtection -eq 1) { Write-Host "[OK] La Protección LSA está HABILITADA." -ForegroundColor Green } 
        else { 
            Write-Host "[VULNERABLE] La Protección LSA está DESHABILITADA." -ForegroundColor Red
            $fix = Read-Host "¿Desea HABILITAR la Protección LSA ahora (requiere reiniciar)? (S/N)"
            if ($fix -eq 's') { 
                Set-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value 1 -Type DWord
                Write-Host "[CORREGIDO] Protección LSA habilitada. REINICIE el equipo para que el cambio surta efecto." -ForegroundColor Green
                Add-LogEntry "Protección LSA (RunAsPPL) habilitada."
            } 
        }
        
        Write-Host "`n[2] Verificando el proveedor de seguridad WDigest..." -ForegroundColor Yellow
        $wdigestKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        $useLogonCred = Get-ItemPropertyValue -Path $wdigestKey -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        if ($useLogonCred -eq 1) {
            Write-Host "[VULNERABLE] WDigest está configurado para almacenar credenciales en texto claro." -ForegroundColor Red
            $fix = Read-Host "¿Desea forzar la DESHABILITACIÓN de WDigest ahora? (S/N)"
            if ($fix -eq 's') { 
                if (-not (Test-Path $wdigestKey)) { New-Item -Path $wdigestKey -Force | Out-Null }
                Set-ItemProperty -Path $wdigestKey -Name "UseLogonCredential" -Value 0 -Type DWord
                Write-Host "[CORREGIDO] WDigest ha sido deshabilitado." -ForegroundColor Green
                Add-LogEntry "WDigest deshabilitado."
            } 
        } else { Write-Host "[OK] WDigest está correctamente configurado." -ForegroundColor Green }
        
        Write-Host "`n[3] Verificando el estado de Credential Guard..." -ForegroundColor Yellow
        try { 
            $cgStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
            if ($cgStatus -contains "Credential Guard") { Write-Host "[OK] Credential Guard está activo." -ForegroundColor Green } 
            else { Write-Host "[INFO] Credential Guard no está activo." -ForegroundColor Cyan } 
        } catch { Write-Host "[INFO] No se pudo determinar el estado de Credential Guard." -ForegroundColor Cyan }
        
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
        try { 
            $clearedLogs = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -ErrorAction Stop
            if ($clearedLogs) { 
                Write-Host "[ALERTA] ¡Se ha detectado que el registro de seguridad ha sido borrado!" -ForegroundColor Red
                $clearedLogs | Select-Object TimeCreated, Id, Message | Format-List 
            } else { 
                Write-Host "[OK] No se encontraron eventos de borrado del registro de seguridad." -ForegroundColor Green 
            } 
        } catch { Write-Host "[INFO] No se encontraron eventos de borrado o no se pudo acceder al log de seguridad." -ForegroundColor Cyan }
        Write-Host "`n--- Auditoría de Eventos Críticos finalizada ---" -ForegroundColor Cyan
    }
    
    function Invoke-LocalPolicyChecks {
        Write-Host "`n--- Verificando Políticas de Seguridad Locales Fundamentales ---" -ForegroundColor Cyan
        Write-Host "`n[1] Verificando estado de User Account Control (UAC)..." -ForegroundColor Yellow
        $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacEnabled = Get-ItemPropertyValue -Path $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue
        if ($uacEnabled -eq 1) { Write-Host "[OK] User Account Control (UAC) está HABILITADO." -ForegroundColor Green } 
        else { Write-Host "[VULNERABLE] User Account Control (UAC) está DESHABILITADO." -ForegroundColor Red }
        
        Write-Host "`n[2] Verificando estado de cifrado de disco (BitLocker)..." -ForegroundColor Yellow
        try { 
            $bitlockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            if ($bitlockerVolume.ProtectionStatus -eq 'On') { Write-Host "[OK] La unidad del sistema ($($env:SystemDrive)) está CIFRADA." -ForegroundColor Green } 
            else { Write-Host "[ADVERTENCIA] La unidad del sistema ($($env:SystemDrive)) NO está cifrada." -ForegroundColor Yellow } 
        } catch { Write-Host "[INFO] No se pudo determinar el estado de BitLocker." -ForegroundColor Cyan }
        
        Write-Host "`n[3] Mostrando política de contraseñas local..." -ForegroundColor Yellow
        $netAccounts = net accounts
        if ($netAccounts) { Write-Host "[INFO] La política de contraseñas configurada en este equipo es:" -ForegroundColor Cyan; $netAccounts } 
        else { Write-Host "[ERROR] No se pudo obtener la política de contraseñas." -ForegroundColor Red }
        
        Write-Host "`n--- Verificación de Políticas Locales finalizada ---" -ForegroundColor Cyan
    }

    function Capture-InitialState {
        Write-Host "Capturando estado del sistema para el reporte..." -ForegroundColor Cyan
        $global:InitialSystemState = [PSCustomObject]@{
            TareasProgramadasSospechosas  = Find-MaliciousScheduledTasks 
        }
    }

    function Activate-Windows {
        Write-Host "ADVERTENCIA: Va a ejecutar un script de activación NO OFICIAL de Internet." -ForegroundColor Red
        $confirm = Read-Host "Para continuar, presione 'S'. Para cancelar, presione cualquier otra tecla."
        if ($confirm -eq "S" -or $confirm -eq "s") {
            try {
                Invoke-Expression (Invoke-RestMethod https://get.activated.win)
            } catch {
                Write-Host "Error al ejecutar el comando de activación." -ForegroundColor Red
            }
        } else {
            Write-Host "Activación cancelada." -ForegroundColor Yellow
        }
    }
    
    # --- MENÚ PRINCIPAL ---
    function Show-MainMenu {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Green
        Write-Host "=         Herramienta de Auditoría MediTool         =" -ForegroundColor Green
        Write-Host "=============================================" -ForegroundColor Green
        Write-Host "Versión 5.1.0 (Definitiva) - por h00kGh0st & Programeta`n"
        
        $menuOptions = @(
            [PSCustomObject]@{ "ID" = 1; "Opcion" = "Revisar Estado de RDP y Conexiones" },
            [PSCustomObject]@{ "ID" = 2; "Opcion" = "Auditar Reglas de Firewall Inseguras" },
            [PSCustomObject]@{ "ID" = 3; "Opcion" = "Cerrar Puertos Inseguros (RDP/WinRM)" },
            [PSCustomObject]@{ "ID" = 4; "Opcion" = "Administrar el servicio de RDP" },
            [PSCustomObject]@{ "ID" = 6; "Opcion" = "Buscar Tareas Programadas Maliciosas" },
            [PSCustomObject]@{ "ID" = 9; "Opcion" = "Verificar Firmas y Analizar Archivos (VirusTotal)" },
            [PSCustomObject]@{ "ID" = 14; "Opcion" = "Analizar Conexiones de Red (Detallado)" },
            [PSCustomObject]@{ "ID" = 19; "Opcion" = "Generar Reporte de Seguridad (HTML)" },
            [PSCustomObject]@{ "ID" = 28; "Opcion" = "Realizar Chequeo Anti-PEAS (Hardening)" },
            [PSCustomObject]@{ "ID" = 29; "Opcion" = "Realizar Chequeo Anti-Robo-Credenciales (Hardening)" },
            [PSCustomObject]@{ "ID" = 30; "Opcion" = "Auditar Eventos Críticos (Borrado de Logs)" },
            [PSCustomObject]@{ "ID" = 31; "Opcion" = "Verificar Políticas de Seguridad Locales (UAC, BitLocker)" },
            [PSCustomObject]@{ "ID" = 88; "Opcion" = "Activar Windows (Advertencia de Seguridad)" },
            [PSCustomObject]@{ "ID" = 99; "Opcion" = "Mensaje del Creador" },
            [PSCustomObject]@{ "ID" = 0; "Opcion" = "Salir" }
        )
        
        $menuOptions | Format-Table -Property @{Expression="ID"; Width=4}, Opcion -HideTableHeaders | Out-String | Write-Host
        
        return Read-Host "Ingresa el numero de la opcion que deseas ejecutar"
    }

    # --- BUCLE PRINCIPAL ---
    Write-Host "El script se está ejecutando con permisos de Administrador." -ForegroundColor Green
    Capture-InitialState
    
    while ($true) {
        $selection = Show-MainMenu
        
        switch ($selection) {
            "1" { Get-RDPStatus }
            "2" { Get-FirewallStatus }
            "3" { Fix-FirewallPorts }
            "4" { Manage-RDP }
            "6" { Find-MaliciousScheduledTasks | Format-Table -AutoSize }
            "9" { Verify-FileSignatures }
            "14" { Analyze-NetworkConnections }
            "19" { Generate-HTMLReport }
            "28" { Invoke-PeasHardeningChecks }
            "29" { Invoke-CredentialHardeningChecks }
            "30" { Invoke-CriticalEventsAudit }
            "31" { Invoke-LocalPolicyChecks }
            "88" { Activate-Windows }
            "99" { Write-Host "Copyright (c) 2023 h00kGh0st & Programeta" -ForegroundColor Cyan }
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

        if ($selection -ne "0") {
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
    }
} # --- FIN DEL BLOQUE QUE REQUIERE PERMISOS DE ADMINISTRADOR ---
