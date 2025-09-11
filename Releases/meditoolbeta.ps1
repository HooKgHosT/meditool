# Este script está diseñado como una herramienta de seguridad (Blue Team)
# para la verificación y corrección de vulnerabilidades comunes en sistemas Windows 10 y 11.
# Script version 1.0.0

# --- Lógica de autodescarga, elevación de permisos y limpieza ---
# Este script esta disenado como una herramienta de seguridad (Blue Team)
$scriptName = "meditool.ps1"
$scriptUrl = "https://raw.githubusercontent.com/HooKgHosT/meditool/main/meditoolbeta.ps1"
$tempPath = Join-Path $env:TEMP $scriptName

function Test-AdminPrivileges {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Si el script no se esta ejecutando desde la ruta temporal y no tiene permisos de administrador, se descarga y se relanza.
if (($MyInvocation.MyCommand.Path -ne $tempPath) -and (-not (Test-AdminPrivileges))) {
    try {
        # 1. Comprobar y eliminar cualquier version anterior del script
        if (Test-Path -Path $tempPath) {
            Write-Host "Se encontro una version anterior del script. Eliminandola para asegurar una descarga limpia..." -ForegroundColor Yellow
            Remove-Item -Path $tempPath -Force -ErrorAction Stop
        }

        # 2. Descargar la version mas reciente
        Write-Host "Iniciando la descarga del script temporal..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
        Write-Host "Descargado en: $tempPath" -ForegroundColor Cyan
        
        # 3. Relanzar con privilegios elevados
        Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempPath`"" -Verb RunAs
        exit
    } catch {
        # 4. Manejo de errores robusto para la eliminacion o descarga
        Write-Host "Error durante la preparacion o descarga del script: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Asegurese de tener conexion a Internet y de que el enlace sea correcto." -ForegroundColor Red
        exit 1
    }
}

# Esta parte solo se ejecuta si el script se ha relanzado con permisos de administrador.
if (Test-AdminPrivileges) {
# Cambiar la codificación para que se muestren los caracteres especiales correctamente
$OutputEncoding = [System.Text.UTF8Encoding]::new()
# Configurar la política de ejecución para permitir la ejecución del script

# Variables globales
$global:ActionLog = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:InitialSystemState = $null
$global:FinalSystemState = $null # Nueva variable para el estado final
function Add-LogEntry {
    param([string]$Message)
    $logEntry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action    = $Message
    }
    $global:ActionLog.Add($logEntry)
}
function Clear-TempFolder {
    if (Test-Path $tempPath) { try { Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue } catch {} }
}

    Write-Host "El script se esta ejecutando con permisos de Administrador." -ForegroundColor Green
    
    # El resto del script se ejecuta aquí...

} else {
    Write-Host "El script no se esta ejecutando con permisos de Administrador. Se le solicita que se ejecute con permisos de Administrador." -ForegroundColor Red
    Write-Host "Asegurese de tener conexion a Internet y de que el enlace sea correcto." -ForegroundColor Red
    exit 1
}


# --- Funciones de seguridad ---
function Invoke-PeasHardeningChecks {
    Write-Host "`n--- Realizando Chequeos de Hardening contra Herramientas de Enumeracion (PEAS) ---" -ForegroundColor Cyan
    Write-Host "`n[1] Buscando rutas de servicio sin comillas..." -ForegroundColor Yellow
    $unquotedServices = Get-CimInstance Win32_Service | Where-Object { $_.PathName -like '* *' -and $_.PathName -notlike '"*' }
    if ($unquotedServices) {
        Write-Host "[VULNERABLE] Se encontraron servicios con rutas sin comillas. Esto puede permitir escalada de privilegios:" -ForegroundColor Red
        $unquotedServices | Format-Table Name, PathName -AutoSize
    } else { Write-Host "[OK] No se encontraron servicios con rutas vulnerables." -ForegroundColor Green }
    Write-Host "`n[2] Verificando la politica 'AlwaysInstallElevated'..." -ForegroundColor Yellow
    $keyPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; $keyPath2 = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
    $value1 = Get-ItemPropertyValue -Path $keyPath1 -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $value2 = Get-ItemPropertyValue -Path $keyPath2 -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    if ($value1 -eq 1 -and $value2 -eq 1) {
        Write-Host "[VULNERABLE] La politica 'AlwaysInstallElevated' esta activada." -ForegroundColor Red
        $fix = Read-Host "¿Desea deshabilitar esta politica ahora? (S/N)"; if ($fix -eq 's') { Set-ItemProperty -Path $keyPath1 -Name "AlwaysInstallElevated" -Value 0; Set-ItemProperty -Path $keyPath2 -Name "AlwaysInstallElevated" -Value 0; Write-Host "[CORREGIDO] La politica ha sido deshabilitada." -ForegroundColor Green; Add-LogEntry -Message "Politica 'AlwaysInstallElevated' deshabilitada." }
    } else { Write-Host "[OK] La politica 'AlwaysInstallElevated' no esta activada." -ForegroundColor Green }
    Write-Host "`n[3] Listando credenciales guardadas por el sistema (cmdkey)..." -ForegroundColor Yellow # This line is duplicated in the context file.
    $credList = cmdkey /list
    if ($credList -match "Currently stored credentials") { Write-Host "[INFO] Se encontraron las siguientes credenciales guardadas. Revise si son necesarias:" -ForegroundColor Cyan; $credList } 
    else { Write-Host "[OK] No se encontraron credenciales guardadas con cmdkey." -ForegroundColor Green }
    Write-Host "`n[4] Verificando si el motor de PowerShell v2 esta habilitado..." -ForegroundColor Yellow
    $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
    if ($psv2Feature.State -eq 'Enabled') { Write-Host "[ADVERTENCIA] El motor de PowerShell v2 esta HABILITADO. Se recomienda deshabilitarlo." -ForegroundColor Yellow } 
    else { Write-Host "[OK] El motor de PowerShell v2 esta deshabilitado." -ForegroundColor Green }
    Write-Host "`n--- Chequeo de Hardening finalizado ---" -ForegroundColor Cyan
}
function Invoke-CriticalEventsAudit {
    Write-Host "`n--- Realizando Auditoria de Eventos de Seguridad Criticos ---" -ForegroundColor Cyan
    Write-Host "`n[1] Buscando intentos de borrado de huellas (Log de Seguridad)..." -ForegroundColor Yellow
    try { $clearedLogs = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -ErrorAction Stop; if ($clearedLogs) { Write-Host "[ALERTA] Se ha detectado que el registro de seguridad ha sido borrado!" -ForegroundColor Red; $clearedLogs | Select-Object TimeCreated, Id, Message | Format-List } else { Write-Host "[OK] No se encontraron eventos de borrado del registro de seguridad." -ForegroundColor Green } } catch { Write-Host "[INFO] No se encontraron eventos de borrado o no se pudo acceder al log de seguridad." -ForegroundColor Cyan }
    Write-Host "`n--- Auditoria de Eventos Criticos finalizada ---" -ForegroundColor Cyan
}
function Invoke-LocalPolicyChecks {
    Write-Host "`n--- Verificando Politicas de Seguridad Locales Fundamentales ---" -ForegroundColor Cyan
    Write-Host "`n[1] Verificando estado de User Account Control (UAC)..." -ForegroundColor Yellow
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacEnabled = Get-ItemPropertyValue -Path $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uacEnabled -eq 1) { Write-Host "[OK] User Account Control (UAC) esta HABILITADO." -ForegroundColor Green } else { Write-Host "[VULNERABLE] User Account Control (UAC) esta DESHABILITADO." -ForegroundColor Red }
    Write-Host "`n[2] Verificando estado de cifrado de disco (BitLocker)..." -ForegroundColor Yellow
    try { $bitlockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; if ($bitlockerVolume.ProtectionStatus -eq 'On') { Write-Host "[OK] La unidad del sistema ($($env:SystemDrive)) esta CIFRADA." -ForegroundColor Green } else { Write-Host "[ADVERTENCIA] La unidad del sistema ($($env:SystemDrive)) NO esta cifrada." -ForegroundColor Yellow } } catch { Write-Host "[INFO] No se pudo determinar el estado de BitLocker." -ForegroundColor Cyan }
    Write-Host "`n[3] Mostrando politica de contrasenas local..." -ForegroundColor Yellow
    $netAccounts = net accounts
    if ($netAccounts) { Write-Host "[INFO] La politica de contrasenas configurada en este equipo es:" -ForegroundColor Cyan; $netAccounts } else { Write-Host "[ERROR] No se pudo obtener la politica de contrasenas." -ForegroundColor Red }
    Write-Host "`n--- Verificacion de Politicas Locales finalizada ---" -ForegroundColor Cyan
}
function Get-SafeAuthenticodeSignature {
    param(
        [string]$Path
    )
    
    # Validar si el archivo existe antes de intentar obtener la firma
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [PSCustomObject]@{ Status = "NotFound" }
    }
    
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return $signature
    } catch {
        # Devolver "Unknown" si ocurre un error al obtener la firma
        return [PSCustomObject]@{ Status = "Unknown" }
    }
}
function Get-RDPStatus {
    $service = Get-Service -Name TermService -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            return "El servicio de RDP se esta ejecutando."
        } else {
            return "El servicio de RDP esta detenido."
        }
    } else {
        return "El servicio de RDP no esta instalado."
    }
}
function Get-LastIncomingRDPLogon {
    try {
        $rdpEvent = Get-WinEvent -FilterHashtable @{Logname='Security'; Id=4624; Data='3389'} -MaxEvents 1 -ErrorAction Stop
        if ($rdpEvent) {
            $props = @{
                "Fecha" = $rdpEvent.TimeCreated
                "Usuario" = $rdpEvent.Properties[5].Value
                "Origen" = $rdpEvent.Properties[18].Value
            }
            return [PSCustomObject]$props
        } else {
            return $null
        }
    } catch {
        return $null
    }
}
function Get-LastOutgoingRDPConnection {
    try {
        $rdpEventOut = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-TerminalServices-Client/Operational'; Id=1024} -MaxEvents 1 -ErrorAction Stop
        if ($rdpEventOut) {
            $props = @{
                "Host" = $rdpEventOut.Properties[1].Value
                "Fecha" = $rdpEventOut.TimeCreated
            }
            return [PSCustomObject]$props
        } else {
            return $null
        }
    } catch {
        return $null
    }
}
function Set-RDP {
    Write-Host "`n Estado actual del RDP: $((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections)"
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
            Write-Host "Opcion no valida." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al cambiar el estado del RDP. Asegurese de tener permisos de Administrador." -ForegroundColor Red
    }
}
function Get-TelemetryStatus {
    try {
        $regValue = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue
        
        if ($null -eq $regValue) {
            return "No configurada/Deshabilitada"
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
        Write-Host "`nEstado actual de la telemetria de Windows: $regValue"
    } catch {
        Write-Host "`nEstado actual de la telemetria de Windows: No configurada"
    }
    
    Write-Host ""
    Write-Host "1. Habilitar Telemetria"
    Write-Host "2. Deshabilitar Telemetria"
    Write-Host "0. Volver al menu principal"
    $telemetryOption = Read-Host "`nSeleccione una opcion"
    
    try {
        if (-not (Test-Path -Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        if ($telemetryOption -eq "1") {
            Set-ItemProperty -Path $regPath -Name $regProperty -Value 1 -Type DWORD -Force
            Write-Host "`nTelemetria habilitada." -ForegroundColor Green
        } elseif ($telemetryOption -eq "2") {
            Set-ItemProperty -Path $regPath -Name $regProperty -Value 0 -Type DWORD -Force
            Write-Host "`nTelemetria deshabilitada." -ForegroundColor Yellow
        } elseif ($telemetryOption -eq "0") {
            # Volver al menu principal.
        } else {
            Write-Host "Opcion no valida." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al cambiar el estado de la telemetria. Asegurese de tener permisos de Administrador." -ForegroundColor Red
    }
}
function Find-MaliciousScheduledTasks {
    Write-Host "`nBuscando tareas programadas con alto riesgo..." -ForegroundColor Yellow
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notlike "\Microsoft\Windows\*" -and $_.TaskPath -notlike "\Microsoft\Office\*" }
        $suspiciousTasks = @()
        foreach ($task in $tasks) {
            $action = $task.Actions[0]
            if ($action -and $action.Path -and ($action.Path.ToLower() -notmatch "c:\\windows" -and $action.Path.ToLower() -notmatch "c:\\program files")) {
                $suspiciousTasks += $task
            }
        }
        return $suspiciousTasks | Select-Object TaskName, State, TaskPath, @{Name="ActionPath";Expression={$_.Actions.Path}}
    } catch {
        Write-Host "Error al auditar tareas programadas. Asegurese de tener permisos de Administrador." -ForegroundColor Red
        return $null
    }
}
function Audit-NonEssentialServices {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    function StopAndDisable-ServiceSafe {
        param(
            [Parameter(Mandatory = $true)]
            [System.ServiceProcess.ServiceController]$Service
        )
        
        if ($PSCmdlet.ShouldProcess($Service.Name, "Detener y Deshabilitar Servicio")) {
            try {
                Stop-Service -InputObject $Service -Force -ErrorAction Stop
                Write-Host " - Servicio '$($Service.Name)' detenido." -ForegroundColor Green
            } catch {
                Write-Error "No se pudo detener el servicio '$($Service.Name)'."
            }
            try {
                Set-Service -InputObject $Service -StartupType Disabled -ErrorAction Stop
                Write-Host " - Servicio '$($Service.Name)' deshabilitado." -ForegroundColor Green
            } catch {
                Write-Error "No se pudo deshabilitar el servicio '$($Service.Name)'."
            }
        }
    }

    Write-Host "`nAuditoria de servicios no esenciales en ejecucion..." -ForegroundColor Yellow
    
    $nonEssentialServices = @(
        "Fax", "HomeGroupProvider", "Spooler", "Themes", "WSearch", 
        "DiagTrack", "CDPSvc", "PcaSvc", "RemoteRegistry", "SensorService"
    )

    $runningServices = Get-Service -Name $nonEssentialServices -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }

    if (-not $runningServices) {
        Write-Host "[OK] No se encontraron servicios no esenciales en ejecucion." -ForegroundColor Green
        return
    }

    Write-Host "[AVISO] Se encontraron los siguientes servicios no esenciales en ejecucion:" -ForegroundColor Red
    $i = 1
    $runningServices | ForEach-Object {
        Write-Host (" [{0}] {1,-20} {2}" -f $i, $_.Name, $_.DisplayName)
        $i++
    }

    Write-Host "`nOpciones de correccion:" -ForegroundColor Cyan
    Write-Host " [D] Detener y Deshabilitar TODOS los servicios de la lista"
    Write-Host " [Numero] Detener y Deshabilitar un servicio especifico (ej: 1, 2)"
    Write-Host " [N] No hacer nada (Omitir)"
    $choice = Read-Host "Selecciona una opcion"

    switch -Regex ($choice) {
        '^[dD]$' {
            Write-Host "`nIntentando detener y deshabilitar todos los servicios encontrados..." -ForegroundColor Yellow
            foreach ($service in $runningServices) {
                StopAndDisable-ServiceSafe -Service $service
            }
        }
        '^\d+$' {
            if ([int]$choice -ge 1 -and [int]$choice -le $runningServices.Count) {
                $serviceToManage = $runningServices[[int]$choice - 1]
                Write-Host "`nGestionando servicio: $($serviceToManage.Name)..." -ForegroundColor Yellow
                StopAndDisable-ServiceSafe -Service $serviceToManage
            } else {
                Write-Warning "El numero '$choice' no esta en la lista."
            }
        }
        '^[nN]$' {
            Write-Host "No se realizaran cambios." -ForegroundColor Gray
        }
        default {
            Write-Warning "Opcion no valida."
        }
    }
}
function Find-InactiveUsers {
    Write-Host "`nBuscando usuarios inactivos..." -ForegroundColor Yellow
    
    $daysInactive = 90
    
    if (-not (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue)) {
        Write-Host "Error: El cmdlet 'Get-LocalUser' no se encontro. Esta funcion solo es compatible con Windows 10/11 y Windows Server 2016 o superior." -ForegroundColor Red
        return $null
    }

    try {
        $inactiveUsers = Get-LocalUser -ErrorAction Stop | Where-Object { 
            $_.LastLogon -and ($_.LastLogon -lt (Get-Date).AddDays(-$daysInactive)) 
        }
        
        if ($inactiveUsers) {
            Write-Host "Se encontraron los siguientes usuarios inactivos por mas de $daysInactive dias:" -ForegroundColor Red
            return $inactiveUsers | Select-Object Name, LastLogon, Enabled
        } else {
            Write-Host "No se encontraron usuarios inactivos por mas de $daysInactive dias." -ForegroundColor Green
            return $null
        }
    } catch {
        Write-Host "Error al buscar usuarios inactivos. Asegurese de tener permisos de Administrador y de que el sistema no este en un entorno de dominio complejo." -ForegroundColor Red
        return $null
    }
}
function Verify-FileSignatures {
    Write-Host "Verificando firmas de archivos en rutas criticas... (Esto puede tardar unos minutos)" -ForegroundColor Yellow
    
    # Lista de rutas y programas que se consideran de confianza y se excluyen.
    $excludedPaths = @(
        "C:\Program Files\7-Zip*",
        "C:\Program Files\AMD*",
        "C:\Program Files\Autopsy*",
        "C:\Program Files\Cisco Packet Tracer*",
        "C:\Program Files\DigiDNA*",
        "C:\Program Files\obs-studio*",
        "C:\Program Files\Oracle*",
        "C:\Program Files\Raspberry Pi Imager*",
        "C:\Program Files\Samsung*",
        "C:\Program Files\VideoLAN*",
        "C:\WINDOWS\System32\config\systemprofile\AppData*",
        "C:\WINDOWS\System32\DriverStore\Temp*"
    )
    
    $criticalPaths = @("$env:SystemRoot\System32", "$env:ProgramFiles", "$env:ProgramFiles(x86)")
    $unsignedFiles = @()

    foreach ($path in $criticalPaths) {
        Write-Host "  - Analizando ruta: $path" -ForegroundColor Gray
        try {
            $files = Get-ChildItem -Path $path -Recurse -File -Include "*.exe", "*.dll" -ErrorAction SilentlyContinue | Where-Object {
                $isExcluded = $false
                foreach ($excluded in $excludedPaths) {
                    if ($_.FullName -like $excluded) {
                        $isExcluded = $true
                        break
                    }
                }
                -not $isExcluded
            }
            
            foreach ($file in $files) {
                $signature = Get-SafeAuthenticodeSignature -Path $file.FullName
                if ($signature.Status -ne "Valid") {
                    $unsignedFiles += $file
                }
            }
        } catch { }
    }
    
    Write-Host "Verificacion de firmas de archivos completada." -ForegroundColor Green
    
    if ($unsignedFiles.Count -gt 0) {
        Write-Host "Se encontraron archivos sin firma digital o con firma invalida:" -ForegroundColor Red
        $unsignedFiles | Select-Object @{Name="Nombre"; Expression={$_.Name}},
                                     @{Name="Directorio"; Expression={
                                         $dir = $_.DirectoryName
                                         if ($dir.Length -gt 60) {
                                             "..." + $dir.Substring($dir.Length - 57)
                                         } else {
                                             $dir
                                         }
                                     }},
                                     @{Name="Ultima Modificacion"; Expression={$_.LastWriteTime}} | Format-Table -AutoSize

        # --- Nuevo Menu para el Usuario ---
        Write-Host "`n¿Que desea hacer a continuacion?" -ForegroundColor Cyan
        Write-Host "1. Detener un proceso sin firma"
        Write-Host "0. Volver al menu principal"
        
        $option = Read-Host "Seleccione una opcion"
        
        switch ($option) {
            "1" {
                Stop-SuspiciousProcess
            }
            "0" {
                # Volver al menu principal, no se requiere codigo extra aqui.
            }
            default {
                Write-Host "Opcion no valida. Volviendo al menu principal." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No se encontraron archivos sospechosos en las rutas criticas." -ForegroundColor Green
    }
}
function Find-UnsignedProcesses {
    Write-Host "`nBuscando procesos en ejecucion sin firma digital... (Esto puede tardar unos segundos)" -ForegroundColor Yellow
    
    $excludedProcesses = @(
        "steam.exe", "steamwebhelper.exe", "Discord.exe", 
        "RiotClientServices.exe", "RiotClient.exe", "RiotVanguard.exe", "LeagueClient.exe", 
        "EpicGamesLauncher.exe", "UnrealEngine.exe", "zoom.exe",
        "chrome.exe", "firefox.exe", "msedge.exe"
    )

    $unsignedProcesses = @()
    $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -notin $excludedProcesses }

    foreach ($process in $processes) {
        try {
            if ($process.Path) {
                $signature = Get-SafeAuthenticodeSignature -Path $process.Path
                if ($signature.Status -ne "Valid") {
                    $unsignedProcesses += $process
                }
            }
        } catch { }
    }
    Write-Host "`nBusqueda de procesos sin firma completada." -ForegroundColor Green
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
    
    Write-Host "`nIngrese el PID del proceso que desea detener o presione '0' para volver al menu principal:" -ForegroundColor Cyan
    $pidToStop = Read-Host "PID del proceso"
    
    if ($pidToStop -eq "0") {
        Write-Host "Operacion cancelada." -ForegroundColor Yellow
        return
    }
    
    try {
        Stop-Process -Id $pidToStop -Force -ErrorAction Stop
        Write-Host "Proceso con PID $pidToStop detenido exitosamente." -ForegroundColor Green
    } catch {
        Write-Host "No se pudo detener el proceso. Verifique el PID y los permisos de Administrador." -ForegroundColor Red
    }
}
function Block-FileExecution {
    param(
        [string]$FileToBlock
    )
    
    # Si la ruta no se proporciona como parametro, la solicitamos al usuario.
    if (-not $FileToBlock) {
        Write-Host "Ingrese la ruta del archivo que desea bloquear (ej. C:\malware.exe):" -ForegroundColor Cyan
        $FileToBlock = Read-Host "Ruta del archivo"
    }

    # Nueva validacion para verificar si el usuario no ingreso nada.
    if ([string]::IsNullOrEmpty($FileToBlock)) {
        Write-Host "Error: No se ha proporcionado una ruta de archivo. Volviendo al menu principal." -ForegroundColor Red
        return
    }
    
    if (-not (Test-Path $FileToBlock)) {
        Write-Host "Error: El archivo no existe." -ForegroundColor Red
        return
    }
    try {
        $ruleName = "BlockExecution_$(Get-Random)"
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $FileToBlock -Action Block
        Write-Host "Regla de Firewall '$ruleName' creada para bloquear la ejecucion de '$FileToBlock'." -ForegroundColor Green
    } catch {
        Write-Host "Error al crear la regla de Firewall. Asegurese de tener permisos de Administrador." -ForegroundColor Red
        Write-Host "Detalles del error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
function Find-RegistryAutorun {
    Write-Host "Buscando entradas de inicio automatico sospechosas..." -ForegroundColor Yellow
    $autorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $suspiciousEntries = @()

    # Lista de programas comunes a excluir.
    $excludedPrograms = @(
        "discord", "spotify", "riotgames", "steam", "epicgames", "zoom", "microsoft", "google", "brave", "opera", "teams"
    )

    foreach ($path in $autorunPaths) {
        try {
            $keys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($keys) {
                $keys.PSObject.Properties | ForEach-Object {
                    $prop = $_
                    if ($prop.Name -notin @("PSPath", "PSDrive", "PSProvider", "PSParentPath", "PSChildName")) {
                        $propValue = $prop.Value.ToLower()
                        
                        # Usa una logica de exclusion mas robusta
                        $isSystemOrCommonPath = $propValue.StartsWith("c:\windows") -or
                                                 $propValue.StartsWith("c:\program files") -or
                                                 $propValue.StartsWith("c:\program files (x86)") -or
                                                 $propValue.StartsWith("c:\programdata")

                        $isExcluded = $false
                        foreach ($excluded in $excludedPrograms) {
                            if ($propValue -like "*$($excluded)*") {
                                $isExcluded = $true
                                break
                            }
                        }

                        if (-not $isSystemOrCommonPath -and -not $isExcluded) {
                            $suspiciousEntries += [PSCustomObject]@{
                                "Clave" = $prop.Name
                                "Ruta" = $prop.Value
                                "Ubicacion" = $path
                            }
                        }
                    }
                }
            }
        } catch { }
    }
    
    if ($suspiciousEntries.Count -gt 0) {
        Write-Host "Se encontraron las siguientes entradas de Autorun sospechosas:" -ForegroundColor Red
        $suspiciousEntries | Format-Table -AutoSize
        
        Write-Host "`n¿Que desea hacer a continuacion?" -ForegroundColor Cyan
        Write-Host "1. Eliminar una entrada de la lista de Autorun"
        Write-Host "0. Volver al menu principal"
        
        $option = Read-Host "Seleccione una opcion"
        
        switch ($option) {
            "1" {
                Write-Host "Ingrese el nombre de la Clave que desea eliminar (de la columna 'Clave'):" -ForegroundColor Cyan
                $keyToBlock = Read-Host "Nombre de la Clave"
                
                $entryToBlock = $suspiciousEntries | Where-Object { $_.Clave -eq $keyToBlock } | Select-Object -First 1
                
                if ($entryToBlock) {
                    try {
                        Write-Host "Eliminando la clave del registro..." -ForegroundColor Yellow
                        Remove-ItemProperty -Path $entryToBlock.Ubicacion -Name $entryToBlock.Clave -Force -ErrorAction Stop
                        Write-Host "Clave del registro eliminada exitosamente." -ForegroundColor Green
                    } catch {
                        Write-Host "Error al eliminar la clave. Asegurese de tener permisos de Administrador." -ForegroundColor Red
                    }
                } else {
                    Write-Host "No se encontro la clave especificada." -ForegroundColor Red
                }
            }
            "0" {
                # Volver al menu principal.
            }
            default {
                Write-Host "Opcion no valida." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No se encontraron entradas de inicio automatico sospechosas." -ForegroundColor Green
    }
}
function Test-NetworkConnections {
    [CmdletBinding()]
    param (
        [switch]$ResolveHostName
    )

    Write-Host "`n PHASE 1: Analizando la configuración de red local..." -ForegroundColor Cyan
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        if ($adapters) {
            foreach ($adapter in $adapters) {
                Write-Host "`n--- Adaptador: $($adapter.Name) ($($adapter.InterfaceDescription)) ---" -ForegroundColor White
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                
                if ($ipConfig) {
                    Write-Host "  - Estado Operacional: $($adapter.Status)" -ForegroundColor Green
                    Write-Host "  - Dirección MAC: $($adapter.MacAddress)"
                    Write-Host "  - Dirección IPv4: $($ipConfig.IPv4Address.IPAddress)"
                    Write-Host "  - Puerta de Enlace: $($ipConfig.IPv4DefaultGateway.NextHop)"
                    Write-Host "  - Servidores DNS: $($ipConfig.DNSServer.ServerAddresses -join ', ')"
                } else {
                    Write-Host "  - No se pudo obtener la configuración IP para este adaptador." -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "No se encontraron adaptadores de red físicos activos." -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Ocurrió un error al obtener la información de los adaptadores de red: $($_.Exception.Message)"
    }

    Write-Host "`n PHASE 2: Analizando conexiones de red en busca de actividad sospechosa..." -ForegroundColor Cyan

    $excludedProcesses = @("chrome", "firefox", "msedge", "steam", "steamwebhelper", "Discord", "RiotClientServices", "LeagueClient", "EpicGamesLauncher", "zoom", "Teams")
    $suspiciousPorts = @(21, 22, 23, 4444, 5900, 5901, 8080, 31337)

    try {
        $processesById = Get-Process -ErrorAction Stop | Group-Object -Property Id -AsHashTable -AsString
        $unsignedProcesses = Find-UnsignedProcesses
        
        $allConnections = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -ne 'Listen' }

        $suspiciousConnections = foreach ($conn in $allConnections) {
            $processInfo = $processesById[$conn.OwningProcess]
            $processName = $processInfo.Name
            
            if ($processName -notin $excludedProcesses) {
                
                $isSuspicious = $false
                $reason = ""

                if ($conn.RemotePort -in $suspiciousPorts) {
                    $isSuspicious = $true
                    $reason += "Puerto Remoto Sospechoso ($($conn.RemotePort)); "
                }

                if ($conn.State -eq "CloseWait") {
                    $isSuspicious = $true
                    $reason += "Estado Anómalo (CloseWait); "
                }
                
                if ($unsignedProcesses.Id -contains $conn.OwningProcess) {
                    $isSuspicious = $true
                    $reason += "Proceso sin Firma Digital; "
                }

                if ($isSuspicious) {
                    $props = @{
                        PID = $conn.OwningProcess
                        Proceso = $processName
                        DireccionLocal = "$($conn.LocalAddress):$($conn.LocalPort)"
                        DireccionRemota = "$($conn.RemoteAddress):$($conn.RemotePort)"
                        HostRemoto = "Resolviendo..."
                        Estado = $conn.State
                        Motivo = $reason.TrimEnd("; ")
                        RutaEjecutable = $processInfo.Path
                    }
                    
                    if ($ResolveHostName) {
                        try {
                            $dnsResult = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
                            $props.HostRemoto = $dnsResult
                        } catch {
                            $props.HostRemoto = "No Resolvido"
                        }
                    } else {
                        $props.HostRemoto = "No Intentado"
                    }
                    
                    New-Object -TypeName PSObject -Property $props
                }
            }
        }

        if ($suspiciousConnections) {
            Write-Host "`n[ALERTA] Se encontraron las siguientes conexiones potencialmente sospechosas:" -ForegroundColor Red
            $suspiciousConnections | Format-Table PID, Proceso, DireccionRemota, HostRemoto, Estado, Motivo -AutoSize
            
            while ($true) {
                Write-Host "`n¿Desea tomar acción sobre alguno de estos procesos? (S/N)" -ForegroundColor Yellow
                $choice = Read-Host
                if ($choice -ne 's') { break }

                $pidToClose = Read-Host "Por favor, ingrese el PID del proceso a cerrar (o '0' para cancelar)"
                if ($pidToClose -eq '0') { continue }
                
                $targetProcess = $suspiciousConnections | Where-Object { $_.PID -eq $pidToClose } | Select-Object -First 1
                if ($targetProcess) {
                    try {
                        Write-Host "Deteniendo el proceso '$($targetProcess.Proceso)' (PID: $($targetProcess.PID))..." -ForegroundColor Yellow
                        Stop-Process -Id $targetProcess.PID -Force -ErrorAction Stop
                        Write-Host "¡Proceso detenido exitosamente!" -ForegroundColor Green

                        if ($targetProcess.RutaEjecutable -and (Test-Path $targetProcess.RutaEjecutable)) {
                            if ((Read-Host "¿Desea bloquear la ejecución futura de '$($targetProcess.RutaEjecutable)'? (S/N)") -eq 's') {
                                Block-FileExecution -FileToBlock $targetProcess.RutaEjecutable
                            }
                            if ((Read-Host "¿Desea analizar el archivo con VirusTotal? (S/N)") -eq 's') {
                                Get-VirusTotalReport -FilePath $targetProcess.RutaEjecutable
                            }
                        }
                        
                        Write-Host "El proceso ha sido gestionado. Se recomienda un nuevo análisis de red." -ForegroundColor Cyan
                        break

                    } catch {
                        Write-Warning "No se pudo detener el proceso con PID $pidToClose. Error: $($_.Exception.Message)"
                    }
                } else {
                    Write-Warning "El PID '$pidToClose' no corresponde a una conexión sospechosa de la lista."
                }
            }

        } else {
            Write-Host "[OK] No se encontró actividad de red sospechosa según los criterios definidos." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Ocurrió un error general durante el análisis de conexiones: $($_.Exception.Message)"
    }
}
function Invoke-WinPEAS {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Host "`n--- Ejecutando WinPEAS para buscar vectores de escalada de privilegios ---" -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess("el sistema para buscar debilidades de configuracion", "Ejecutar WinPEAS")) {
        try {
            # Forzar el uso de TLS 1.2 para compatibilidad con GitHub
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $architecture = $env:PROCESSOR_ARCHITECTURE
            $winpeasUrl = ""
            if ($architecture -eq 'AMD64') {
                $winpeasUrl = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
                Write-Host "Detectada arquitectura de 64 bits. Descargando winPEASx64.exe..." -ForegroundColor Yellow
            } else {
                $winpeasUrl = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe"
                Write-Host "Detectada arquitectura de 32 bits. Descargando winPEASx86.exe..." -ForegroundColor Yellow
            }

            $tempFile = New-TemporaryFile
            Invoke-WebRequest -Uri $winpeasUrl -OutFile $tempFile.FullName -UseBasicParsing -ErrorAction Stop
            Write-Host "Ejecutando winPEAS... (los resultados se mostraran a continuacion)" -ForegroundColor Green
            Start-Process -FilePath $tempFile.FullName -Wait
            Remove-Item -Path $tempFile.FullName -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Error "Ocurrio un error al descargar o ejecutar WinPEAS. Verifica tu conexion a internet."
            Write-Error "Detalles: $($_.Exception.Message)"
        }
    }
}
function Invoke-FirewallAudit {
    [CmdletBinding()]
    param()

    Write-Host "`n--- Auditoría de Conexiones de Red Activas (netstat) ---" -ForegroundColor Cyan
    Write-Host "Obteniendo conexiones activas... Esto puede tardar un momento."

    try {
        $netstatOutput = netstat -ban
        $connections = [System.Collections.Generic.List[PSObject]]::new()
        $currentProcess = ""

        foreach ($line in ($netstatOutput | Where-Object { $_ -match '\S' })) {
            if ($line -match '\[(.+?)\]') { # Captura el nombre del ejecutable, ej: [svchost.exe]
                $currentProcess = $matches[1].Trim()
            }
            elseif ($line.Trim() -match '^(TCP|UDP)\s+([\d\.:\*]+)\s+([\d\.:\*]+)\s+(\w+)\s+(\d+)') { # Captura la linea de conexion
                $connections.Add([PSCustomObject]@{
                    Protocolo = $matches[1]
                    DirLocal  = $matches[2]
                    DirRemota = $matches[3]
                    Estado    = $matches[4]
                    PID       = $matches[5]
                    Proceso   = $currentProcess
                })
            }
        }

        if ($connections.Count -eq 0) {
            Write-Host "[OK] No se encontraron conexiones activas o no se pudo parsear la salida de netstat." -ForegroundColor Green
            return
        }

        Write-Host "Se han encontrado $($connections.Count) conexiones activas." -ForegroundColor Yellow
        $connections | Format-Table -AutoSize

        while ($true) {
            $pidToAction = Read-Host "`n? Ingrese el PID de un proceso para gestionarlo (o '0' para volver al menú)"
            if ($pidToAction -eq '0') { break }

            $targetProcessInfo = $connections | Where-Object { $_.PID -eq $pidToAction } | Select-Object -First 1
            if (-not $targetProcessInfo) {
                Write-Warning "El PID '$pidToAction' no se encuentra en la lista."
                continue
            }

            try {
                $process = Get-Process -Id $pidToAction -ErrorAction Stop
                Write-Host "`n--- Gestionando Proceso: $($process.Name) (PID: $($process.Id)) ---" -ForegroundColor Cyan
                Write-Host "  Ruta: $($process.Path)"
                Write-Host "  1. Terminar Proceso"
                Write-Host "  2. Bloquear con Firewall (Saliente)"
                Write-Host "  3. Analizar con VirusTotal"
                Write-Host "  4. Eliminar Archivo Ejecutable (¡PELIGRO!)"
                Write-Host "  0. Seleccionar otro proceso"

                $actionChoice = Read-Host "? Qué acción desea realizar?"

                switch ($actionChoice) {
                    '1' {
                        Write-Host "Terminando proceso..." -ForegroundColor Yellow
                        Stop-Process -Id $process.Id -Force
                        Write-Host "[OK] Proceso terminado." -ForegroundColor Green
                    }
                    '2' {
                        if ($process.Path) {
                            Write-Host "Bloqueando ejecutable con el firewall..." -ForegroundColor Yellow
                            Block-FileExecution -FileToBlock $process.Path
                        } else {
                            Write-Warning "No se puede bloquear porque no se encontró la ruta del ejecutable."
                        }
                    }
                    '3' {
                        if ($process.Path) {
                            Get-VirusTotalReport -FilePath $process.Path
                        } else {
                            Write-Warning "No se puede analizar porque no se encontró la ruta del ejecutable."
                        }
                    }
                    '4' {
                        if ($process.Path) {
                            $confirmDelete = Read-Host "¿ESTÁ SEGURO de que desea eliminar '$($process.Path)'? Esta acción es irreversible. (S/N)"
                            if ($confirmDelete -eq 's') {
                                Write-Host "Primero se detendrá el proceso..." -ForegroundColor Yellow
                                Stop-Process -Id $process.Id -Force
                                Start-Sleep -Seconds 1
                                Write-Host "Eliminando archivo..." -ForegroundColor Red
                                Remove-Item -Path $process.Path -Force
                                Write-Host "[OK] Archivo eliminado." -ForegroundColor Green
                            } else {
                                Write-Host "Eliminación cancelada." -ForegroundColor Yellow
                            }
                        } else {
                            Write-Warning "No se puede eliminar porque no se encontró la ruta del ejecutable."
                        }
                    }
                    '0' { continue }
                    default { Write-Warning "Opción no válida." }
                }

            } catch {
                Write-Error "No se pudo obtener información del proceso con PID $pidToAction. Puede que ya se haya cerrado."
            }
        }

    } catch {
        Write-Error "Ocurrió un error al ejecutar 'netstat'. Detalles: $($_.Exception.Message)"
    }
}
function Invoke-PortAnalysis {
    [CmdletBinding()]
    param()

    Write-Host "`n--- Análisis de Puertos en Escucha (LISTENING) ---" -ForegroundColor Cyan
    try {
        $listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction Stop

        if (-not $listeningPorts) {
            Write-Host "[OK] No se encontraron puertos TCP en estado de escucha." -ForegroundColor Green
            return
        }

        $portInfo = foreach ($port in $listeningPorts) {
            try {
                $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    PuertoLocal = $port.LocalPort
                    Direccion   = $port.LocalAddress
                    PID         = $port.OwningProcess
                    Proceso     = if ($process) { $process.Name } else { "No disponible" }
                    Ruta        = if ($process) { $process.Path } else { "No disponible" }
                }
            } catch {
                # Proceso podría haber terminado
            }
        }

        Write-Host "Se encontraron los siguientes puertos en escucha:" -ForegroundColor Yellow
        $portInfo | Format-Table -AutoSize

        while ($true) {
            $pidToAction = Read-Host "`n? Ingrese el PID de un proceso para gestionarlo (o '0' para volver al menú)"
            if ($pidToAction -eq '0') { break }

            $targetProcessInfo = $portInfo | Where-Object { $_.PID -eq $pidToAction } | Select-Object -First 1
            if (-not $targetProcessInfo) {
                Write-Warning "El PID '$pidToAction' no se encuentra en la lista."
                continue
            }

            # Reutilizamos la lógica de acción de la otra función
            Invoke-FirewallAudit -Connections $portInfo # Pasamos la info para que el menú funcione
            break # Salimos después de la acción

        }

    } catch {
        Write-Error "Ocurrió un error al obtener los puertos en escucha. Detalles: $($_.Exception.Message)"
    }
}
function Invoke-ForensicArtifactCollection {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Host "`n--- Recopilacion de Artefactos Forenses ---" -ForegroundColor Cyan
    if (-not ($PSCmdlet.ShouldProcess("el sistema para recopilar evidencia", "Recopilar Artefactos"))) {
        return
    }

    $evidencePath = Join-Path -Path ([Environment]::GetFolderPath('Desktop')) -ChildPath "MediTool_Evidence_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    Write-Host "Creando carpeta de evidencia en: $evidencePath" -ForegroundColor Yellow
    New-Item -Path $evidencePath -ItemType Directory -Force | Out-Null

    # 1. Recopilar Prefetch
    try {
        Write-Host "Recopilando archivos Prefetch..." -ForegroundColor Green
        $prefetchPath = Join-Path $evidencePath "Prefetch"
        New-Item -Path $prefetchPath -ItemType Directory -Force | Out-Null
        Copy-Item -Path "$($env:windir)\Prefetch\*.pf" -Destination $prefetchPath -ErrorAction SilentlyContinue
    } catch { Write-Warning "No se pudieron recopilar los archivos Prefetch." }

    # 2. Recopilar LNK y JumpLists
    try {
        Write-Host "Recopilando archivos LNK y JumpLists..." -ForegroundColor Green
        $lnkPath = Join-Path $evidencePath "LNK_Jumplists"
        New-Item -Path $lnkPath -ItemType Directory -Force | Out-Null
        $recentPath = "$($env:APPDATA)\Microsoft\Windows\Recent"
        Copy-Item -Path "$recentPath\*.lnk" -Destination $lnkPath -ErrorAction SilentlyContinue
        Copy-Item -Path "$recentPath\AutomaticDestinations\*.automaticDestinations-ms" -Destination $lnkPath -ErrorAction SilentlyContinue
        Copy-Item -Path "$recentPath\CustomDestinations\*.customDestinations-ms" -Destination $lnkPath -ErrorAction SilentlyContinue
    } catch { Write-Warning "No se pudieron recopilar los archivos LNK/JumpLists." }

    # 3. Extraer Eventos Clave
    Write-Host "Extrayendo registros de eventos clave (esto puede tardar)..." -ForegroundColor Green
    $eventsPath = Join-Path $evidencePath "EventLogs"
    New-Item -Path $eventsPath -ItemType Directory -Force | Out-Null

    # Creacion de Procesos (4688)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -ErrorAction Stop | Select-Object TimeCreated, Id, Message | Export-Csv -Path "$eventsPath\ProcessCreation_4688.csv" -NoTypeInformation -Encoding UTF8
    } catch { Write-Warning "No se encontraron o no se pudieron exportar los eventos de creacion de procesos." }

    # Creacion de Tareas Programadas (4698)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698} -ErrorAction Stop | Select-Object TimeCreated, Id, Message | Export-Csv -Path "$eventsPath\ScheduledTaskCreation_4698.csv" -NoTypeInformation -Encoding UTF8
    } catch { Write-Warning "No se encontraron o no se pudieron exportar los eventos de creacion de tareas." }

    # Borrado de Logs (1102)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -ErrorAction Stop | Select-Object TimeCreated, Id, Message | Export-Csv -Path "$eventsPath\LogClear_1102.csv" -NoTypeInformation -Encoding UTF8
    } catch { Write-Warning "No se encontraron o no se pudieron exportar los eventos de borrado de logs." }

    # Guardar el log de la sesion actual
    if ($global:ActionLog.Count -gt 0) {
        $global:ActionLog | Export-Csv -Path "$evidencePath\ActionLog_Session.csv" -NoTypeInformation -Encoding UTF8
    }

    Write-Host "`n[OK] Recopilacion de artefactos finalizada." -ForegroundColor Green
    Write-Host "Los datos se han guardado en la carpeta '$evidencePath'." -ForegroundColor Cyan
    Invoke-Item -Path $evidencePath
}

function Invoke-RealTimeMonitoring {
    Clear-Host
    Write-Host "`n--- Modulo de Monitoreo en Tiempo Real ---" -ForegroundColor Cyan
    Write-Host "1. Monitorear Creacion de Procesos"
    Write-Host "2. Monitorear Conexiones de Red Salientes"
    Write-Host "0. Volver al menu anterior"
    $choice = Read-Host "Selecciona una opcion"

    switch ($choice) {
        '1' {
            if ($global:ProcessMonitorJob) { Write-Warning "El monitor de procesos ya esta activo."; return }
            Write-Host "`nIniciando monitor de creacion de procesos en segundo plano..." -ForegroundColor Yellow

            $scriptBlock = {
                $query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
                Register-WmiEvent -Query $query -Action {
                    $process = $event.SourceEventArgs.NewEvent.TargetInstance
                    $logMessage = "[MONITOR] Nuevo Proceso Creado: $($process.Name) (PID: $($process.ProcessId)) | Linea de Comando: $($process.CommandLine)"
                    Write-Host $logMessage -ForegroundColor Red
                } | Out-Null; while ($true) { Start-Sleep -Seconds 1 }
            }
            $global:ProcessMonitorJob = Start-Job -ScriptBlock $scriptBlock
            Add-LogEntry -Message "Iniciado el monitor de creacion de procesos."
            Write-Host "[OK] Monitor de procesos iniciado. Volviendo al menu..." -ForegroundColor Green
        }
        '2' {
            if ($global:NetworkMonitorJob) { Write-Warning "El monitor de red ya esta activo."; return }
            Write-Host "`nIniciando monitor de conexiones de red en segundo plano..." -ForegroundColor Yellow
            $scriptBlock = {
                $query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PerfFormattedData_Tcpip_TCPv4' AND TargetInstance.ConnectionsEstablished > 0"
                Register-WmiEvent -Query $query -Action {
                    $connections = $event.SourceEventArgs.NewEvent.TargetInstance.ConnectionsEstablished
                    $logMessage = "[MONITOR] Nueva conexion de red establecida detectada. Total actual: $connections"
                    Write-Host $logMessage -ForegroundColor Red
                    Write-Host "  - Se recomienda ejecutar la 'Auditoria de Conexiones de Red (netstat)' para investigar." -ForegroundColor Cyan
                } | Out-Null; while ($true) { Start-Sleep -Seconds 1 }
            }
            $global:NetworkMonitorJob = Start-Job -ScriptBlock $scriptBlock
            Add-LogEntry -Message "Iniciado el monitor de conexiones de red."
            Write-Host "[OK] Monitor de red iniciado. Volviendo al menu..." -ForegroundColor Green
        }
        '0' { return }
        default { Write-Warning "Opcion no valida." }
    }
}

function Invoke-ThreatIntelScan {
    Clear-Host
    Write-Host "`n--- Modulo de Inteligencia de Amenazas ---" -ForegroundColor Cyan
    Write-Host "1. Analizar Procesos sin Firma en Lote (VirusTotal)"
    Write-Host "2. Analizar IPs de Red en Lote (AbuseIPDB)"
    Write-Host "0. Volver al menu anterior"
    $choice = Read-Host "Selecciona una opcion"

    switch ($choice) {
        '1' {
            $unsigned = Find-UnsignedProcesses
            if (-not $unsigned) {
                Write-Host "[OK] No se encontraron procesos sin firma para analizar." -ForegroundColor Green
                return
            }
            Write-Host "Se encontraron $($unsigned.Count) procesos sin firma." -ForegroundColor Yellow
            $unsigned | Format-Table Name, ID, Path -AutoSize
            $response = Read-Host "?Deseas analizar todos estos procesos con VirusTotal? (S/N)"
            if ($response -match '^[sS]$') {
                foreach ($proc in $unsigned) {
                    Get-VirusTotalReport -FilePath $proc.Path
                }
            }
        }
        '2' {
            $apiKey = Read-Host "Ingresa tu API Key de AbuseIPDB"
            if ([string]::IsNullOrWhiteSpace($apiKey)) { Write-Warning "API Key no valida."; return }

            $connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
            $remoteIPs = $connections.RemoteAddress | Where-Object { $_ -ne "127.0.0.1" -and $_ -ne "::1" } | Get-Unique

            if (-not $remoteIPs) {
                Write-Host "[OK] No se encontraron conexiones externas activas para analizar." -ForegroundColor Green
                return
            }

            Write-Host "Analizando $($remoteIPs.Count) IPs unicas..." -ForegroundColor Yellow
            foreach ($ip in $remoteIPs) {
                $headers = @{ "Key" = $apiKey; "Accept" = "application/json" }
                $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90"
                try {
                    $report = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop
                    if ($report.data.abuseConfidenceScore -ge 50) {
                        Write-Host "  - [ALERTA] IP: $ip | Puntuacion de Abuso: $($report.data.abuseConfidenceScore)% | Pais: $($report.data.countryCode)" -ForegroundColor Red
                    } else {
                        Write-Host "  - [OK] IP: $ip | Puntuacion de Abuso: $($report.data.abuseConfidenceScore)%" -ForegroundColor Green
                    }
                } catch {
                    Write-Warning "No se pudo analizar la IP $ip. Error: $($_.Exception.Message)"
                }
            }
        }
        '0' { return }
        default { Write-Warning "Opcion no valida." }
    }
}

function Invoke-VulnerabilityScan {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    # Base de datos interna de vulnerabilidades con exploits publicos conocidos
    $knownExploits = @{
        'MS17-010'      = @{ Type = 'REMOTO'; Exploit = 'EternalBlue/WannaCry'; Criticality = 'CRITICO' }
        'MS14-068'      = @{ Type = 'LOCAL'; Exploit = 'Kerberos Golden Ticket (PyKEK)'; Criticality = 'CRITICO' }
        'MS16-032'      = @{ Type = 'LOCAL'; Exploit = 'Secondary Logon Escalation (Juicy Potato)'; Criticality = 'ALTO' }
        'MS15-051'      = @{ Type = 'LOCAL'; Exploit = 'Win32k Privilege Escalation (CVE-2015-1701)'; Criticality = 'ALTO' }
        'MS14-064'      = @{ Type = 'REMOTO'; Exploit = 'OLE Remote Code Execution (Sandworm)'; Criticality = 'ALTO' }
        'MS10-061'      = @{ Type = 'REMOTO'; Exploit = 'Print Spooler RCE'; Criticality = 'MEDIO' }
        'CVE-2019-0708' = @{ Type = 'REMOTO'; Exploit = 'BlueKeep RDP RCE'; Criticality = 'CRITICO' }
        'CVE-2020-0796' = @{ Type = 'REMOTO'; Exploit = 'SMBGhost RCE'; Criticality = 'CRITICO' }
        'CVE-2021-40444' = @{ Type = 'REMOTO'; Exploit = 'MSHTML RCE (Office)'; Criticality = 'ALTO' }
        'CVE-2023-23397' = @{ Type = 'REMOTO'; Exploit = 'Outlook NTLM Hash Leak'; Criticality = 'CRITICO' }
    }

    Write-Host "`n--- Buscando Actualizaciones de Seguridad Faltantes y Exploits Conocidos ---" -ForegroundColor Cyan
    Write-Host "Iniciando contacto con el servicio de Windows Update. Este proceso puede tardar varios minutos..."

    try {
        $updateSession = New-Object -ComObject "Microsoft.Update.Session"
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        Write-Progress -Activity "Buscando Actualizaciones de Windows" -Status "Consultando el servidor de actualizaciones..." -PercentComplete 50
        
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and CategoryIDs contains '0fa1201d-4330-4fa8-8ae9-b877473b6441'")
        
        Write-Progress -Activity "Buscando Actualizaciones de Windows" -Completed

        if ($searchResult.Updates.Count -eq 0) {
            Write-Host "`n[OK] No se encontraron actualizaciones de seguridad pendientes. El sistema esta al dia." -ForegroundColor Green
            return
        }

        Write-Host "`n[AVISO] Se han encontrado $($searchResult.Updates.Count) actualizaciones de seguridad pendientes." -ForegroundColor Yellow
        Write-Host "Analizando si alguna corresponde a una vulnerabilidad con exploit conocido..."

        $vulnerableUpdates = foreach ($update in $searchResult.Updates) {
            $title = $update.Title
            $kb = ($update.KBArticleIDs | Select-Object -First 1)
            $severity = $update.MsrcSeverity
            $exploitInfo = $null

            foreach ($key in $knownExploits.Keys) {
                if ($title -like "*$key*") {
                    $exploitInfo = $knownExploits[$key]
                    break
                }
            }

            [PSCustomObject]@{
                KB          = "KB$kb"
                Severidad   = if ($severity) { $severity } else { 'No esp.' }
                Explotable  = if ($exploitInfo) { "SI" } else { "No" }
                TipoExploit = if ($exploitInfo) { $exploitInfo.Type } else { "N/A" }
                Nombre      = if ($exploitInfo) { $exploitInfo.Exploit } else { "N/A" }
                Titulo      = $title
            }
        }

        $header = "{0,-12} {1,-10} {2,-11} {3,-12} {4,-40} {5}" -f "KB", "Severidad", "Explotable", "Tipo", "Nombre Exploit", "Titulo de la Actualizacion"
        Write-Host "`n$header" -ForegroundColor White
        Write-Host ("-" * ($header.Length + 20)) -ForegroundColor White

        foreach ($item in $vulnerableUpdates) {
            $isExploitable = $item.Explotable -eq 'SI'
            $color = if ($isExploitable) { 'Red' } else { 'Yellow' }
            
            $line = "{0,-12} {1,-10} {2,-11} {3,-12} {4,-40} {5}" -f $item.KB, $item.Severidad, $item.Explotable, $item.TipoExploit, $item.Nombre, $item.Titulo
            Write-Host $line -ForegroundColor $color
        }

        # --- NUEVA SECCION INTERACTIVA PARA INSTALAR ACTUALIZACIONES ---
        $kbsToInstall = $vulnerableUpdates.KB -replace "KB", "" | Where-Object { $_ }
        if ($kbsToInstall.Count -gt 0) {
            $response = Read-Host "`n?Deseas intentar instalar estas $($kbsToInstall.Count) actualizaciones de seguridad para corregir las vulnerabilidades? (S/N)"
            if ($response -match '^[sS]$') {
                
                if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                    $installModule = Read-Host "El modulo 'PSWindowsUpdate' es necesario. ?Deseas instalarlo desde la PowerShell Gallery? (S/N)"
                    if ($installModule -match '^[sS]$') {
                        try {
                            # Forzar el uso de TLS 1.2 para compatibilidad con PowerShell Gallery
                            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                            Write-Host "Instalando el modulo PSWindowsUpdate..." -ForegroundColor Cyan
                            Install-Module PSWindowsUpdate -Force -AcceptLicense -ErrorAction Stop
                        } catch {
                            Write-Error "No se pudo instalar el modulo. Abortando la instalacion de actualizaciones."
                            return
                        }
                    } else {
                        Write-Warning "Instalacion de actualizaciones cancelada."
                        return
                    }
                }

                Write-Host "Iniciando la instalacion de las actualizaciones. Esto puede requerir uno o mas reinicios." -ForegroundColor Yellow
                if ($PSCmdlet.ShouldProcess("el sistema para instalar $($kbsToInstall.Count) actualizaciones", "Instalar Actualizaciones de Seguridad")) {
                    Install-WindowsUpdate -KBArticleID $kbsToInstall -AcceptAll -AutoReboot -Verbose
                }
            }
        }

    }
    catch {
        Write-Error "Ocurrio un error al contactar con el servicio de Windows Update."
        Write-Error "Detalles: $($_.Exception.Message)"
        Write-Warning "Asegurate de que el servicio 'Windows Update' (wuauserv) este en ejecucion."
    }
}
function Find-HiddenFilesAndScan {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string[]]$Path = @(
            "C:\ProgramData",
            "$env:USERPROFILE\AppData\Local",
            "$env:SystemDrive\Users\Public"
        ),
        [switch]$ScanWithDefender,
        [switch]$SkipScanPrompt
    )

    begin {
        $allFoundFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
        $defenderPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"
        $defenderExists = Test-Path $defenderPath
    }

    process {
        foreach ($searchPath in $Path) {
            if (-not (Test-Path -Path $searchPath -PathType Container)) {
                Write-Warning "La ruta '$searchPath' no existe o no es un directorio. Se omitira."
                continue
            }

            Write-Host "`n Analizando ruta: $searchPath..." -ForegroundColor Cyan
            try {
                $found = Get-ChildItem -Path $searchPath -Recurse -Hidden -Force -ErrorAction Stop | Where-Object { -not $_.PSIsContainer }
                if ($found) {
                    $allFoundFiles.AddRange($found)
                }
            }
            catch {
                Write-Warning "No se pudo acceder a elementos dentro de '$searchPath'. Error: $($_.Exception.Message)"
            }
        }
    }

    end {
        if ($allFoundFiles.Count -gt 0) {
            Write-Host "`n[ALERTA] Se encontraron $($allFoundFiles.Count) archivos ocultos en las rutas especificadas:" -ForegroundColor Red
            $allFoundFiles | Select-Object Name, @{N='Directory'; E={$_.DirectoryName}}, CreationTime, Length | Format-Table -AutoSize

            if ($ScanWithDefender) {
                $scanChoice = 's'
            }
            elseif (-not $SkipScanPrompt) {
                Write-Host "`n¿Desea escanear estos archivos con Windows Defender? (S/N)" -ForegroundColor Yellow
                $scanChoice = Read-Host
            }

            if ($scanChoice -eq 's') {
                if (-not $defenderExists) {
                    Write-Warning "El ejecutable de Windows Defender (MpCmdRun.exe) no se encontró en la ruta esperada. No se puede escanear."
                    return
                }

                Write-Host "Iniciando escaneo con Windows Defender. Esto puede tardar varios minutos..." -ForegroundColor Green
                $fileCount = $allFoundFiles.Count
                $i = 0
                foreach ($file in $allFoundFiles) {
                    $i++
                    Write-Progress -Activity "Escaneando con Windows Defender" -Status "Escaneando $($file.Name)" -PercentComplete (($i / $fileCount) * 100)
                    if ($PSCmdlet.ShouldProcess($file.FullName, "Escanear Archivo")) {
                        Start-Process -FilePath $defenderPath -ArgumentList "-Scan -ScanType 3 -File `"$($file.FullName)`"" -Wait -NoNewWindow
                    }
                }
                Write-Progress -Activity "Escaneando con Windows Defender" -Completed
                Write-Host "`n¡Escaneo completado!" -ForegroundColor Green
                Write-Host "Revise el historial de protección en 'Seguridad de Windows' para ver los resultados detallados." -ForegroundColor Cyan
            }
        } else {
            Write-Host "`n[OK] No se encontraron archivos ocultos en las rutas especificadas." -ForegroundColor Green
        }
    }
}
function Get-FailedLogons {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$Days = 1,

        [Parameter(Mandatory=$false)]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    Write-Host "`n Auditando inicios de sesion fallidos (ID 4625) en los ultimos $Days dia(s)..." -ForegroundColor Cyan
    
    try {
        $startTime = (Get-Date).AddDays(-$Days)
        
        $failedLogons = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4625
            StartTime = $startTime
        } -ErrorAction Stop

        if ($failedLogons) {
            $report = foreach ($event in $failedLogons) {
                $xml = [xml]$event.ToXml()
                $targetUserName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $ipAddress = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                
                [PSCustomObject]@{
                    FechaHora       = $event.TimeCreated
                    Usuario         = $targetUserName
                    DireccionOrigen = $ipAddress
                    TipoDeInicio    = switch ($logonType) {
                        '2' { "Interactivo" }
                        '3' { "Red" }
                        '4' { "Batch" }
                        '5' { "Servicio" }
                        '7' { "Desbloqueo" }
                        '8' { "NetworkCleartext" }
                        '9' { "NewCredentials" }
                        '10' { "RemoteInteractive (RDP)" }
                        '11' { "CachedInteractive" }
                        default { "Desconocido ($logonType)" }
                    }
                    Equipo          = $event.MachineName
                }
            }
            
            Write-Host "`n[ALERTA] Se encontraron $($report.Count) intentos de inicio de sesión fallidos:" -ForegroundColor Red
            $report | Format-Table -AutoSize
        }
    }
    catch {
        if ($_.Exception.Message -like "*No events were found*") {
            Write-Host "`n[OK] No se encontraron inicios de sesión fallidos en el período especificado." -ForegroundColor Green
        } else {
            Write-Warning "Ocurrió un error al consultar el registro de eventos en $($ComputerName): $($_.Exception.Message)"
        }
    }
}
function Enable-WindowsActivation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    begin {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $targetUrl = "https://get.activated.win"
    }

    process {
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error "Este comando requiere privilegios de Administrador. Por favor, reinicie la terminal con 'Ejecutar como Administrador'."
            return
        }
        
        Write-Host "`nADVERTENCIA: Está a punto de descargar y ejecutar un script de activación de Windows no oficial desde internet." -ForegroundColor Yellow
        Write-Host "Esta acción presenta un riesgo de seguridad y debe realizarse bajo su propia responsabilidad." -ForegroundColor Yellow
        
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Ejecutar script de activación desde $targetUrl")) {
            try {
                Write-Host "Iniciando activación..." -ForegroundColor Green
                Invoke-RestMethod -Uri $targetUrl -ErrorAction Stop | Invoke-Expression
                Write-Host "Comando de activación ejecutado. Revise el estado de su sistema para confirmar." -ForegroundColor Green
            }
            catch [System.Net.WebException] {
                Write-Error "Error de red al intentar descargar el script. Verifique su conexión a Internet."
                Write-Error "Detalles: $($_.Exception.Response.StatusDescription)"
            }
            catch {
                Write-Error "Ocurrió un error inesperado durante la ejecución."
                Write-Error "Detalles: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "Activación cancelada por el usuario." -ForegroundColor Red
        }
    }
}
function Export-JsonSecurityReport {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    begin {
        if ($null -eq $global:InitialSystemState -or $null -eq $global:ActionLog) {
            Write-Error "Los datos de análisis no han sido capturados. Ejecute un análisis completo antes de exportar el reporte."
            return
        }
    }

    process {
        $reportObject = [PSCustomObject]@{
            ReportMetadata = @{
                Generator    = 'Meditool Security Script'
                TimestampUTC = (Get-Date).ToUniversalTime().ToString('o')
                ComputerName = $env:COMPUTERNAME
                UserName     = $env:USERNAME
            }
            SystemScanState = $global:InitialSystemState
            UserActionsLog  = $global:ActionLog
        }

        if ([string]::IsNullOrEmpty($Path)) {
            try {
                $defaultPath = [Environment]::GetFolderPath('Desktop')
            } catch {
                $defaultPath = $env:TEMP
            }
            $fileName = "SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $fullPath = Join-Path -Path $defaultPath -ChildPath $fileName
        } else {
            $fullPath = $Path
        }

        Write-Host "`n Generando reporte de seguridad en formato JSON..." -ForegroundColor Cyan

        try {
            if ($PSCmdlet.ShouldProcess($fullPath, "Exportar Reporte JSON")) {
                $reportObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $fullPath -Encoding utf8 -ErrorAction Stop
                Write-Host "Reporte JSON generado exitosamente en: $fullPath" -ForegroundColor Green
                Invoke-Item -Path $fullPath
            }
        }
        catch {
            Write-Error "No se pudo guardar el reporte en '$fullPath'. Verifique los permisos y la ruta."
            Write-Error "Detalles del error: $($_.Exception.Message)"
        }
    }
}
function Get-UserInfo {
    [CmdletBinding()]
    param()

    $output = [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        CurrentUser         = $env:USERNAME
        OperatingSystem     = "No disponible"
        OSArchitecture      = "No disponible"
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
        LocalAdministrators = @()
        NetworkAdapters     = @()
    }

    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $output.OperatingSystem = $osInfo.Caption
        $output.OSArchitecture = $osInfo.OSArchitecture
    }
    catch {
        Write-Warning "No se pudo obtener la informacion del sistema operativo."
    }

    try {
        $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        $output.LocalAdministrators = Get-LocalGroupMember -Name $adminGroup.Name -ErrorAction Stop | Select-Object -ExpandProperty Name
    }
    catch {
        Write-Warning "No se pudieron obtener los administradores locales. Se requieren privilegios elevados."
    }

    $adapterList = [System.Collections.Generic.List[PSObject]]::new()
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        if ($adapters) {
            foreach ($adapter in $adapters) {
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                
                $adapterList.Add([PSCustomObject]@{
                    Name           = $adapter.Name
                    Description    = $adapter.InterfaceDescription
                    MACAddress     = $adapter.MacAddress
                    IPv4Address    = $ipConfig.IPv4Address.IPAddress
                    DefaultGateway = $ipConfig.IPv4DefaultGateway.NextHop
                    DNSServers     = $ipConfig.DNSServer.ServerAddresses
                })
            }
        }
    }
    catch {
        Write-Warning "No se pudo obtener la información de los adaptadores de red."
    }
    
    $output.NetworkAdapters = $adapterList
    
    return $output
}
function Update-AllWingetApps {
    Write-Host "Iniciando la actualizacion de todas las aplicaciones con winget..." -ForegroundColor Green
    Write-Host "Esto puede tardar varios minutos y no requerira confirmacion manual." -ForegroundColor Yellow
    
    try {
        # El comando incluye parametros para aceptar acuerdos de licencia automaticamente.
        $wingetOutput = winget upgrade --all --include-unknown --force --accept-package-agreements --accept-source-agreements
        
        # Verificar la salida para saber si hubo actualizaciones.
        if ($wingetOutput -match "No se encontraron paquetes para actualizar.") {
             Write-Host "`nTodas las aplicaciones se han actualizado con exito." -ForegroundColor Green
        } else {
             Write-Host "`nLa actualizacion de winget ha finalizado. Es posible que algunos paquetes se hayan actualizado o ya estuvieran al dia." -ForegroundColor Green
        }
        
    } catch {
        Write-Host "`nOcurrio un error al ejecutar winget. Asegurese de que winget este instalado y de tener permisos de Administrador." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
function Clear-TempFolder {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$IncludeWindowsTemp,
        [switch]$IncludeSoftwareDistributionCache
    )

    $pathsToClean = [System.Collections.Generic.List[string]]::new()
    $pathsToClean.Add($env:TEMP)

    if ($IncludeWindowsTemp) {
        $pathsToClean.Add([System.IO.Path]::Combine($env:windir, 'Temp'))
    }
    if ($IncludeSoftwareDistributionCache) {
        $pathsToClean.Add([System.IO.Path]::Combine($env:windir, 'SoftwareDistribution', 'Download'))
    }

    $validPaths = $pathsToClean | Where-Object { Test-Path $_ }
    if ($validPaths.Count -eq 0) {
        Write-Warning "No se encontraron directorios temporales para limpiar."
        return
    }

    Write-Host "Analizando archivos temporales en las rutas seleccionadas..." -ForegroundColor Cyan
    $itemsToDelete = Get-ChildItem -Path $validPaths -Recurse -Force -ErrorAction SilentlyContinue
    
    if (-not $itemsToDelete) {
        Write-Host "`n[OK] No se encontraron archivos o carpetas para limpiar en las ubicaciones seleccionadas." -ForegroundColor Green
        return
    }

    $totalSize = ($itemsToDelete | Measure-Object -Property Length -Sum).Sum
    $sizeInMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "Se encontraron $($itemsToDelete.Count) elementos, con un tamaño total de $sizeInMB MB." -ForegroundColor Yellow

    if ($PSCmdlet.ShouldProcess(" $($itemsToDelete.Count) elementos ($sizeInMB MB)", "Eliminar Archivos Temporales")) {
        $failedItems = [System.Collections.Generic.List[string]]::new()
        $i = 0
        $totalItems = $itemsToDelete.Count

        foreach ($item in $itemsToDelete) {
            $i++
            Write-Progress -Activity "Limpiando archivos temporales" -Status "Eliminando: $($item.Name)" -PercentComplete (($i / $totalItems) * 100)
            try {
                Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
            }
            catch {
                $failedItems.Add($item.FullName)
            }
        }
        Write-Progress -Activity "Limpiando archivos temporales" -Completed

        $successCount = $totalItems - $failedItems.Count
        Write-Host "`nOperación de limpieza completada." -ForegroundColor Green
        Write-Host " - Elementos eliminados: $successCount"
        if ($failedItems.Count -gt 0) {
            Write-Warning " - No se pudieron eliminar $($failedItems.Count) elementos (probablemente estaban en uso)."
        }
    }
}
function Test-ISO27001Status {
    [CmdletBinding()]
    param()

    function New-ComplianceResult {
        param(
            [string]$ControlID,
            [string]$Description,
            [ValidateSet('PASS', 'FAIL', 'WARN', 'ERROR')]
            [string]$Status,
            [string]$Details
        )
        return [PSCustomObject]@{
            ControlID   = $ControlID
            Description = $Description
            Status      = $Status
            Details     = $Details
        }
    }

    $results = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $av = Get-MpComputerStatus -ErrorAction Stop
        if ($av.AntivirusEnabled) {
            if ($av.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7)) {
                $results.Add((New-ComplianceResult 'A.12.2.1' 'Anti-Malware' 'WARN' "Defender activo, pero las firmas tienen mas de 7 dias."))
            } else {
                $results.Add((New-ComplianceResult 'A.12.2.1' 'Anti-Malware' 'PASS' 'Windows Defender esta activo y actualizado.'))
            }
        } else {
            $results.Add((New-ComplianceResult 'A.12.2.1' 'Anti-Malware' 'FAIL' 'Windows Defender esta deshabilitado.'))
        }
    } catch {
        $results.Add((New-ComplianceResult 'A.12.2.1' 'Anti-Malware' 'ERROR' "No se pudo determinar el estado de Windows Defender."))
    }

    try {
        $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop).fDenyTSConnections -eq 0
        if ($rdpEnabled) {
            $results.Add((New-ComplianceResult 'A.9.4.2' 'Acceso Remoto (RDP)' 'WARN' 'El Escritorio Remoto (RDP) esta habilitado.'))
        } else {
            $results.Add((New-ComplianceResult 'A.9.4.2' 'Acceso Remoto (RDP)' 'PASS' 'El Escritorio Remoto (RDP) esta deshabilitado.'))
        }
    } catch {
        $results.Add((New-ComplianceResult 'A.9.4.2' 'Acceso Remoto (RDP)' 'ERROR' "No se pudo determinar el estado de RDP."))
    }

    try {
        $updateSession = New-Object -ComObject "Microsoft.Update.Session"
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates.Count
        if ($pendingUpdates -gt 0) {
            $results.Add((New-ComplianceResult 'A.12.1.2' 'Gestion de Parches' 'WARN' "Se encontraron $pendingUpdates actualizaciones de Windows pendientes."))
        } else {
            $results.Add((New-ComplianceResult 'A.12.1.2' 'Gestion de Parches' 'PASS' 'El sistema operativo esta actualizado.'))
        }
    } catch {
        $results.Add((New-ComplianceResult 'A.12.1.2' 'Gestion de Parches' 'ERROR' "No se pudo verificar el estado de Windows Update."))
    }
    
    try {
        $uacEnabled = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop).EnableLUA -eq 1
        if ($uacEnabled) {
            $results.Add((New-ComplianceResult 'A.9.4.4' 'Control de Acceso (UAC)' 'PASS' 'El Control de Cuentas de Usuario (UAC) esta habilitado.'))
        } else {
            $results.Add((New-ComplianceResult 'A.9.4.4' 'Control de Acceso (UAC)' 'FAIL' 'El Control de Cuentas de Usuario (UAC) esta deshabilitado.'))
        }
    } catch {
         $results.Add((New-ComplianceResult 'A.9.4.4' 'Control de Acceso (UAC)' 'ERROR' "No se pudo determinar el estado de UAC."))
    }

    Write-Host @"
========================================================
==      Verificacion de Controles de Seguridad        ==
========================================================
"@ -ForegroundColor Cyan

    # Encabezado de la tabla manual
    $header = ("{0,-10} {1,-11} {2,-26} {3}" -f "Resultado", "ControlID", "Descripcion", "Detalles")
    Write-Host $header -ForegroundColor White
    Write-Host ("-" * $header.Length) -ForegroundColor White

    # Bucle para escribir cada linea de la tabla manualmente
    foreach ($item in $results) {
        $status = $item.Status
        $color = switch ($status) {
            'PASS'  { 'Green' }
            'FAIL'  { 'Red' }
            'WARN'  { 'Yellow' }
            'ERROR' { 'Magenta' }
            default { 'White' }
        }
        $statusText = "[$status]"
        
        $line = "{0,-10} {1,-11} {2,-26} {3}" -f $statusText, $item.ControlID, $item.Description, $item.Details
        
        Write-Host -Object $line -ForegroundColor $color
    }

    Write-Host "`nNota: Esta es una verificacion automatizada y simplificada de controles seleccionados." -ForegroundColor Gray
    
    return $results
}
function Remove-SysJunk {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$IncludeSystemCache,
        [switch]$IncludeUpdateCache,
        [switch]$IncludeBrowserCache,
        [switch]$IncludeEventLogs,
        [switch]$CleanAll
    )

    $locations = @{
        UserTemp         = @{ Path = $env:TEMP }
        WindowsTemp      = @{ Path = Join-Path $env:windir -ChildPath 'Temp' }
        SoftwareDist     = @{ Path = Join-Path $env:windir -ChildPath 'SoftwareDistribution' | Join-Path -ChildPath 'Download' }
        INetCache        = @{ Path = Join-Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\INetCache' }
        Prefetch         = @{ Path = Join-Path $env:windir -ChildPath 'Prefetch' }
        WER              = @{ Path = Join-Path $env:ProgramData -ChildPath 'Microsoft\Windows\WER\ReportQueue' }
    }

    $selectedPaths = [System.Collections.Generic.List[string]]::new()
    $selectedPaths.Add($locations.UserTemp.Path)

    if ($IncludeSystemCache -or $CleanAll) {
        $selectedPaths.Add($locations.WindowsTemp.Path)
        $selectedPaths.Add($locations.Prefetch.Path)
        $selectedPaths.Add($locations.WER.Path)
    }
    if ($IncludeUpdateCache -or $CleanAll) {
        $selectedPaths.Add($locations.SoftwareDist.Path)
    }
    if ($IncludeBrowserCache -or $CleanAll) {
        $selectedPaths.Add($locations.INetCache.Path)
    }

    $validPaths = $selectedPaths | ForEach-Object { if (Test-Path $_) { $_ } }
    if ($validPaths.Count -eq 0) {
        Write-Warning "No se encontraron directorios de limpieza validos."
        return
    }
    
    Write-Host "Analizando rutas de limpieza. Esto puede tardar un momento..." -ForegroundColor Cyan
    $itemsToDelete = Get-ChildItem -Path $validPaths -Recurse -Force -ErrorAction SilentlyContinue
    
    if (-not $itemsToDelete) {
        Write-Host "`n[OK] No se encontraron archivos o carpetas para limpiar." -ForegroundColor Green
        return
    }

    $totalSize = ($itemsToDelete | Measure-Object -Property Length -Sum).Sum
    $sizeInMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "Se encontraron $($itemsToDelete.Count) elementos, ocupando un total de $sizeInMB MB." -ForegroundColor Yellow

    if ($PSCmdlet.ShouldProcess("Todos los archivos y carpetas en las rutas seleccionadas ($sizeInMB MB)", "Limpieza Profunda del Sistema")) {
        $failedItems = [System.Collections.Generic.List[string]]::new()
        $totalItems = $itemsToDelete.Count
        $i = 0

        foreach ($item in $itemsToDelete) {
            $i++
            Write-Progress -Activity "Realizando Limpieza Profunda" -Status "Eliminando: $($item.FullName)" -PercentComplete (($i / $totalItems) * 100)
            try {
                Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
            }
            catch {
                $failedItems.Add($item.FullName)
            }
        }
        Write-Progress -Activity "Realizando Limpieza Profunda" -Completed

        $successCount = $totalItems - $failedItems.Count
        $reclaimedMB = [math]::Round(($totalSize - ($failedItems | ForEach-Object { (Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue).Length } | Measure-Object -Sum).Sum) / 1MB, 2)

        Write-Host "`n Limpieza finalizada." -ForegroundColor Green
        Write-Host " - Espacio recuperado: $reclaimedMB MB"
        Write-Host " - Elementos eliminados: $successCount de $totalItems"

        if ($failedItems.Count -gt 0) {
            Write-Warning "No se pudieron eliminar $($failedItems.Count) elementos, probablemente por estar en uso."
        }
    }
    
    if ($IncludeEventLogs -or $CleanAll) {
        Write-Host "`nLimpiando registros de eventos de Windows..." -ForegroundColor Cyan
        if ($PSCmdlet.ShouldProcess("Todos los registros de eventos no esenciales", "Limpiar Registros")) {
            Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -and $_.IsEnabled } | ForEach-Object {
                try {
                    $logName = $_.LogName
                    if ($PSCmdlet.ShouldProcess($logName, "Limpiar Log")) {
                        Clear-EventLog -LogName $logName -ErrorAction Stop
                    }
                } catch {}
            }
            Write-Host "Registros de eventos limpiados." -ForegroundColor Green
        }
    }
}
function Find-OrphanedAndZeroByteFiles {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string[]]$Path = @(
            $env:USERPROFILE,
            $env:ProgramData
        ),
        [switch]$Delete
    )

    begin {
        $allFoundFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    }

    process {
        foreach ($searchPath in $Path) {
            if (-not (Test-Path -Path $searchPath -PathType Container)) {
                Write-Warning "La ruta '$searchPath' no existe o no es un directorio. Se omitira."
                continue
            }
            
            Write-Host "Buscando archivos de 0 bytes en '$searchPath'..." -ForegroundColor Cyan
            
            try {
                $found = Get-ChildItem -Path $searchPath -Recurse -File -Force -ErrorAction Stop | Where-Object { $_.Length -eq 0 }
                if ($found) {
                    $allFoundFiles.AddRange($found)
                }
            }
            catch {
                Write-Warning "Error al acceder a subdirectorios dentro de '$searchPath'. Es posible que no tengas permisos."
            }
        }
    }

    end {
        if ($allFoundFiles.Count -eq 0) {
            Write-Host "`n[OK] No se encontraron archivos de 0 bytes en las ubicaciones especificadas." -ForegroundColor Green
            return
        }

        Write-Host "`n[AVISO] Se encontraron $($allFoundFiles.Count) archivos de 0 bytes." -ForegroundColor Yellow
        $allFoundFiles | Select-Object Name, @{N='Directory'; E={$_.DirectoryName}}, CreationTime | Format-Table -AutoSize

        if ($Delete) {
            $failedDeletions = [System.Collections.Generic.List[string]]::new()
            
            foreach ($file in $allFoundFiles) {
                if ($PSCmdlet.ShouldProcess($file.FullName, "Eliminar archivo de 0 bytes")) {
                    try {
                        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    }
                    catch {
                        $failedDeletions.Add($file.FullName)
                    }
                }
            }
            
            if ($failedDeletions.Count -gt 0) {
                Write-Warning "No se pudieron eliminar $($failedDeletions.Count) archivos, probablemente por permisos o porque estaban en uso."
            }
        } else {
            return $allFoundFiles
        }
    }
}
#region Funciones de Soporte y Reutilizables
function Set-WindowFocus {
    [CmdletBinding()]
    param()
    if (-not ('Win32Functions.Api' -as [type])) {
        $signature = @"
        using System;
        using System.Runtime.InteropServices;
        namespace Win32Functions {
            public class Api {
                [DllImport("user32.dll")]
                public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            }
        }
"@
        try { Add-Type -TypeDefinition $signature -ErrorAction Stop }
        catch { Write-Error "No se pudo compilar el codigo P/Invoke necesario."; return }
    }
    try {
        $hwnd = (Get-Process -Id $PID).MainWindowHandle
        if ($hwnd -and $hwnd -ne [IntPtr]::Zero) {
            $SW_RESTORE = 9
            [Win32Functions.Api]::ShowWindow($hwnd, $SW_RESTORE) | Out-Null
        }
    }
    catch {
        Write-Warning "No se pudo enfocar la ventana de la consola."
    }
}
function Show-Findings {
    param(
        [string]$Title,
        [PSObject[]]$Data,
        [string]$NotFoundMessage = "No se encontraron elementos."
    )
    if ($Data -and $Data.Count -gt 0) {
        Write-Host "`n[AVISO] Se encontraron los siguientes elementos en '$Title':" -ForegroundColor Red
        $Data | Format-Table -AutoSize
    }
    else {
        Write-Host "`n[OK] $NotFoundMessage" -ForegroundColor Green
    }
}
#endregion

#region Definición de Todas las Funciones del Menú
function Get-RdpStatusAndConnections {
    $rdpIn = Get-LastIncomingRDPLogon
    $rdpOut = Get-LastOutgoingRDPConnection
    Write-Host "`nEstado del servicio RDP: $(Get-RDPStatus)"
    Write-Host "`nUltima conexion RDP entrante:`n  - Fecha: $(if ($rdpIn) { $rdpIn.Fecha } else { 'N/A' })`n  - Usuario: $(if ($rdpIn) { $rdpIn.Usuario } else { 'N/A' })`n  - Origen: $(if ($rdpIn) { $rdpIn.Origen } else { 'N/A' })"
    Write-Host "`nUltima conexion RDP saliente:`n  - Host/IP: $(if ($rdpOut) { $rdpOut.Host } else { 'N/A' })`n  - Fecha: $(if ($rdpOut) { $rdpOut.Fecha } else { 'N/A' })"
}
function Invoke-NotImplemented {
    param([string]$FeatureName)
    Write-Host "`n[AVISO] La funcion '$FeatureName' aun no esta implementada en esta version." -ForegroundColor Yellow
}
#endregion

#region Función Principal - Menú Interactivo
function Show-SubMenu {
    param(
        [string]$Title,
        [array]$MenuOptions
    )
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "=============================================" -ForegroundColor Green
    $MenuOptions | ForEach-Object {
        Write-Host "  $($_.ID). $($_.Opcion)"
    }
    return Read-Host "`nSelecciona una opcion"
}

function Start-AuditMenu {
    $menu = @(
        [PSCustomObject]@{ ID = 1; Opcion = "Recopilar Artefactos Forenses"; Action = { Invoke-ForensicArtifactCollection } },
        [PSCustomObject]@{ ID = 2; Opcion = "Iniciar Monitoreo en Tiempo Real"; Action = { Invoke-RealTimeMonitoring } },
        [PSCustomObject]@{ ID = 3; Opcion = "Analisis con Inteligencia de Amenazas"; Action = { Invoke-ThreatIntelScan } },
        [PSCustomObject]@{ ID = 4; Opcion = "Revisar Estado de RDP y Ultimas Conexiones"; Action = { Get-RdpStatusAndConnections } },
        [PSCustomObject]@{ ID = 5; Opcion = "Auditar Conexiones de Red Activas (netstat)"; Action = { Invoke-FirewallAudit } },
        [PSCustomObject]@{ ID = 6; Opcion = "Analizar Puertos en Escucha (LISTENING)"; Action = { Invoke-PortAnalysis } },
        [PSCustomObject]@{ ID = 7; Opcion = "Buscar Tareas Programadas Maliciosas"; Action = { Show-Findings -Title "Tareas Programadas Sospechosas" -Data (Find-MaliciousScheduledTasks) -NotFoundMessage "No se encontraron tareas programadas sospechosas." } },
        [PSCustomObject]@{ ID = 8; Opcion = "Auditar Servicios No Esenciales"; Action = { Audit-NonEssentialServices } },
        [PSCustomObject]@{ ID = 9; Opcion = "Buscar Cuentas de Usuario Inactivas"; Action = { Show-Findings -Title "Cuentas de Usuario Inactivas" -Data (Find-InactiveUsers) -NotFoundMessage "No se encontraron cuentas de usuario inactivas." } },
        [PSCustomObject]@{ ID = 10; Opcion = "Verificar Firmas de Archivos Criticos"; Action = { Verify-FileSignatures } },
        [PSCustomObject]@{ ID = 11; Opcion = "Verificar Procesos en Ejecucion sin Firma"; Action = { Show-Findings -Title "Procesos en Ejecucion sin Firma Digital" -Data (Find-UnsignedProcesses) -NotFoundMessage "No se encontraron procesos sin firma." } },
        [PSCustomObject]@{ ID = 12; Opcion = "Auditar Registro de Inicio Automatico (Autorun)"; Action = { Find-RegistryAutorun } },
        [PSCustomObject]@{ ID = 13; Opcion = "Analizar Configuracion de Red Detallada"; Action = { Test-NetworkConnections } },
        [PSCustomObject]@{ ID = 14; Opcion = "Buscar Archivos de 0 Bytes"; Action = { Find-OrphanedAndZeroByteFiles } },
        [PSCustomObject]@{ ID = 15; Opcion = "Buscar Archivos Ocultos"; Action = { Find-HiddenFilesAndScan } },
        [PSCustomObject]@{ ID = 16; Opcion = "Auditar Inicios de Sesion Fallidos"; Action = { Get-FailedLogons | Format-Table -AutoSize } },
        [PSCustomObject]@{ ID = 17; Opcion = "Buscar Vulnerabilidades (Exploits Conocidos)"; Action = { Invoke-VulnerabilityScan } },
        [PSCustomObject]@{ ID = 18; Opcion = "Escaneo de Escalada de Privilegios (WinPEAS)"; Action = { Invoke-WinPEAS } },
        [PSCustomObject]@{ ID = 0; Opcion = "Volver al Menu Principal"; Action = { return } }
    )
    while ($true) {
        $choice = Show-SubMenu -Title "Menu de Auditoria y Analisis Local" -MenuOptions $menu
        $selected = $menu | Where-Object { $_.ID -eq $choice }
        if ($selected) {
            if ($selected.ID -eq 0) { break }
            Invoke-Command -ScriptBlock $selected.Action
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White; Read-Host | Out-Null
        } else { Write-Host "Opcion no valida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}

function Start-HardeningMenu {
    $menu = @(
        [PSCustomObject]@{ ID = 1; Opcion = "Administrar el servicio de RDP"; Action = { Set-RDP } },
        [PSCustomObject]@{ ID = 2; Opcion = "Administrar la Telemetria de Windows"; Action = { Manage-WindowsTelemetry } },
        [PSCustomObject]@{ ID = 3; Opcion = "Detener Procesos Sin Firma"; Action = { Stop-SuspiciousProcess } },
        [PSCustomObject]@{ ID = 4; Opcion = "Bloquear Ejecucion de Archivo por Ruta"; Action = { Block-FileExecution } },
        [PSCustomObject]@{ ID = 5; Opcion = "Chequeos de Hardening (Anti-PEAS)"; Action = { Invoke-PeasHardeningChecks } },
        [PSCustomObject]@{ ID = 6; Opcion = "Chequeos de Credenciales (Anti-Mimikatz)"; Action = { Invoke-CredentialHardeningChecks } },
        [PSCustomObject]@{ ID = 7; Opcion = "Auditar Eventos de Seguridad Criticos"; Action = { Invoke-CriticalEventsAudit } },
        [PSCustomObject]@{ ID = 8; Opcion = "Verificar Politicas de Seguridad Locales"; Action = { Invoke-LocalPolicyChecks } },
        [PSCustomObject]@{ ID = 0; Opcion = "Volver al Menu Principal"; Action = { return } }
    )
    while ($true) {
        $choice = Show-SubMenu -Title "Menu de Hardening y Correccion" -MenuOptions $menu
        $selected = $menu | Where-Object { $_.ID -eq $choice }
        if ($selected) {
            if ($selected.ID -eq 0) { break }
            Invoke-Command -ScriptBlock $selected.Action
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White; Read-Host | Out-Null
        } else { Write-Host "Opcion no valida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}

function Start-DomainReconMenu {
    Invoke-NotImplemented -FeatureName "Reconocimiento de Dominio"
    Write-Host "Esta categoria esta disenada para herramientas de Active Directory que han sido eliminadas en esta version." -ForegroundColor Cyan
}

function Start-AdvancedModulesMenu {
    $menu = @(
        [PSCustomObject]@{ ID = 1; Opcion = "Buscar Vulnerabilidades (Exploits Conocidos)"; Action = { Invoke-VulnerabilityScan } },
        [PSCustomObject]@{ ID = 2; Opcion = "Escaneo de Escalada de Privilegios (WinPEAS)"; Action = { Invoke-WinPEAS } },
        [PSCustomObject]@{ ID = 88; Opcion = "Activar Windows (Advertencia)"; Action = { Enable-WindowsActivation } },
        [PSCustomObject]@{ ID = 0; Opcion = "Volver al Menu Principal"; Action = { return } }
    )
    while ($true) {
        $choice = Show-SubMenu -Title "Menu de Modulos Avanzados" -MenuOptions $menu
        $selected = $menu | Where-Object { $_.ID -eq $choice }
        if ($selected) {
            if ($selected.ID -eq 0) { break }
            Invoke-Command -ScriptBlock $selected.Action
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White; Read-Host | Out-Null
        } else { Write-Host "Opcion no valida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}

function Start-UtilitiesMenu {
    $menu = @(
        [PSCustomObject]@{ ID = 1; Opcion = "Generar Reporte de Seguridad (JSON)"; Action = { Export-JsonSecurityReport } },
        [PSCustomObject]@{ ID = 2; Opcion = "Generar Reporte de Seguridad (HTML)"; Action = { Export-HtmlSecurityReport } },
        [PSCustomObject]@{ ID = 2; Opcion = "Obtener Informacion del Usuario y Sistema"; Action = { Get-UserInfo | Format-List } },
        [PSCustomObject]@{ ID = 88; Opcion = "Activar Windows (Advertencia)"; Action = { Enable-WindowsActivation } },
        [PSCustomObject]@{ ID = 3; Opcion = "Actualizar todas las aplicaciones (winget)"; Action = { Update-AllWingetApps } },
        [PSCustomObject]@{ ID = 4; Opcion = "Verificacion de Estado (ISO 27001)"; Action = { Test-ISO27001Status } },
        [PSCustomObject]@{ ID = 5; Opcion = "Limpiar Archivos Temporales del Sistema"; Action = { Remove-SysJunk } },
        [PSCustomObject]@{ ID = 99; Opcion = "Mensaje del Creador"; Action = { Write-Host "`nCopyright (c) 2023 h00kGh0st" -ForegroundColor Cyan } },
        [PSCustomObject]@{ ID = 0; Opcion = "Volver al Menu Principal"; Action = { return } }
    )
    while ($true) {
        $choice = Show-SubMenu -Title "Menu de Utilidades y Reportes" -MenuOptions $menu
        $selected = $menu | Where-Object { $_.ID -eq $choice }
        if ($selected) {
            if ($selected.ID -eq 0) { break }
            Invoke-Command -ScriptBlock $selected.Action
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White; Read-Host | Out-Null
        } else { Write-Host "Opcion no valida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}
function Stop-AllMonitoringJobs {
    Write-Host "`nDeteniendo todos los trabajos de monitoreo en segundo plano..." -ForegroundColor Yellow
    if ($global:ProcessMonitorJob) {
        Stop-Job -Job $global:ProcessMonitorJob
        Remove-Job -Job $global:ProcessMonitorJob
        $global:ProcessMonitorJob = $null
        Add-LogEntry -Message "Monitor de procesos detenido."
        Write-Host "[OK] Monitor de procesos detenido." -ForegroundColor Green
    }
    if ($global:NetworkMonitorJob) {
        Stop-Job -Job $global:NetworkMonitorJob
        Remove-Job -Job $global:NetworkMonitorJob
        $global:NetworkMonitorJob = $null
        Add-LogEntry -Message "Monitor de red detenido."
        Write-Host "[OK] Monitor de red detenido." -ForegroundColor Green
    }
}
function Start-MediTool {
    while ($true) {
        Clear-Host

        # Recibir y mostrar datos de los trabajos en segundo plano
        if ($global:ProcessMonitorJob) { Receive-Job -Job $global:ProcessMonitorJob }
        if ($global:NetworkMonitorJob) { Receive-Job -Job $global:NetworkMonitorJob }

        Write-Host "=============================================" -ForegroundColor Green
        Write-Host "=  3.2   Herramienta de Seguridad MediTool  =" -ForegroundColor Green
        Write-Host "=============================================" -ForegroundColor Green

        # Mostrar estado de los monitores
        $procStatus = if ($global:ProcessMonitorJob -and $global:ProcessMonitorJob.State -eq 'Running') { "[ACTIVO]" } else { "[INACTIVO]" }
        $netStatus = if ($global:NetworkMonitorJob -and $global:NetworkMonitorJob.State -eq 'Running') { "[ACTIVO]" } else { "[INACTIVO]" }
        Write-Host "Estado Monitores: Procesos $procStatus | Red $netStatus" -ForegroundColor Cyan
        Write-Host "Escribe 'stop' para detener todos los monitores." -ForegroundColor Gray

        Write-Host "Bienvenido a MediTool, tu solucion de seguridad Blue Team."
        Write-Host "Por favor, selecciona una categoria del menu:`n"

        $mainMenu = @(
            [PSCustomObject]@{ ID = 1; Opcion = "Auditoria y Analisis"; Action = { Start-AuditMenu } },
            [PSCustomObject]@{ ID = 2; Opcion = "Hardening y Correccion"; Action = { Start-HardeningMenu } },
            [PSCustomObject]@{ ID = 3; Opcion = "Utilidades y Reportes"; Action = { Start-UtilitiesMenu } },
            [PSCustomObject]@{ ID = 0; Opcion = "Salir"; Action = { Clear-TempFolder; Write-Host "`nSaliendo del programa. ¡Adios!" -ForegroundColor Green; exit } }
        )

        $mainMenu | ForEach-Object { Write-Host "  $($_.ID). $($_.Opcion)" }
        
        # Leer la tecla presionada sin esperar a Enter
        $selection = Read-Host "`nIngresa el numero de la categoria"

        # Comprobar si se quiere detener los monitores
        if ($selection -eq 'stop') {
            Stop-AllMonitoringJobs
            Read-Host "`nPresione Enter para continuar..." | Out-Null
            continue
        }

        $chosenOption = $mainMenu | Where-Object { $_.ID -eq $selection }

        if ($chosenOption) {
            if ($selection -eq '0') {
                Stop-AllMonitoringJobs
            }
            Invoke-Command -ScriptBlock $chosenOption.Action
        } else {
            Write-Host "`nOpcion no valida. Por favor, intente de nuevo." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}
#endregion
# --- Punto de Entrada del Script ---
# Aquí se inicia la herramienta.
Start-MediTool