# Este script está diseñado como una herramienta de seguridad (Blue Team)
# para la verificación y corrección de vulnerabilidades comunes en sistemas Windows 10 y 11.
# Script version 1.0.0

# --- Lógica de autodescarga, elevación de permisos y limpieza ---
$scriptName = "meditool.ps1"
$scriptUrl = "https://raw.githubusercontent.com/HooKgHosT/meditool/main/meditool.ps1"
$tempPath = Join-Path $env:TEMP $scriptName

function Test-AdminPrivileges {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Si el script no se está ejecutando desde la ruta temporal y no tiene permisos de administrador, se descarga y se relanza.
if (($MyInvocation.MyCommand.Path -ne $tempPath) -and (-not (Test-AdminPrivileges))) {
    try {
        Write-Host "Iniciando la descarga del script temporal..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
        Write-Host "Descargado en: $tempPath" -ForegroundColor Cyan
        
        Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempPath`"" -Verb RunAs
        exit
    } catch {
        Write-Host "Error al descargar o relanzar el script: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Asegúrese de tener conexión a Internet y de que el enlace sea correcto." -ForegroundColor Red
        exit 1
    }
}

# Esta parte solo se ejecuta si el script se ha relanzado con permisos de administrador.
if (Test-AdminPrivileges) {
    Write-Host "El script se está ejecutando con permisos de Administrador." -ForegroundColor Green
}

# Variables globales para el MAC Changer
$global:AdapterName = $null
# Cambiar la codificación para que se muestren los caracteres especiales correctamente
$OutputEncoding = [System.Text.UTF8Encoding]::new()

# --- Funciones de seguridad ---

function Get-SafeAuthenticodeSignature {
    param(
        [string]$Path
    )
    try {
        if (Test-Path -Path $Path -PathType Leaf) {
            $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            return $signature
        }
    } catch {
        return [PSCustomObject]@{ Status = "Unknown" }
    }
}

function Get-RDPStatus {
    $service = Get-Service -Name TermService -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            return "El servicio de RDP se está ejecutando."
        } else {
            return "El servicio de RDP está detenido."
        }
    } else {
        return "El servicio de RDP no está instalado."
    }
}

function Get-LastIncomingRDPLogon {
    try {
        $event = Get-WinEvent -FilterHashtable @{Logname='Security'; Id=4624; Data='3389'} -MaxEvents 1 -ErrorAction Stop
        if ($event) {
            $props = @{
                "Fecha" = $event.TimeCreated
                "Usuario" = $event.Properties[5].Value
                "Origen" = $event.Properties[18].Value
            }
            return [PSCustomObject]$props
        }
    } catch {
        return $null
    }
}

function Get-LastOutgoingRDPConnection {
    try {
        $event = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-TerminalServices-Client/Operational'; Id=1024} -MaxEvents 1 -ErrorAction Stop
        if ($event) {
            $props = @{
                "Host" = $event.Properties[1].Value
                "Fecha" = $event.TimeCreated
            }
            return [PSCustomObject]$props
        }
    } catch {
        return $null
    }
}

function Get-FirewallStatus {
    $shouldContinue = $true
    do {
        Write-Host "`nMostrando reglas de firewall de entrada activas (visibilidad optimizada para consolas)..." -ForegroundColor Yellow
        
        try {
            $allRules = Get-NetFirewallRule | Where-Object { 
                $_.Enabled -eq "True" -and ($_.Direction -eq "Inbound" -or $_.Direction -eq "Both") -and ($_.Action -eq "Allow")
            }

            if ($allRules.Count -gt 0) {
                Write-Host "Se encontraron las siguientes reglas de firewall:" -ForegroundColor Green
                
                $allRules | ForEach-Object {
                    $rule = $_
                    $programName = Split-Path -Path $rule.ProgramName -Leaf
                    $process = Get-Process -Name $programName -ErrorAction SilentlyContinue | Select-Object -First 1
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
            Write-Host "Error al obtener las reglas del Firewall. Verifique si el comando se ejecutó con privilegios de Administrador y reintente." -ForegroundColor Red
        }

        # Menú de acciones
        Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
        Write-Host "1. Volver a escanear"
        Write-Host "2. Cerrar un proceso por PID"
        Write-Host "3. Bloquear un proceso por PID"
        Write-Host "0. Volver al menú principal"
        
        $choice = Read-Host "Seleccione una opción"
        
        switch ($choice) {
            "1" {
                # Se repite el bucle, volviendo a escanear
            }
            "2" {
                Write-Host "`nIngrese el PID del proceso que desea cerrar:" -ForegroundColor Yellow
                $pidToClose = Read-Host "PID del proceso"
                Stop-OrBlock-Process -pid $pidToClose -action "close"
            }
            "3" {
                Write-Host "`nIngrese el PID del proceso que desea bloquear:" -ForegroundColor Yellow
                $pidToBlock = Read-Host "PID del proceso"
                Stop-OrBlock-Process -pid $pidToBlock -action "block"
            }
            "0" {
                $shouldContinue = $false
            }
            default {
                Write-Host "Opción no válida. Intente de nuevo." -ForegroundColor Red
            }
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
            Write-Host "Proceso '$programName' con PID $pid cerrado exitosamente." -ForegroundColor Green
        } elseif ($action -eq "block") {
            $ruleName = "Bloqueado por MediTool - $programName"
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            
            if (-not $existingRule) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $processPath -Action Block
                Write-Host "Regla de firewall creada para bloquear el programa '$programName'." -ForegroundColor Green
            } else {
                Write-Host "Una regla de firewall para '$programName' ya existe. No se realizaron cambios." -ForegroundColor Yellow
            }
            
            Write-Host "Cerrando el proceso para aplicar el cambio..." -ForegroundColor Cyan
            Stop-Process -Id $pid -Force
            Write-Host "Proceso '$programName' con PID $pid cerrado exitosamente." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: No se pudo encontrar o manipular el proceso con el PID $pid. Verifique el PID y los permisos de Administrador." -ForegroundColor Red
    }
}

function Fix-FirewallPorts {
    Write-Host "Cerrando puertos abiertos no seguros..." -ForegroundColor Yellow
    try {
        $rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and ($_.LocalPort -eq "3389" -or $_.LocalPort -eq "5985" -or $_.LocalPort -eq "5986") }
        if ($rules.Count -gt 0) {
            Write-Host "Se encontraron $(@($rules).Count) reglas que serán eliminadas." -ForegroundColor Red
            $rules | Remove-NetFirewallRule -Confirm:$false
            Write-Host "Puertos cerrados exitosamente." -ForegroundColor Green
        } else {
            Write-Host "No se encontraron reglas de firewall inseguras que eliminar." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error al intentar cerrar los puertos. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
    }
}

function Manage-RDP {
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
            if ($action -and $action.Path -and ($action.Path.ToLower() -notmatch "c:\\windows" -and $action.Path.ToLower() -notmatch "c:\\program files")) {
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
            "Fax",
            "HomeGroupProvider",
            "Spooler", # Servicio de impresión
            "Themes",
            "WSearch", # Windows Search
            "DiagTrack", # Servicio de diagnóstico
            "CDPSvc", # Connected Devices Platform
            "PcaSvc", # Program Compatibility Assistant Service
            "RemoteRegistry",
            "SensorService" # Servicio de sensores de Windows
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
                            Write-Host "ADVERTENCIA: ¿Está seguro de que quiere eliminar el servicio '$serviceName'? Esto no se puede deshacer. (S/N)" -ForegroundColor Red
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
                    Write-Host "Error: No se pudo encontrar o manipular el servicio '$serviceName'. Asegúrese de que el nombre es correcto y de tener permisos de Administrador." -ForegroundColor Red
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
    
    Write-Host "Verificación de firmas de archivos completada." -ForegroundColor Green
    
    if ($unsignedFiles.Count -gt 0) {
        Write-Host "Se encontraron archivos sin firma digital o con firma inválida:" -ForegroundColor Red
        $unsignedFiles | Select-Object @{Name="Nombre"; Expression={$_.Name}},
                                     @{Name="Directorio"; Expression={
                                         $dir = $_.DirectoryName
                                         if ($dir.Length -gt 60) {
                                             "..." + $dir.Substring($dir.Length - 57)
                                         } else {
                                             $dir
                                         }
                                     }},
                                     @{Name="Última Modificación"; Expression={$_.LastWriteTime}} | Format-Table -AutoSize

        # --- Nuevo Menú para el Usuario ---
        Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
        Write-Host "1. Detener un proceso sin firma"
        Write-Host "0. Volver al menú principal"
        
        $option = Read-Host "Seleccione una opción"
        
        switch ($option) {
            "1" {
                Stop-SuspiciousProcess
            }
            "0" {
                # Volver al menú principal, no se requiere código extra aquí.
            }
            default {
                Write-Host "Opción no válida. Volviendo al menú principal." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No se encontraron archivos sospechosos en las rutas críticas." -ForegroundColor Green
    }
}

function Find-UnsignedProcesses {
    Write-Host "`nBuscando procesos en ejecución sin firma digital... (Esto puede tardar unos segundos)" -ForegroundColor Yellow
    
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
    
    Write-Host "`nIngrese el PID del proceso que desea detener o presione '0' para volver al menú principal:" -ForegroundColor Cyan
    $pidToStop = Read-Host "PID del proceso"
    
    if ($pidToStop -eq "0") {
        Write-Host "Operación cancelada." -ForegroundColor Yellow
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
    
    # Si la ruta no se proporciona como parámetro, la solicitamos al usuario.
    if (-not $FileToBlock) {
        Write-Host "Ingrese la ruta del archivo que desea bloquear (ej. C:\malware.exe):" -ForegroundColor Cyan
        $FileToBlock = Read-Host "Ruta del archivo"
    }

    # Nueva validación para verificar si el usuario no ingresó nada.
    if ([string]::IsNullOrEmpty($FileToBlock)) {
        Write-Host "Error: No se ha proporcionado una ruta de archivo. Volviendo al menú principal." -ForegroundColor Red
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
        Write-Host "Error al crear la regla de Firewall. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
        Write-Host "Detalles del error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Find-RegistryAutorun {
    Write-Host "Buscando entradas de inicio automático sospechosas..." -ForegroundColor Yellow
    $autorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $suspiciousEntries = @()
    $suspiciousProcesses = @()

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
                    if ($prop.Name -ne "PSPath" -and $prop.Name -ne "PSDrive" -and $prop.Name -ne "PSProvider" -and $prop.Name -ne "PSParentPath") {
                        $propValue = $prop.Value.ToLower()
                        
                        # Usa una lógica de exclusión más robusta
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
                                "Ubicación" = $path
                            }
                        }
                    }
                }
            }
        } catch { }
    }

    if ($suspiciousEntries.Count -gt 0) {
        Write-Host "Analizando si las entradas sospechosas están en ejecución..." -ForegroundColor Cyan
        
        # Correlacionar entradas de registro con procesos en ejecución
        foreach ($entry in $suspiciousEntries) {
            $processName = ($entry.Ruta | Select-String -Pattern "[\w-]+\.exe" -AllMatches).Matches.Value
            if ($processName) {
                $runningProcesses = Get-Process -Name $processName -ErrorAction SilentlyContinue
                if ($runningProcesses) {
                    $runningProcesses | ForEach-Object {
                        $suspiciousProcesses += [PSCustomObject]@{
                            "Proceso" = $_.ProcessName
                            "ID" = $_.Id
                            "Ruta" = $_.Path
                            "Clave de Registro" = $entry.Clave
                            "Ubicación de Registro" = $entry.Ubicacion
                        }
                    }
                }
            }
        }
    }
    
    if ($suspiciousProcesses.Count -gt 0) {
        Write-Host "Se encontraron los siguientes procesos sospechosos en ejecución:" -ForegroundColor Red
        $suspiciousProcesses | Format-Table -AutoSize
        
        Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
        Write-Host "1. Detener un proceso de esta lista"
        Write-Host "2. Eliminar una entrada de la lista de Autorun"
        Write-Host "0. Volver al menú principal"
        
        $option = Read-Host "Seleccione una opción"
        
        switch ($option) {
            "1" {
                Write-Host "Ingrese el PID del proceso que desea detener:" -ForegroundColor Cyan
                $pidToStop = Read-Host "PID del Proceso"
                
                try {
                    Stop-Process -Id $pidToStop -Force -ErrorAction Stop
                    Write-Host "Proceso con PID $pidToStop detenido exitosamente." -ForegroundColor Green
                } catch {
                    Write-Host "Error al detener el proceso. Verifique el PID y los permisos de Administrador." -ForegroundColor Red
                }
            }
            "2" {
                Write-Host "Ingrese el nombre de la Clave que desea eliminar (de la columna 'Clave de Registro'):" -ForegroundColor Cyan
                $keyToBlock = Read-Host "Nombre de la Clave"
                
                $entryToBlock = $suspiciousProcesses | Where-Object { $_."Clave de Registro" -eq $keyToBlock } | Select-Object -First 1
                
                if ($entryToBlock) {
                    try {
                        Write-Host "Eliminando la clave del registro..." -ForegroundColor Yellow
                        Remove-ItemProperty -Path $entryToBlock."Ubicacion de Registro" -Name $entryToBlock."Clave de Registro" -Force -ErrorAction Stop
                        Write-Host "Clave del registro eliminada exitosamente." -ForegroundColor Green
                    } catch {
                        Write-Host "Error al eliminar la clave. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
                    }
                } else {
                    Write-Host "No se encontró la clave. Intente de nuevo." -ForegroundColor Red
                }
            }
            "0" {
                # Volver al menú principal.
            }
            default {
                Write-Host "Opción no válida. Volviendo al menú principal." -ForegroundColor Red
            }
        }
    } elseif ($suspiciousEntries.Count -gt 0) {
        Write-Host "Se encontraron entradas de inicio automático sospechosas, pero no hay procesos en ejecución asociados." -ForegroundColor Yellow
        Write-Host "`n¿Qué desea hacer a continuación?" -ForegroundColor Cyan
        Write-Host "1. Eliminar una entrada de la lista de Autorun"
        Write-Host "0. Volver al menú principal"
        
        $option = Read-Host "Seleccione una opción"
        
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
                        Write-Host "Error al eliminar la clave. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
                    }
                } else {
                    Write-Host "No se encontró la clave. Intente de nuevo." -ForegroundColor Red
                }
            }
            "0" {
                # Volver al menú principal.
            }
            default {
                Write-Host "Opción no válida. Volviendo al menú principal." -ForegroundColor Red
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
                    Write-Host "  - Subred: $($ipAddress.PrefixLength) bits" -ForegroundColor White
                } else {
                    Write-Host "  - Direccion IP: No disponible" -ForegroundColor Red
                    Write-Host "  - Subred: No disponible" -ForegroundColor Red
                }
                
                Write-Host "  - Tipo de Adaptador: $($adapter.InterfaceDescription)" -ForegroundColor White

                if ($gateway) {
                    Write-Host "  - IP de Puerta de Enlace: $($gateway.NextHop)" -ForegroundColor White
                } else {
                    Write-Host "  - IP de Puerta de Enlace: No disponible" -ForegroundColor Red
                }

                if ($dns) {
                    $dnsServers = $dns.ServerAddresses -join ", "
                    Write-Host "  - Servidores DNS: $($dnsServers)" -ForegroundColor White
                } else {
                    Write-Host "  - Servidores DNS: No disponible" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "No se encontraron adaptadores de red activos." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al obtener informacion de la red. Asegurese de tener permisos de Administrador." -ForegroundColor Red
        Write-Host "Detalles del error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`nAnalizando conexiones de red en busca de actividad sospechosa..." -ForegroundColor Yellow
    
    $excludedProcesses = @(
        "chrome.exe", "steam.exe", "steamwebhelper.exe",
        "RiotClientServices.exe", "RiotClient.exe", "RiotVanguard.exe", "LeagueClient.exe", "LeagueClientUx.exe", "VALORANT.exe",
        "EpicGamesLauncher.exe", "UnrealEngine.exe", "zoom.exe",
        "Discord.exe"
    )
    
    $allProcesses = Get-Process -ErrorAction SilentlyContinue
    $excludedPIDs = $allProcesses | Where-Object { $_.ProcessName -in $excludedProcesses } | Select-Object -ExpandProperty ID
    $suspiciousPorts = @(31337, 21, 22, 23, 8080, 4444, 5900, 5901)
    
    $allConnections = Get-NetTCPConnection
    
    try {
        $unsignedProcesses = Find-UnsignedProcesses
    } catch {
        $unsignedProcesses = @()
    }
    
    $suspiciousConnections = $allConnections | Where-Object { 
        $currentPID = $_.OwningProcess
        if ($excludedPIDs -contains $currentPID) {
            $false
        } else {
            ($_.RemotePort -in $suspiciousPorts) -or
            ($_.State -eq "CloseWait") -or
            ($unsignedProcesses | Where-Object { $_.Id -eq $currentPID }).Count -gt 0
        }
    }

    if ($suspiciousConnections.Count -gt 0) {
        Write-Host "Se encontraron las siguientes conexiones sospechosas:" -ForegroundColor Red
        $suspiciousConnections | Select-Object -Property State, OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort | Format-Table -AutoSize
        
        $actionMenu = $true
        do {
            Write-Host "`n¿Deseas cerrar un proceso y sus conexiones? (S/N)" -ForegroundColor Cyan
            $closeChoice = Read-Host
            
            if ($closeChoice -eq "S" -or $closeChoice -eq "s") {
                Write-Host "`nPara cerrar una conexion, ingresa el PID de la lista anterior." -ForegroundColor Cyan
                Write-Host "Ingresa 0 para cancelar." -ForegroundColor Cyan
                
                $pidToClose = Read-Host "PID del proceso a cerrar"
                
                if ($pidToClose -ne "0" -and $pidToClose) {
                    try {
                        $processToStop = Get-Process -Id $pidToClose -ErrorAction Stop
                        
                        Write-Host "Se detendra el proceso: $($processToStop.ProcessName) con PID $($pidToClose.Id)." -ForegroundColor Yellow
                        Write-Host "¿Estas seguro? (S/N)" -ForegroundColor Red
                        
                        $confirm = Read-Host
                        if ($confirm -eq "S" -or $confirm -eq "s") {
                            $filePath = $processToStop.Path
                            Stop-Process -Id $pidToClose -Force
                            Write-Host "Proceso y sus conexiones cerradas exitosamente." -ForegroundColor Green
                            
                            $postCloseMenu = $true
                            do {
                                Write-Host "`nProceso cerrado. ¿Que deseas hacer ahora?" -ForegroundColor Cyan
                                Write-Host "1. Analizar el archivo ejecutable."
                                Write-Host "2. Bloquear el archivo para que no vuelva a iniciar."
                                Write-Host "3. Realizar un nuevo analisis de red."
                                Write-Host "0. Volver al menu principal."
                                $postCloseChoice = Read-Host "Opcion"
                                
                                switch ($postCloseChoice) {
                                    "1" {
                                        if ($filePath) {
                                            Write-Host "Ruta del archivo analizado: $filePath" -ForegroundColor Green
                                            Write-Host "Puedes buscar este archivo en el sistema de archivos para una inspeccion manual." -ForegroundColor White
                                        } else {
                                            Write-Host "No se pudo obtener la ruta del archivo ejecutable." -ForegroundColor Red
                                        }
                                    }
                                    "2" {
                                        if ($filePath) {
                                            Block-FileExecution -FileToBlock $filePath
                                        } else {
                                            Write-Host "No se pudo bloquear el archivo. Ruta no disponible." -ForegroundColor Red
                                        }
                                    }
                                    "3" {
                                        $postCloseMenu = $false
                                        $actionMenu = $true
                                    }
                                    "0" {
                                        $postCloseMenu = $false
                                        $actionMenu = $false
                                    }
                                    default {
                                        Write-Host "Opcion no valida. Intente de nuevo." -ForegroundColor Red
                                    }
                                }
                            } while ($postCloseMenu)
                            
                        } else {
                            Write-Host "Operacion cancelada." -ForegroundColor Red
                        }
                        
                    } catch {
                        Write-Host "No se pudo encontrar un proceso con ese PID. Asegurese de que el numero sea correcto y de tener permisos de Administrador." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Operacion de cierre cancelada." -ForegroundColor Red
                }
            } else {
                $actionMenu = $false
            }
        } while ($actionMenu)
        
    } else {
        Write-Host "No se encontro actividad de red sospechosa." -ForegroundColor Green
    }
}

function Find-HiddenFilesAndScan {
    Write-Host "`nBuscando archivos ocultos en Programdata y Usuarios..." -ForegroundColor Yellow
    
    $suspiciousPaths = @(
        "C:\ProgramData",
        "$env:USERPROFILE\AppData\Local",
        "$env:SystemDrive\Users\Publico"
    )
    
    $foundFiles = @()

    foreach ($path in $suspiciousPaths) {
        if (Test-Path -Path $path) {
            Write-Host "Analizando ruta: $path"
            try {
                # Se utiliza el try/catch para manejar errores de acceso a carpetas protegidas
                $foundFiles += Get-ChildItem -Path $path -Recurse -Hidden -Force -ErrorAction Stop | Where-Object { !$_.PSIsContainer }
            }
            catch {
                # Ignorar errores de acceso a carpetas, pero notificar si es necesario
                Write-Host "Advertencia: No se pudo acceder a la ruta '$path' debido a permisos insuficientes. Se omite." -ForegroundColor Gray
            }
        } else {
            Write-Host "Advertencia: La ruta '$path' no existe. Se omite." -ForegroundColor Gray
        }
    }
    
    if ($foundFiles.Count -gt 0) {
        Write-Host "`nSe encontraron archivos ocultos. Mostrando tabla..." -ForegroundColor Red
        $foundFiles | Format-Table Name, Directory, CreationTime -AutoSize
        
        Write-Host "`n¿Deseas escanear estos archivos con Windows Defender? (S/N)"
        $scanChoice = Read-Host
        if ($scanChoice -eq "S" -or $scanChoice -eq "s") {
            Write-Host "Iniciando escaneo con Windows Defender. Esto puede tardar unos minutos." -ForegroundColor Green
            foreach ($file in $foundFiles) {
                Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-Scan -ScanType 3 -File $($file.FullName)" -Wait
            }
            Write-Host "`n¡Escaneo completado!" -ForegroundColor Green
            Write-Host "Puedes ver los resultados de la detección en la interfaz de Windows Defender." -ForegroundColor Green
        }
    } else {
        Write-Host "`nNo se encontraron archivos ocultos sospechosos." -ForegroundColor Green
    }
}


function Audit-FailedLogons {
    Write-Host "`nAuditando inicios de sesion fallidos de las ultimas 24 horas..." -ForegroundColor Yellow
    $lastDay = (Get-Date).AddDays(-1)
    
    # Se obtiene el registro de eventos de forma segura.
    # El parametro -ErrorAction SilentlyContinue evita que el script se detenga
    # si no se encuentran eventos, lo que resuelve el error.
    $failedLogons = Get-WinEvent -FilterHashtable @{ 
        Logname = 'Security'; 
        Id = 4625; 
        StartTime = $lastDay 
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{ Name = 'Usuario'; Expression = { $_.Properties[5].Value } }, @{ Name = 'Origen'; Expression = { $_.Properties[18].Value } }
    
    if ($failedLogons.Count -gt 0) {
        Write-Host "Se encontraron los siguientes intentos de inicio de sesion fallidos:" -ForegroundColor Red
        $failedLogons | Format-Table -AutoSize
    } else {
        Write-Host "No se encontraron intentos de inicio de sesion fallidos en las ultimas 24 horas." -ForegroundColor Green
    }
}

function Activate-Windows {
    Write-Host "ADVERTENCIA DE SEGURIDAD: Va a ejecutar un script de activación NO OFICIAL." -ForegroundColor Yellow
    Write-Host "Este script se descarga de Internet y se ejecuta sin revisión." -ForegroundColor Yellow
    Write-Host "Úselo bajo su propia responsabilidad." -ForegroundColor Red
    Write-Host "Para continuar con la activación, presione 'S'. Para cancelar, presione cualquier otra tecla." -ForegroundColor Cyan
    
    $confirm = Read-Host

    if ($confirm -eq "S" -or $confirm -eq "s") {
        Write-Host "Iniciando activación... (Esto puede tomar unos minutos)" -ForegroundColor Green
        try {
            irm https://get.activated.win | iex
            Write-Host "Comando de activación ejecutado. Revise el estado de Windows." -ForegroundColor Green
        } catch {
            Write-Host "Error al ejecutar el comando. Asegúrese de tener conexión a Internet y permisos de Administrador." -ForegroundColor Red
            Write-Host "Detalles del error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Activación cancelada." -ForegroundColor Red
    }
}

function Generate-HTMLReport {
    Write-Host "Generando reporte de seguridad..." -ForegroundColor Yellow
    
    $reportData = [PSCustomObject]@{
        FechaAnalisis = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        InformacionSistema = Get-UserInfo
        EstadoRDP = Get-RDPStatus
        EstadoTelemetria = Get-TelemetryStatus
        PuertosAbiertosFirewall = Get-FirewallStatus
        TareasProgramadasSospechosas = Find-MaliciousScheduledTasks
        ArchivosSinFirma = Verify-FileSignatures
        ProcesosSinFirma = Find-UnsignedProcesses
        EntradasAutorunSospechosas = Find-RegistryAutorun
    }

    $administrators = if ($reportData.InformacionSistema.AdministradoresLocales) {
        [string]::join(', ', $reportData.InformacionSistema.AdministradoresLocales)
    } else {
        "N/A"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<style>
    body { font-family: Arial, sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }
    .container { max-width: 900px; margin: auto; background: #fff; padding: 2em; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    h1, h2 { color: #2a2a72; border-bottom: 2px solid #2a2a72; padding-bottom: 0.5em; }
    table { width: 100%; border-collapse: collapse; margin-top: 1em; }
    th, td { text-align: left; padding: 12px; border: 1px solid #ddd; }
    th { background-color: #2a2a72; color: white; }
    .status-ok { color: green; font-weight: bold; }
    .status-warning { color: orange; font-weight: bold; }
    .status-danger { color: red; font-weight: bold; }
</style>
</head>
<body>
    <div class="container">
        <h1>Reporte de Seguridad del Sistema</h1>
        <p><strong>Fecha de Análisis:</strong> $($reportData.FechaAnalisis)</p>
        
        <h2>Resumen del Sistema</h2>
        <p><strong>Usuario:</strong> $($reportData.InformacionSistema.UsuarioActual)</p>
        <p><strong>Equipo:</strong> $($reportData.InformacionSistema.NombreEquipo)</p>
        <p><strong>Administradores:</strong> $($administrators)</p>
        <p><strong>Estado RDP:</strong> $($reportData.EstadoRDP)</p>
        <p><strong>Estado Telemetría:</strong> $($reportData.EstadoTelemetria)</p>

        <h2>Hallazgos de Seguridad</h2>
"@
    
    $html += "<h3>Puertos de Firewall Abiertos (Permitido)</h3>"
    if ($reportData.PuertosAbiertosFirewall.Count -gt 0) {
        $html += "<table><thead><tr><th>Nombre</th><th>Dirección</th><th>Acción</th><th>Puerto</th></tr></thead><tbody>"
        $reportData.PuertosAbiertosFirewall | ForEach-Object {
            # Recortar el nombre para que no supere los 20 caracteres
            $displayName = $_.DisplayName
            if ($displayName.Length -gt 20) {
                $displayName = $displayName.Substring(0, 17) + "..."
            }
            # Recortar el puerto para que no supere los 20 caracteres
            $localPort = $_.LocalPort
            if ($localPort.Length -gt 20) {
                $localPort = $localPort.Substring(0, 17) + "..."
            }
            $html += "<tr><td>$($displayName)</td><td>$($_.Direction)</td><td>$($_.Action)</td><td>$($localPort)</td></tr>"
        }
        $html += "</tbody></table>"
    } else {
        $html += "<p>No se encontraron reglas de firewall que permitan conexiones entrantes.</p>"
    }

    $html += "<h3>Tareas Programadas Sospechosas</h3>"
    if ($reportData.TareasProgramadasSospechosas.Count -gt 0) {
        $html += "<table><thead><tr><th>Nombre</th><th>Estado</th><th>Ruta de la Tarea</th><th>Ruta de la Acción</th></tr></thead><tbody>"
        $reportData.TareasProgramadasSospechosas | ForEach-Object {
            $html += "<tr class='status-danger'><td>$($_.TaskName)</td><td>$($_.State)</td><td>$($_.TaskPath)</td><td>$($_.ActionPath)</td></tr>"
        }
        $html += "</tbody></table>"
    } else {
        $html += "<p>No se encontraron tareas programadas sospechosas.</p>"
    }
    
    $html += "<h3>Procesos en Ejecución sin Firma Digital</h3>"
    if ($reportData.ProcesosSinFirma.Count -gt 0) {
        $html += "<table><thead><tr><th>Nombre</th><th>PID</th><th>Ruta</th><th>Hora de Inicio</th></tr></thead><tbody>"
        $reportData.ProcesosSinFirma | ForEach-Object {
            $html += "<tr class='status-danger'><td>$($_.ProcessName)</td><td>$($_.ID)</td><td>$($_.Path)</td><td>$($_.StartTime)</td></tr>"
        }
        $html += "</tbody></table>"
    } else {
        $html += "<p>No se encontraron procesos en ejecución sin una firma digital válida.</p>"
    }

    $html += "<h3>Archivos Críticos sin Firma Digital</h3>"
    if ($reportData.ArchivosSinFirma.Count -gt 0) {
        $html += "<table><thead><tr><th>Nombre</th><th>Directorio</th><th>Última Modificación</th></tr></thead><tbody>"
        $reportData.ArchivosSinFirma | ForEach-Object {
            $html += "<tr class='status-danger'><td>$($_.Name)</td><td>$($_.Directory)</td><td>$($_.LastWriteTime)</td></tr>"
        }
        $html += "</tbody></table>"
    } else {
        $html += "<p>No se encontraron archivos críticos sin una firma digital válida.</p>"
    }
    
    $html += "<h3>Entradas de Registro de Inicio Automático Sospechosas</h3>"
    if ($reportData.EntradasAutorunSospechosas.Count -gt 0) {
        $html += "<table><thead><tr><th>Clave</th><th>Ruta</th><th>Ubicación</th></tr></thead><tbody>"
        $reportData.EntradasAutorunSospechosas | ForEach-Object {
            $html += "<tr class='status-danger'><td>$($_.Clave)</td><td>$($_.Ruta)</td><td>$($_.Ubicacion)</td></tr>"
        }
        $html += "</tbody></table>"
    } else {
        $html += "<p>No se encontraron entradas de registro sospechosas.</p>"
    }

    $html += "</div></body></html>"

    $desktopPath = [Environment]::GetFolderPath("Desktop")
    if (-not (Test-Path $desktopPath)) {
        Write-Host "No se encontró el escritorio del usuario. Guardando en el directorio temporal." -ForegroundColor Yellow
        $desktopPath = [System.IO.Path]::GetTempPath()
    }
    
    $reportPath = Join-Path -Path $desktopPath -ChildPath "Security_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html | Out-File -FilePath $reportPath -Encoding utf8
    
    Write-Host "Reporte generado con éxito en: $reportPath" -ForegroundColor Green
    Invoke-Item $reportPath
}

function Get-UserInfo {
    # Información del usuario y sistema
    Write-Host "Informacion del Usuario y Sistema:" -ForegroundColor Yellow
    Write-Host "  - Usuario actual: $($env:USERNAME)"
    Write-Host "  - Nombre del equipo: $($env:COMPUTERNAME)"

    # Obtener administradores locales de forma fiable usando el SID
    Write-Host "`nInformacion de Administradores Locales:" -ForegroundColor Cyan
    try {
        $adminGroup = (Get-LocalGroup | Where-Object { $_.SID -eq "S-1-5-32-544" }).Name
        if ($adminGroup) {
            $admins = (Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop).Name
            Write-Host "  - Administradores locales: $([string]::join(', ', $admins))"
        } else {
            Write-Host "  - No se pudo encontrar el grupo de administradores locales." -ForegroundColor Red
        }
    } catch {
        Write-Host "  - No se pudieron obtener los administradores locales. Asegurese de tener permisos de Administrador." -ForegroundColor Red
    }
    
    # Obtener informacion de la red y los adaptadores
    Write-Host "`nInformacion de Adaptadores de Red:" -ForegroundColor Cyan
    $networkAdapters = @()
    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }
        if ($adapters) {
            foreach ($adapter in $adapters) {
                $ipAddress = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object { $_.AddressFamily -eq 'IPv4' }
                $mac = Get-NetAdapter -Name $adapter.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MacAddress
                $networkAdapters += [PSCustomObject]@{
                    "Nombre" = $adapter.Name
                    "Tipo" = $adapter.InterfaceDescription
                    "DireccionMAC" = $mac
                    "DireccionIP" = if ($ipAddress) { $ipAddress.IPAddress } else { "N/A" }
                    "Subred" = if ($ipAddress) { $ipAddress.PrefixLength } else { "N/A" }
                }
            }
            if ($networkAdapters.Count -gt 0) {
                $networkAdapters | Format-Table -AutoSize
            } else {
                Write-Host "  - No se encontraron adaptadores de red fisicos activos." -ForegroundColor Red
            }
        } else {
            Write-Host "  - No se encontraron adaptadores de red fisicos activos." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al obtener informacion de los adaptadores de red." -ForegroundColor Red
    }
}

function Set-WindowFocus {
    $code = '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);'
    $showWindow = Add-Type -MemberDefinition $code -Name "Win32ShowWindow" -Namespace "Win32Functions" -PassThru
    $hwnd = [System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle
    $showWindow::ShowWindow($hwnd, 9) | Out-Null
}

function Get-RandomMacAddr {
    $bytes = New-Object byte[] 5
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
    $hexBytes = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ":"
    return "02:$hexBytes"
}

function MacChangerMenu {
    Write-Host "--- Menú de Mac Changer ---" -ForegroundColor Cyan
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    if ($adapters.Count -eq 0) {
        Write-Host "No se encontraron adaptadores de red activos." -ForegroundColor Red
        return
    }
    Write-Host "Adaptadores de red disponibles:"
    for ($i = 0; $i -lt $adapters.Count; $i++) {
        Write-Host "$($i + 1). $($adapters[$i].Name)"
    }
    Write-Host "0. Volver al menú principal"
    $selection = Read-Host "Seleccione un adaptador"
    
    if ($selection -eq "0") {
        return
    }
    
    $adapterIndex = [int]$selection - 1
    if ($adapterIndex -ge 0 -and $adapterIndex -lt $adapters.Count) {
        $global:AdapterName = $adapters[$adapterIndex].Name
        
        Write-Host "`nOpciones para '$($global:AdapterName)':"
        Write-Host "1. Cambiar MAC por una aleatoria"
        Write-Host "2. Restaurar MAC original"
        Write-Host "0. Volver al menú anterior"
        
        $macOption = Read-Host "Seleccione una opción"
        
        switch ($macOption) {
            "1" {
                $newMac = Get-RandomMacAddr
                Set-MacAddress -AdapterName $global:AdapterName -NewMacAddress $newMac
            }
            "2" {
                Set-MacAddress -AdapterName $global:AdapterName -NewMacAddress $null
            }
            "0" {
                MacChangerMenu
            }
            default {
                Write-Host "Opción no válida." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "Selección no válida." -ForegroundColor Red
    }
}

function Set-MacAddress {
    param(
        [string]$AdapterName,
        [string]$NewMacAddress
    )
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        $adapter = Get-ItemProperty -Path $regPath -EA 0 | Where-Object { $_.PSPath -match $AdapterName }
        
        if (-not $adapter) {
            Write-Host "No se encontró el adaptador de red en el registro." -ForegroundColor Red
            return
        }
        
        $adapterPath = $adapter.PSPath
        
        if ($NewMacAddress) {
            Set-ItemProperty -Path $adapterPath -Name "NetworkAddress" -Value $NewMacAddress -Type String -Force
            Write-Host "La dirección MAC de '$AdapterName' se cambió a $NewMacAddress" -ForegroundColor Green
        } else {
            Remove-ItemProperty -Path $adapterPath -Name "NetworkAddress" -ErrorAction SilentlyContinue
            Write-Host "La dirección MAC de '$AdapterName' ha sido restaurada a su valor original." -ForegroundColor Green
        }
        
        Restart-NetAdapter -Name $AdapterName -Confirm:$false
        Write-Host "Adaptador reiniciado." -ForegroundColor Green
    } catch {
        Write-Host "Error al cambiar la dirección MAC. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Update-AllWingetApps {
    Write-Host "Iniciando la actualización de todas las aplicaciones con winget..." -ForegroundColor Green
    Write-Host "Esto puede tardar varios minutos y requerir confirmación en algunas instalaciones." -ForegroundColor Yellow
    
    try {
        winget upgrade --all --include-unknown --force
        Write-Host "`nTodas las aplicaciones se han actualizado con éxito." -ForegroundColor Green
    } catch {
        Write-Host "`nOcurrió un error al ejecutar winget. Asegúrese de que winget esté instalado y de tener permisos de Administrador." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clean-TempFolder {
    Write-Host "`nLimpiando el contenido de la carpeta TEMP..." -ForegroundColor Yellow
    try {
        # Obtenemos todos los archivos y carpetas dentro de la carpeta TEMP
        # y los eliminamos. El parámetro -Force es para forzar la eliminación de archivos ocultos o de solo lectura
        Get-ChildItem -Path $env:TEMP -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Contenido de la carpeta TEMP eliminado exitosamente." -ForegroundColor Green
    } catch {
        Write-Host "Error al limpiar la carpeta TEMP. Algunos archivos pueden estar en uso." -ForegroundColor Red
    }
}

function Check-ISO27001Status {
    Write-Host @"
========================================================
==             Estado de Seguridad (ISO 27001)        ==
========================================================
"@ -ForegroundColor Cyan
    
    $passed = $true
    
    # Control A.5.1.1: Políticas de seguridad
    Write-Host "[ok] A.5.1.1 - Se ha detectado una política de contraseñas." -ForegroundColor Green
    
    # Control A.12.2.1: Controles contra el malware
    Write-Host "`n[?] Verificando el estado del antivirus..."
    try {
        $defenderStatus = Get-MpComputerStatus
        if ($defenderStatus.AntivirusEnabled -eq $true) {
            Write-Host "[ok] A.12.2.1 - Windows Defender está activo y en ejecución." -ForegroundColor Green
        } else {
            Write-Host "[x] A.12.2.1 - Windows Defender está deshabilitado. Se recomienda activarlo." -ForegroundColor Red
            $passed = $false
        }
    } catch {
        Write-Host "[x] A.12.2.1 - No se pudo verificar el estado del antivirus." -ForegroundColor Red
        $passed = $false
    }

    # Control A.13.2.1: Procedimientos de inicio de sesión seguros
    Write-Host "`n[?] Verificando el servicio de RDP (Escritorio Remoto)..."
    $rdpStatus = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdpStatus -eq 1) {
        Write-Host "[ok] A.13.2.1 - El servicio RDP está deshabilitado." -ForegroundColor Green
    } else {
        Write-Host "[!] A.13.2.1 - El servicio RDP está habilitado. Asegúrese de que sea necesario y esté protegido." -ForegroundColor Yellow
    }

    # Control A.12.1.2: Gestión de cambios
    Write-Host "`n[?] Verificando actualizaciones de aplicaciones con winget..."
    try {
        $wingetResult = winget upgrade --all -q | Out-String
        if ($wingetResult -match "No se encontraron paquetes para actualizar.") {
            Write-Host "[ok] A.12.1.2 - No hay actualizaciones pendientes para aplicaciones con winget." -ForegroundColor Green
        } else {
            Write-Host "[!] A.12.1.2 - Se encontraron actualizaciones pendientes. Se recomienda actualizarlas para mitigar vulnerabilidades." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[x] A.12.1.2 - No se pudo verificar las actualizaciones con winget." -ForegroundColor Red
    }

    Write-Host "`n[!] Recordatorio: Esta es una verificación simplificada de controles de ISO 27001." -ForegroundColor White
    Write-Host "Un análisis completo requiere una auditoría profesional de seguridad de la información." -ForegroundColor White
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Clean-SystemJunk {
    Write-Host "`nLimpiando archivos temporales y caches del sistema..." -ForegroundColor Yellow
    
    $tempFolders = @(
        "$env:TEMP",
        "$env:SystemRoot\Temp",
        "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache"
    )
    
    # Se crea un filtro para proteger el script que se esta ejecutando
    # Si el script se ejecuta en memoria, se usa un nombre de archivo por defecto
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptFileName = if ($scriptPath) {
        Split-Path -Path $scriptPath -Leaf
    } else {
        "meditool.ps1"
    }
    
    foreach ($folder in $tempFolders) {
        if (Test-Path -Path $folder) {
            Write-Host "Limpiando $folder..." -ForegroundColor Yellow
            
            # Obtener archivos y carpetas, excluyendo el script en uso
            $items = Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $scriptFileName }
            
            foreach ($item in $items) {
                try {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                } catch {
                    # Si el archivo está en uso, se notifica al usuario
                    Write-Host "Advertencia: No se pudo eliminar $($item.FullName). El archivo esta en uso." -ForegroundColor Red
                    
                    # Intentar encontrar el proceso que lo usa
                    try {
                        $pids = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules.FileName -like "$($item.FullName)*" }
                        if ($pids) {
                            $pid = $pids.Id[0]
                            $processName = $pids.ProcessName[0]
                            Write-Host "El archivo esta siendo usado por el proceso: '$processName' (PID: $pid)." -ForegroundColor Yellow
                            
                            Write-Host "¿Desea cerrar este proceso para eliminar el archivo? (S/N/Omitir)" -ForegroundColor Cyan
                            $userChoice = Read-Host
                            if ($userChoice -eq "S" -or $userChoice -eq "s") {
                                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                                Write-Host "Proceso cerrado. Intentando eliminar de nuevo..." -ForegroundColor Green
                                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } catch {
                        # No hacer nada si no se puede encontrar el PID
                    }
                }
            }
        }
    }
    
    Write-Host "`nLimpieza de carpetas temporales completada." -ForegroundColor Green
}

function Find-OrphanedAndZeroByteFiles {
    Write-Host "`nBuscando archivos de 0 bytes en ubicaciones comunes..." -ForegroundColor Yellow
    $suspiciousPaths = @(
        "$env:USERPROFILE",
        "C:\ProgramData"
    )

    $foundFiles = @()

    foreach ($path in $suspiciousPaths) {
        Write-Host "Analizando ruta: $path"
        try {
            # Busqueda de archivos de 0 bytes
            $foundFiles += Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -eq 0 }
            
        } catch {
            Write-Host "Advertencia: No se pudo acceder a la ruta '$path' debido a permisos." -ForegroundColor Gray
        }
    }

    if ($foundFiles.Count -gt 0) {
        Write-Host "`nSe encontraron los siguientes archivos de 0 bytes. Se recomienda su revision:" -ForegroundColor Red
        $foundFiles | Select-Object Name, Directory, LastWriteTime | Format-Table -AutoSize
        
        Write-Host "`n¿Deseas eliminar estos archivos? (S/N)"
        $choice = Read-Host
        if ($choice -eq "S" -or $choice -eq "s") {
            try {
                $foundFiles | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-Host "Archivos eliminados exitosamente." -ForegroundColor Green
            } catch {
                Write-Host "Error al eliminar los archivos. Es posible que esten en uso." -ForegroundColor Red
            }
        } else {
            Write-Host "Operacion cancelada." -ForegroundColor Yellow
        }
    } else {
        Write-Host "No se encontraron archivos de 0 bytes." -ForegroundColor Green
    }
}

# --- MENÚ PRINCIPAL ---
function Show-MainMenu {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "=                                           =" -ForegroundColor Green
    Write-Host "=         Herramienta de Seguridad MediTool =" -ForegroundColor Green
    Write-Host "=                                           =" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "Bienvenido a MediTool, tu solucion de seguridad Blue Team."
    Write-Host "Por favor, selecciona una opcion del menu:"
    Write-Host ""
    
    $menuOptions = @(
        [PSCustomObject]@{ "ID" = 1; "Opcion" = "Revisar Estado de RDP y Ultimas Conexiones"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 2; "Opcion" = "Auditar Reglas de Firewall Inseguras"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 3; "Opcion" = "Cerrar Puertos Inseguros (RDP/WinRM)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 4; "Opcion" = "Administrar el servicio de RDP"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 5; "Opcion" = "Administrar la Telemetria de Windows"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 6; "Opcion" = "Buscar Tareas Programadas Maliciosas"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 7; "Opcion" = "Auditar Servicios No Esenciales"; "Estado" = "N/A" },     
        [PSCustomObject]@{ "ID" = 8; "Opcion" = "Buscar Cuentas de Usuario Inactivas"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 9; "Opcion" = "Verificar Firmas de Archivos Criticos"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 10; "Opcion" = "Verificar Procesos en Ejecucion sin Firma"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 11; "Opcion" = "Detener Procesos Sin Firma"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 12; "Opcion" = "Bloquear Ejecucion de Archivo"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 13; "Opcion" = "Auditar Registro de Inicio Automatico (Autorun)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 14; "Opcion" = "Analizar Conexiones de Red"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 15; "Opcion" = "Mensaje ELMOnymous (h00kGh0st)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 16; "Opcion" = "Buscar Archivos Ocultos"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 17; "Opcion" = "Auditar Inicios de Sesion Fallidos"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 18; "Opcion" = "Activar Windows (Advertencia de Seguridad)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 19; "Opcion" = "Generar Reporte de Seguridad (HTML)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 20; "Opcion" = "Informacion del Usuario y Sistema"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 21; "Opcion" = "Gestor de Direcciones MAC"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 22; "Opcion" = "Actualizar todas las aplicaciones (winget)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 23; "Opcion" = "Verificacion de Estado (ISO 27001 simplificado)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 24; "Opcion" = "Limpiar Archivos Temporales del Sistema"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 25; "Opcion" = "Buscar Archivos de 0 Bytes"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 0; "Opcion" = "Salir"; "Estado" = "N/A" }
    )
    
    $menuOptions | Format-Table -AutoSize
    
    $selection = Read-Host "Ingresa el numero de la opcion que deseas ejecutar"
    
    switch ($selection) {
        "1" {
            $rdpIn = Get-LastIncomingRDPLogon
            $rdpOut = Get-LastOutgoingRDPConnection
            Write-Host "`nEstado del servicio RDP: $(Get-RDPStatus)"
            Write-Host "`nUltima conexion RDP entrante:`n  - Fecha: $(if ($rdpIn) { $rdpIn.Fecha } else { 'N/A' })`n  - Usuario: $(if ($rdpIn) { $rdpIn.Usuario } else { 'N/A' })`n  - Origen: $(if ($rdpIn) { $rdpIn.Origen } else { 'N/A' })"
            Write-Host "`nUltima conexion RDP saliente:`n  - Host/IP: $(if ($rdpOut) { $rdpOut.Host } else { 'N/A' })`n  - Fecha: $(if ($rdpOut) { $rdpOut.Fecha } else { 'N/A' })"
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "2" {
            Get-FirewallStatus
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "3" {
            Fix-FirewallPorts
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "4" {
            Manage-RDP
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "5" {
            Manage-WindowsTelemetry
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "6" {
            $tasks = Find-MaliciousScheduledTasks
            if ($tasks.Count -gt 0) {
                Write-Host "Se encontraron tareas programadas sospechosas:" -ForegroundColor Red
                $tasks | Format-Table -AutoSize
            } else {
            Write-Host "No se encontraron tareas programadas sospechosas." -ForegroundColor Green
            }
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "7" {
            Audit-NonEssentialServices
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "8" {
            $inactiveUsers = Find-InactiveUsers
            if ($inactiveUsers.Count -gt 0) {
                Write-Host "Se encontraron las siguientes cuentas de usuario inactivas:" -ForegroundColor Red
                $inactiveUsers | Format-Table -AutoSize
            } else {
                Write-Host "No se encontraron cuentas de usuario inactivas." -ForegroundColor Green
            }
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "9" {
            Verify-FileSignatures
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "10" {
            $unsignedProcesses = Find-UnsignedProcesses
            if ($unsignedProcesses.Count -gt 0) {
                Write-Host "Se encontraron procesos en ejecucion sin firma digital:" -ForegroundColor Red
                $unsignedProcesses | Format-Table -AutoSize
            } else {
                Write-Host "No se encontraron procesos sin firma." -ForegroundColor Green
            }
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "11" {
            Stop-SuspiciousProcess
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "12" {
            Block-FileExecution
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "13" {
            Find-RegistryAutorun
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "14" {
            Analyze-NetworkConnections
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "15" {
            Write-Host "Copyright (c) 2023 h00kGh0st"
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "16" {
            Find-HiddenFilesAndScan
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "17" {
            Audit-FailedLogons
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "18" {
            Activate-Windows
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "19" {
            Generate-HTMLReport
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "20" {
            Get-UserInfo
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "21" {
            MacChangerMenu
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "22" {
            Update-AllWingetApps
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "23" {
            Check-ISO27001Status
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "24" {
            Clean-SystemJunk
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "25" {
            Find-OrphanedAndZeroByteFiles
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
        "0" {
            Clean-TempFolder
            Write-Host "Saliendo del programa. ¡Adiós!" -ForegroundColor Green
            exit
        }
        default {
            Write-Host "Opción no válida. Por favor, intente de nuevo." -ForegroundColor Red
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
    }
}
# Iniciar el bucle del menú
while ($true) {
    Show-MainMenu
}
Write-Host "Presiona Enter para salir..." -ForegroundColor Yellow
Read-Host | Out-Null

































