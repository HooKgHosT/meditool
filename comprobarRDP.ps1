# Este script está diseñado como una herramienta de seguridad (Blue Team)
# para la verificación y corrección de vulnerabilidades comunes en sistemas Windows 10 y 11.
# --- AUTODESCARGA Y RELANZAMIENTO ---
$scriptUrl = "https://raw.githubusercontent.com/HooKgHosT/meditool/main/comprobarRDP.ps1"
$tempPath  = Join-Path $env:TEMP "comprobarRDP.ps1"

# Si el script aún no está ejecutándose desde TEMP → descargarlo y relanzar
if (-not $MyInvocation.MyCommand.Path -or ($MyInvocation.MyCommand.Path -ne $tempPath)) {
    try {
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempPath -UseBasicParsing
        Write-Host "Descargado en: $tempPath" -ForegroundColor Cyan

        # Relanzar como admin
        Start-Process powershell -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$tempPath`"" -Verb RunAs
        exit
    } catch {
        Write-Host "Error al descargar/ejecutar: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}


Write-Host "
%	  ______   ______  ______  ______   ______  ______  ______    ______  
%	 | |__| | | |__| || |__| || |__| | | |__| || |__| || |__| |  | |__| | 
% 	 |  ()  | |  ()  ||  ()  ||  ()  | |  ()  ||  ()  ||  ()  |  |  ()  | 
% 	 |______| |______||______||______| |______||______||______|  |______| 
% 	  ______  				                      ______
% 	 | |__| |   _  _   ____  ___   __  _____  ____   ____  _     | |__| | 
% 	 |  ()  |  | \/ | |____||_  \ \__/|_ _ _| / _  \/ _  \| |    |  ()  | 
% 	 |______|  | || | | _|  | |  | ||   | |  | |.| | |.|  | |    |______| 
% 	  ______   | || | |__|_ |_|  | ||   | |  | |_| | |_|  | |_    ______
% 	 | |__| |  |_||_| |____||___/ /__\  |_|   \____/\____/|___|  | |__| | 
% 	 | () | |			                             |  ()  | 
% 	 |______|			                             |______| 
% 	  ______   ______  ______  ______   ______  ______  ______    ______  
% 	 | |__| | | |__| || |__| || |__| | | |__| || |__| || |__| |  | |__| | 
% 	 |  ()  | |  ()  ||  ()  ||  ()  | |  ()  ||  ()  ||  ()  |  |  ()  | 
% 	 |______| |______||______||______| |______||______||______|  |______|
" -ForegroundColor Cyan
# Variables globales para el MAC Changer
$global:AdapterName = $null
# Cambiar la codificación para que se muestren las tildes y la ñ correctamente
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
    Write-Host "`nAnalizando reglas de firewall. Esto puede tardar unos segundos..." -ForegroundColor Yellow
    
    # Lista de nombres de programas comunes a excluir.
    $excludedPrograms = @(
        "*chrome.exe*", "*firefox.exe*", "*msedge.exe*",
        "*steam.exe*", "*steamwebhelper.exe*", "*Discord.exe*", 
        "*EpicGamesLauncher.exe*", "*UnrealEngine.exe*", "*zoom.exe*",
        "*RiotClientServices.exe*", "*RiotClient.exe*", "*RiotVanguard.exe*", "*LeagueClient.exe*", "*LeagueClientUx.exe*", "*VALORANT.exe*"
    )

    try {
        $allRules = Get-NetFirewallRule | Where-Object { 
            $_.Enabled -eq "True" -and ($_.Direction -eq "Inbound" -or $_.Direction -eq "Both") -and ($_.Action -eq "Allow" -or $_.Action -eq "AllowInbound") 
        }

        $filteredRules = $allRules | Where-Object {
            $programName = $_.ProgramName.ToLower()
            $isExcluded = $false
            foreach ($excluded in $excludedPrograms) {
                if ($programName -like $excluded) {
                    $isExcluded = $true
                    break
                }
            }
            -not $isExcluded
        }
        
        return $filteredRules | Select-Object DisplayName, Direction, Action, Profile, Protocol, LocalPort
    } catch {
        Write-Host "Error al obtener las reglas del Firewall. Asegúrese de tener permisos de Administrador." -ForegroundColor Red
        return $null
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
    $rdpOption = Read-Host "Seleccione una opcion: "
    
    try {
        if ($rdpOption -eq "1") {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
            Write-Host "RDP habilitado.`n" -ForegroundColor Green
        } elseif ($rdpOption -eq "2") {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
            Write-Host "RDP deshabilitado.`n" -ForegroundColor Yellow
        } elseif ($rdpOption -eq "0") {
            # Quita la llamada a Show-MainMenu aquí. El bucle principal se encargará de esto.
        } else {
            Write-Host "Opcion no valida." -ForegroundColor Red
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
            # Quita la llamada a Show-MainMenu aquí. El bucle principal se encargará de esto.
        } else {
            Write-Host "Opcion no válida." -ForegroundColor Red
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

function Analyze-PasswordPolicy {
    Write-Host ""
    $output = net accounts 2>$null

    $results = @()
    $policy = @{
        "Longitud Minima" = "N/A"
        "Complejidad" = "N/A"
        "Historial" = "N/A"
        "Antiguedad Máxima (días)" = "N/A"
    }

    foreach ($line in $output) {
        if ($line -like "*Longitud minima de la password*") {
            $policy."Longitud Minima" = ($line.Split(':')[1]).Trim()
        }
        if ($line -like "*La complejidad de la password*") {
            $policy."Complejidad" = ($line.Split(':')[1]).Trim()
        }
        if ($line -like "*Se guardan passwords en el historial*") {
            $policy."Historial" = ($line.Split(':')[1]).Trim()
        }
        if ($line -like "*Antiguedad maxima de la password*") {
            $policy."Antiguedad Maxima (dias)" = ($line.Split(':')[1]).Trim()
        }
    }

    $policy.Keys | ForEach-Object {
        $results += [PSCustomObject]@{
            "Parametro de Seguridad" = $_
            "Valor" = $policy[$_]
        }
    }
    
    return $results
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
    Write-Host "`nBusqueda de procesos sin firma completada." -ForegroundColor Green
    return $unsignedProcesses
}

function Stop-SuspiciousProcess {
    $processes = Find-UnsignedProcesses
    if ($processes.Count -eq 0) {
        Write-Host "No se encontraron procesos sin firma para detener." -ForegroundColor Green
        return
    }
    $processes | Select-Object ProcessName, Path, ID, StartTime | Format-Table -AutoSize
    Write-Host "Ingrese el PID del proceso que desea detener:" -ForegroundColor Cyan
    $pidToStop = Read-Host "PID"
    try {
        Stop-Process -Id $pidToStop -Force
        Write-Host "Proceso con PID $pidToStop detenido exitosamente." -ForegroundColor Green
    } catch {
        Write-Host "No se pudo detener el proceso. Verifique el PID y los permisos de Administrador." -ForegroundColor Red
    }
}
function Block-FileExecution {
    param(
        [string]$FileToBlock
    )
    
    if (-not $FileToBlock) {
        Write-Host "Ingrese la ruta del archivo que desea bloquear (ej. C:\malware.exe):" -ForegroundColor Cyan
        $FileToBlock = Read-Host "Ruta del archivo"
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
        Write-Host "Error al crear la regla de Firewall. Asegurese de tener permisos de Administrador." -ForegroundColor Red
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
        "discord", "spotify", "riotgames", "steam", "epicgames", "zoom", "microsoft", "google"
    )

    foreach ($path in $autorunPaths) {
        try {
            $keys = Get-ItemProperty -Path $path
            $keys.PSObject.Properties | ForEach-Object {
                $prop = $_
                if ($prop.Name -ne "PSPath" -and $prop.Name -ne "PSDrive" -and $prop.Name -ne "PSProvider" -and $prop.Name -ne "PSParentPath") {
                    $propValue = $prop.Value.ToLower()
                    
                    if ($propValue -and $propValue -notmatch "c:\\windows" -and $propValue -notmatch "c:\\program files" -and $propValue -notmatch "c:\\programdata") {
                        $isExcluded = $false
                        foreach ($excluded in $excludedPrograms) {
                            if ($propValue -like "*$($excluded)*") {
                                $isExcluded = $true
                                break
                            }
                        }

                        if (-not $isExcluded) {
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
                            "Ubicacion de Registro" = $entry.Ubicacion
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
    Write-Host "`nAnalizando conexiones de red en busca de actividad sospechosa..." -ForegroundColor Yellow
    
    $excludedProcesses = @(
        "chrome.exe", "steam.exe", "steamwebhelper.exe",
        "RiotClientServices.exe", "RiotClient.exe", "RiotVanguard.exe", "LeagueClient.exe", "LeagueClientUx.exe", "VALORANT.exe",
        "EpicGamesLauncher.exe", "UnrealEngine.exe", "Discord.exe"
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
                Write-Host "`nPara cerrar una conexión, ingresa el PID de la lista anterior." -ForegroundColor Cyan
                Write-Host "Ingresa 0 para cancelar." -ForegroundColor Cyan
                
                $pidToClose = Read-Host "PID del proceso a cerrar"
                
                if ($pidToClose -ne "0" -and $pidToClose) {
                    try {
                        $processToStop = Get-Process -Id $pidToClose -ErrorAction Stop
                        
                        Write-Host "Se detendra el proceso: $($processToStop.ProcessName) con PID $($pidToStop.Id)." -ForegroundColor Yellow
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
        "$env:SystemDrive\Users\P[u|ú]blic[o|a]"
    )
    
    $foundFiles = @()

    foreach ($path in $suspiciousPaths) {
        if (Test-Path -Path $path) {
            Write-Host "Analizando ruta: $path"
            $foundFiles += Get-ChildItem -Path $path -Recurse -Hidden -Force -ErrorAction SilentlyContinue | Where-Object { !$_.PSIsContainer }
        } else {
            Write-Host "Advertencia: La ruta '$path' no existe o no se puede acceder a ella. Se omite." -ForegroundColor Gray
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
            Write-Host "Puedes ver los resultados de la deteccion en la interfaz de Windows Defender." -ForegroundColor Green
        }
    } else {
        Write-Host "`nNo se encontraron archivos ocultos sospechosos." -ForegroundColor Green
    }
}

function Audit-FailedLogons {
    Write-Host "`nAuditando inicios de sesion fallidos de las últimas 24 horas..." -ForegroundColor Yellow
    $lastDay = (Get-Date).AddDays(-1)
    
    try {
        $failedLogons = Get-WinEvent -FilterHashtable @{ Logname = 'Security'; Id = 4625; StartTime = $lastDay } -ErrorAction Stop
        
        if ($failedLogons) {
            Write-Host "Se encontraron los siguientes intentos de inicio de sesion fallidos:" -ForegroundColor Red
            $failedLogons | Select-Object TimeCreated, @{ Name = 'Usuario'; Expression = { $_.Properties[5].Value } }, @{ Name = 'Origen'; Expression = { $_.Properties[18].Value } } |
            Format-Table -AutoSize
        } else {
            Write-Host "No se encontraron intentos de inicio de sesion fallidos en las últimas 24 horas." -ForegroundColor Green
        }
        
    } catch {
        if ($_.Exception.Message -like "*No se encontraron eventos*") {
            Write-Host "No se encontraron intentos de inicio de sesión fallidos en las últimas 24 horas." -ForegroundColor Green
        } else {
            Write-Host "Error al acceder al registro de eventos. Detalles del error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Asegurese de ejecutar el script como Administrador." -ForegroundColor Red
        }
    }
}

function Activate-Windows {
    Write-Host "ADVERTENCIA DE SEGURIDAD: Vas a ejecutar un script de activación NO OFICIAL." -ForegroundColor Yellow
    Write-Host "Este script se descarga de Internet y se ejecuta sin revisión." -ForegroundColor Yellow
    Write-Host "Úsalo bajo tu propia responsabilidad." -ForegroundColor Red
    Write-Host "Para continuar con la activación, presiona 'S'. Para cancelar, presiona cualquier otra tecla." -ForegroundColor Cyan
    
    $confirm = Read-Host

    if ($confirm -eq "S" -or $confirm -eq "s") {
        Write-Host "Iniciando activación... (Esto puede tomar unos minutos)" -ForegroundColor Green
        try {
            irm https://get.activated.win | iex
            Write-Host "Comando de activación ejecutado. Revisa el estado de Windows." -ForegroundColor Green
        } catch {
            Write-Host "Error al ejecutar el comando. Asegúrate de tener conexión a Internet y permisos de Administrador." -ForegroundColor Red
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
    $adminMembers = @()
    try {
        # Intenta obtener los miembros del grupo de administradores.
        $adminMembers = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name
    } catch {
        # Si ocurre un error, $adminMembers se quedará como un array vacío.
    }
    
    $info = [PSCustomObject]@{
        "UsuarioActual" = $env:USERNAME
        "NombreEquipo" = $env:COMPUTERNAME
        "AdministradoresLocales" = $adminMembers
    }
    return $info
}

function Set-WindowFocus {
    $code = '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);'
    $showWindow = Add-Type -MemberDefinition $code -Name "Win32ShowWindow" -Namespace "Win32Functions" -PassThru
    $hwnd = [System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle
    $showWindow::ShowWindow($hwnd, 9) | Out-Null
}

function Test-AdminPrivileges {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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
        Write-Host "`nOcurrió un error al ejecutar winget. Asegúrate de que winget esté instalado y de tener permisos de Administrador." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- MENÚ PRINCIPAL ---
function Show-MainMenu {
    Clear-Host
Write-Host "
%	  ______   ______  ______  ______   ______  ______  ______    ______  
%	 | |__| | | |__| || |__| || |__| | | |__| || |__| || |__| |  | |__| | 
% 	 |  ()  | |  ()  ||  ()  ||  ()  | |  ()  ||  ()  ||  ()  |  |  ()  | 
% 	 |______| |______||______||______| |______||______||______|  |______| 
% 	  ______  				                      ______
% 	 | |__| |   _  _   ____  ___   __  _____  ____   ____  _     | |__| | 
% 	 |  ()  |  | \/ | |____||_  \ \__/|_ _ _| / _  \/ _  \| |    |  ()  | 
% 	 |______|  | || | | _|  | |  | ||   | |  | |.| | |.|  | |    |______| 
% 	  ______   | || | |__|_ |_|  | ||   | |  | |_| | |_|  | |_    ______
% 	 | |__| |  |_||_| |____||___/ /__\  |_|   \____/\____/|___|  | |__| | 
% 	 | () | |			                             |  ()  | 
% 	 |______|			                             |______| 
% 	  ______   ______  ______  ______   ______  ______  ______    ______  
% 	 | |__| | | |__| || |__| || |__| | | |__| || |__| || |__| |  | |__| | 
% 	 |  ()  | |  ()  ||  ()  ||  ()  | |  ()  ||  ()  ||  ()  |  |  ()  | 
% 	 |______| |______||______||______| |______||______||______|  |______|
" -ForegroundColor Cyan
    Write-Host "Bienvenido a MediTool, tu solución de seguridad Blue Team."
    Write-Host "Por favor, selecciona una opción del menú:"
    Write-Host ""
    
    $menuOptions = @(
        [PSCustomObject]@{ "ID" = 1; "Opcion" = "Revisar Estado de RDP y Últimas Conexiones"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 2; "Opcion" = "Auditar Reglas de Firewall Inseguras"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 3; "Opcion" = "Cerrar Puertos Inseguros (RDP/WinRM)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 4; "Opcion" = "Administrar el servicio de RDP"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 5; "Opcion" = "Administrar la Telemetría de Windows"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 6; "Opcion" = "Buscar Tareas Programadas Maliciosas"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 7; "Opcion" = "Analizar Política de Contraseñas"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 8; "Opcion" = "Buscar Cuentas de Usuario Inactivas"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 9; "Opcion" = "Verificar Firmas de Archivos Críticos"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 10; "Opcion" = "Verificar Procesos en Ejecución sin Firma"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 11; "Opcion" = "Detener Procesos Sin Firma"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 12; "Opcion" = "Bloquear Ejecución de Archivo"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 13; "Opcion" = "Auditar Registro de Inicio Automático (Autorun)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 14; "Opcion" = "Analizar Conexiones de Red"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 15; "Opcion" = "Cerrar Conexiones Sospechosas"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 16; "Opcion" = "Buscar Archivos Ocultos"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 17; "Opcion" = "Auditar Inicios de Sesión Fallidos"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 18; "Opcion" = "Activar Windows (Advertencia de Seguridad)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 19; "Opcion" = "Generar Reporte de Seguridad (HTML)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 20; "Opcion" = "Información del Usuario y Sistema"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 21; "Opcion" = "Gestor de Direcciones MAC"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 22; "Opcion" = "Actualizar todas las aplicaciones (winget)"; "Estado" = "N/A" },
        [PSCustomObject]@{ "ID" = 0; "Opcion" = "Salir"; "Estado" = "N/A" }
    )
    
    $menuOptions | Format-Table -AutoSize
    
    $selection = Read-Host "Ingresa el número de la opción que deseas ejecutar"
    
    switch ($selection) {
        "1" {
            $rdpIn = Get-LastIncomingRDPLogon
            $rdpOut = Get-LastOutgoingRDPConnection
            Write-Host "`nEstado del servicio RDP: $(Get-RDPStatus)"
            Write-Host "`nUltima conexión RDP entrante:`n  - Fecha: $(if ($rdpIn) { $rdpIn.Fecha } else { 'N/A' })`n  - Usuario: $(if ($rdpIn) { $rdpIn.Usuario } else { 'N/A' })`n  - Origen: $(if ($rdpIn) { $rdpIn.Origen } else { 'N/A' })"
            Write-Host "`nUltima conexión RDP saliente:`n  - Host/IP: $(if ($rdpOut) { $rdpOut.Host } else { 'N/A' })`n  - Fecha: $(if ($rdpOut) { $rdpOut.Fecha } else { 'N/A' })"
        }
        "2" {
            $rules = Get-FirewallStatus
            if ($rules) { 
                Write-Host "Reglas de Firewall que permiten conexiones entrantes:" -ForegroundColor Yellow
                $rules | Format-Table -AutoSize 
            } else { 
                Write-Host "No se encontraron reglas de Firewall que permitan conexiones entrantes." -ForegroundColor Green 
            }
        }
        "3" {
            Fix-FirewallPorts
        }
        "4" {
            Manage-RDP
        }
        "5" {
            Manage-WindowsTelemetry
        }
        "6" {
            $tasks = Find-MaliciousScheduledTasks
            if ($tasks.Count -gt 0) { 
                Write-Host "Se encontraron tareas programadas sospechosas:" -ForegroundColor Red
                $tasks | Format-Table -AutoSize 
            } else { 
                Write-Host "No se encontraron tareas programadas sospechosas." -ForegroundColor Green 
            }
        }
        "7" {
            Write-Host "`nAnalizando la politica de contraseñas..." -ForegroundColor Yellow
            $policy = Analyze-PasswordPolicy
            if ($policy) {
                $policy | Format-Table -AutoSize
            } else {
                Write-Host "No se pudo obtener la politica de contraseñas. Asegurese de tener permisos." -ForegroundColor Red
            }
        }
        "8" {
            $inactiveUsers = Find-InactiveUsers
            if ($inactiveUsers.Count -gt 0) { 
                Write-Host "Se encontraron las siguientes cuentas de usuario inactivas:" -ForegroundColor Red
                $inactiveUsers | Format-Table -AutoSize 
            } else { 
                Write-Host "No se encontraron cuentas de usuario inactivas." -ForegroundColor Green 
            }
        }
        "9" {
            Verify-FileSignatures
        }
        "10" {
            $unsignedProcesses = Find-UnsignedProcesses
            if ($unsignedProcesses.Count -gt 0) { 
                Write-Host "Se encontraron procesos en ejecución sin firma digital:" -ForegroundColor Red
                $unsignedProcesses | Format-Table -AutoSize 
            } else { 
                Write-Host "No se encontraron procesos sin firma." -ForegroundColor Green 
            }
        }
        "11" {
            Stop-SuspiciousProcess
        }
        "12" {
            Block-FileExecution
        }
        "13" {
            Find-RegistryAutorun
        }
        "14" {
            Analyze-NetworkConnections
        }
        "15" {
            # Se ha eliminado la llamada a Close-SuspiciousConnection ya que está dentro de Analyze-NetworkConnections
            Write-Host "La opción para cerrar conexiones se encuentra dentro del análisis de red (opción 14)."
        }
        "16" {
            Find-HiddenFilesAndScan
        }
        "17" {
            Audit-FailedLogons
        }
        "18" {
            Activate-Windows
        }
        "19" {
            Generate-HTMLReport
        }
        "20" {
            $info = Get-UserInfo
            Write-Host "`nInformacion del Usuario y Sistema:" -ForegroundColor Yellow
            Write-Host "  - Usuario actual: $($info.UsuarioActual)"
            Write-Host "  - Nombre del equipo: $($info.NombreEquipo)"
            
            $administrators = if ($info.AdministradoresLocales.Count -gt 0) {
                [string]::join(', ', $info.AdministradoresLocales)
            } else {
                "No se pudieron obtener los administradores locales."
            }
            Write-Host "  - Administradores locales: $administrators"
        }
        "21" {
            MacChangerMenu
        }
        "22" {
            Update-AllWingetApps
        }
        "0" {
            exit
        }
        default {
            Write-Host "Opcion no valida. Por favor, intente de nuevo." -ForegroundColor Red
        }
    }

    Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
    Read-Host | Out-Null
}

# Iniciar el bucle del menú
while ($true) {
    Show-MainMenu
}

Write-Host "Presiona Enter para salir..." -ForegroundColor Yellow
Read-Host | Out-Null
