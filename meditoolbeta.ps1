# Este script está diseñado como una herramienta de seguridad (Blue Team)
# para la verificación y corrección de vulnerabilidades comunes en sistemas Windows 10 y 11.
# Script version 1.0.0

# --- Lógica de autodescarga, elevación de permisos y limpieza ---
# Este script esta disenado como una herramienta de seguridad (Blue Team)
# para la verificacion y correccion de vulnerabilidades comunes en sistemas Windows 10 y 11.
# Script version 1.0.0

# --- Logica de autodescarga, elevacion de permisos y limpieza ---
$scriptName = "meditool.ps1"
$scriptUrl = "https://raw.githubusercontent.com/HooKgHosT/meditool/main/meditool.ps1"
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
    Write-Host "El script se esta ejecutando con permisos de Administrador." -ForegroundColor Green
    } else {
        Write-Host "El script no se esta ejecutando con permisos de Administrador. Se le solicita que se ejecute con permisos de Administrador." -ForegroundColor Red
        Write-Host "Asegurese de tener conexion a Internet y de que el enlace sea correcto." -ForegroundColor Red
        exit 1
}
# Al finalizar, se elimina el script temporal.

# Cambiar la codificación para que se muestren los caracteres especiales correctamente
$OutputEncoding = [System.Text.UTF8Encoding]::new()
# Configurar la política de ejecución para permitir la ejecución del script

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
        $fix = Read-Host "¿Desea deshabilitar esta politica ahora? (S/N)"; if ($fix -eq 's') { Set-ItemProperty -Path $keyPath1 -Name "AlwaysInstallated" -Value 0; Set-ItemProperty -Path $keyPath2 -Name "AlwaysInstallated" -Value 0; Write-Host "[CORREGIDO] La politica ha sido deshabilitada." -ForegroundColor Green; Add-LogEntry -Message "Politica 'AlwaysInstallated' deshabilitada." }
    } else { Write-Host "[OK] La politica 'AlwaysInstallated' no esta activada." -ForegroundColor Green }
    Write-Host "`n[3] Listando credenciales guardadas por el sistema (cmdkey)..." -ForegroundColor Yellow
    $credList = cmdkey /list
    if ($credList -match "Currently stored credentials") { Write-Host "[INFO] Se encontraron las siguientes credenciales guardadas. Revise si son necesarias:" -ForegroundColor Cyan; $credList } 
    else { Write-Host "[OK] No se encontraron credenciales guardadas con cmdkey." -ForegroundColor Green }
    Write-Host "`n[4] Verificando si el motor de PowerShell v2 esta habilitado..." -ForegroundColor Yellow
    $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
    if ($psv2Feature.State -eq 'Enabled') { Write-Host "[ADVERTENCIA] El motor de PowerShell v2 esta HABILITADO. Se recomienda deshabilitarlo." -ForegroundColor Yellow } 
    else { Write-Host "[OK] El motor de PowerShell v2 esta deshabilitado." -ForegroundColor Green }
    Write-Host "`n--- Chequeo de Hardening finalizado ---" -ForegroundColor Cyan
}
function Invoke-CredentialHardeningChecks {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    function New-HardeningResult {
        param(
            [string]$CheckName,
            [string]$Mitigation,
            [ValidateSet('PROTEGIDO', 'VULNERABLE', 'ERROR', 'INFO')]
            [string]$Status,
            [string]$Details,
            [scriptblock]$FixScript,
            [scriptblock]$CheckScript
        )
        return [PSCustomObject]@{
            CheckName   = $CheckName
            Mitigation  = $Mitigation
            Status      = $Status
            Details     = $Details
            FixScript   = $FixScript
            CheckScript = $CheckScript
        }
    }

    function Test-CredentialGuardPrerequisites {
        Write-Host "`n--- Comprobando requisitos para Credential Guard ---" -ForegroundColor Cyan
        $remediationSteps = [System.Collections.Generic.List[string]]::new()
        $allMet = $true

        # 1. Comprobacion de Sistema Operativo
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        if ($osInfo.Caption -notlike "*Enterprise*" -and $osInfo.Caption -notlike "*Education*") {
            $remediationSteps.Add("El SO debe ser Windows Enterprise/Education. Version actual: $($osInfo.Caption)")
            $allMet = $false
        }

        # 2. Comprobacion de Secure Boot
        try {
            if (-not (Confirm-SecureBootUEFI -ErrorAction Stop)) {
                $remediationSteps.Add("Secure Boot esta deshabilitado. Debes activarlo en la BIOS/UEFI.")
                $allMet = $false
            }
        } catch {
            $remediationSteps.Add("No se pudo confirmar el estado de Secure Boot (el sistema puede no ser UEFI).")
            $allMet = $false
        }

        # 3. Comprobacion de Virtualizacion en Firmware
        $vbs = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'Root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue)
        if (-not $vbs.VirtualizationBasedSecurityStatus -eq 2) {
             if (-not ((Get-ComputerInfo).HyperVRequirementDataVirtualizationEnabledInFirmware)) {
                $remediationSteps.Add("La virtualizacion de CPU (Intel VT-x / AMD-V) esta deshabilitada en la BIOS/UEFI.")
                $allMet = $false
             }
        }

        if ($allMet) {
            Write-Host "[OK] Tu sistema CUMPLE con los requisitos para Credential Guard." -ForegroundColor Green
            Write-Host "Puedes habilitarlo usando la Politica de Grupo (GPO) en:" -ForegroundColor White
            Write-Host "  'Configuracion del Equipo > Plantillas Administrativas > Sistema > Device Guard'" -ForegroundColor White
            Write-Host "  Habilitando 'Activar seguridad basada en virtualizacion' y seleccionando 'Credential Guard'." -ForegroundColor White
            Write-Host "Se requerira un reinicio." -ForegroundColor White
        } else {
            Write-Host "[AVISO] Tu sistema NO CUMPLE con todos los requisitos para Credential Guard." -ForegroundColor Yellow
            Write-Host "Pasos para corregirlo manualmente:" -ForegroundColor White
            $remediationSteps | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
        }
    }

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $wdigestKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $rebootNeeded = $false

    $fixLsa = {
        try {
            if (-not (Test-Path $lsaKey)) { New-Item -Path $lsaKey -Force | Out-Null }
            Set-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value 1 -Type DWord -Force -ErrorAction Stop
            Write-Host "[OK] La proteccion LSA ha sido HABILITADA." -ForegroundColor Green
            $script:rebootNeeded = $true
        } catch { Write-Error "No se pudo habilitar la proteccion LSA. Ejecuta el script como Administrador." }
    }
    try {
        $lsaProtection = Get-ItemPropertyValue -Path $lsaKey -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if ($lsaProtection -eq 1) {
            $results.Add((New-HardeningResult 'Proteccion LSA' 'RunAsPPL' 'PROTEGIDO' 'LSA esta protegido. Mimikatz no puede acceder directamente a lsass.exe.'))
        } else {
            $results.Add((New-HardeningResult 'Proteccion LSA' 'RunAsPPL' 'VULNERABLE' 'La proteccion LSA esta DESHABILITADA o mal configurada.' -FixScript $fixLsa))
        }
    }
    catch {
        $results.Add((New-HardeningResult 'Proteccion LSA' 'RunAsPPL' 'VULNERABLE' 'La proteccion LSA esta DESHABILITADA (la clave de registro no existe).' -FixScript $fixLsa))
    }

    $fixWdigest = {
        try {
            if (-not (Test-Path $wdigestKey)) { New-Item -Path $wdigestKey -Force | Out-Null }
            Set-ItemProperty -Path $wdigestKey -Name "UseLogonCredential" -Value 0 -Type DWord -Force -ErrorAction Stop
            Write-Host "[OK] WDigest ha sido DESHABILITADO." -ForegroundColor Green
        } catch { Write-Error "No se pudo deshabilitar WDigest. Ejecuta el script como Administrador." }
    }
    try {
        $wdigestValue = Get-ItemPropertyValue -Path $wdigestKey -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        if ($wdigestValue -eq 0) {
            $results.Add((New-HardeningResult 'WDigest' 'UseLogonCredential' 'PROTEGIDO' 'WDigest esta deshabilitado. Las contrasenas no se guardan en texto plano.'))
        } else {
            $results.Add((New-HardeningResult 'WDigest' 'UseLogonCredential' 'VULNERABLE' 'WDigest esta HABILITADO. Las contrasenas pueden ser extraidas de la memoria.' -FixScript $fixWdigest))
        }
    }
    catch {
        $results.Add((New-HardeningResult 'WDigest' 'UseLogonCredential' 'PROTEGIDO' 'WDigest esta deshabilitado (la clave de registro no existe).'))
    }

    try {
        $guard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'Root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        if ($guard.SecurityServicesRunning -contains 1) {
            $results.Add((New-HardeningResult 'Credential Guard' 'Virtual Secure Mode' 'PROTEGIDO' 'Credential Guard esta activo, aislando las credenciales del sistema.'))
        } else {
            $results.Add((New-HardeningResult 'Credential Guard' 'Virtual Secure Mode' 'VULNERABLE' 'No esta en ejecucion.' -CheckScript ${function:Test-CredentialGuardPrerequisites}))
        }
    }
    catch {
        $results.Add((New-HardeningResult 'Credential Guard' 'Virtual Secure Mode' 'INFO' 'No se pudo determinar el estado (puede no ser soportado por el hardware/SO).'))
    }

    Write-Host @"
================================================================
== Chequeos de Hardening contra Robo de Credenciales (Mimikatz) ==
================================================================
"@ -ForegroundColor Cyan
    
    $header = ("{0,-12} {1,-20} {2,-20} {3}" -f "Resultado", "Comprobacion", "Mitigacion", "Detalles")
    Write-Host $header -ForegroundColor White
    Write-Host ("-" * ($header.Length + 30)) -ForegroundColor White

    foreach ($item in $results) {
        $status = $item.Status
        $color = switch ($status) {
            'PROTEGIDO' { 'Green' }
            'VULNERABLE'{ 'Red' }
            'INFO'      { 'Cyan' }
            'ERROR'     { 'Magenta' }
            default     { 'White' }
        }
        $statusText = "[$status]"
        $line = "{0,-12} {1,-20} {2,-20} {3}" -f $statusText, $item.CheckName, $item.Mitigation, $item.Details
        Write-Host -Object $line -ForegroundColor $color
    }

    $vulnerabilitiesToFix = @($results | Where-Object { $_.Status -eq 'VULNERABLE' })
    if ($vulnerabilitiesToFix.Count -gt 0) {
        Write-Host "`nSe han encontrado vulnerabilidades." -ForegroundColor Yellow
        
        foreach ($vuln in $vulnerabilitiesToFix) {
            if ($vuln.FixScript) {
                $prompt = "?Deseas corregir la vulnerabilidad '$($vuln.CheckName)'? (S/N)"
                $response = Read-Host -Prompt $prompt
                if ($response -match '^[sS]$') {
                    if ($PSCmdlet.ShouldProcess("el sistema para habilitar '$($vuln.CheckName)'", "Corregir Vulnerabilidad")) {
                        Invoke-Command -ScriptBlock $vuln.FixScript
                    }
                }
            }
            elseif ($vuln.CheckScript) {
                $prompt = "?Deseas comprobar si se puede solucionar la vulnerabilidad '$($vuln.CheckName)'? (S/N)"
                $response = Read-Host -Prompt $prompt
                if ($response -match '^[sS]$') {
                    Invoke-Command -ScriptBlock $vuln.CheckScript
                }
            }
        }
    }

    if ($rebootNeeded) {
        Write-Host "`n[IMPORTANTE] Uno o mas cambios requieren un reinicio del sistema para ser aplicados completamente." -ForegroundColor Yellow
    }
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
function Get-FirewallStatus {
    Write-Host "`nMostrando reglas de firewall de entrada activas (visibilidad optimizada para consolas)..." -ForegroundColor Yellow
    
    try {
        $allRules = Get-NetFirewallRule | Where-Object { 
            $_.Enabled -eq "True" -and ($_.Direction -eq "Inbound" -or $_.Direction -eq "Both") -and ($_.Action -eq "Allow") -and -not [string]::IsNullOrEmpty($_.ProgramName)
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
        Write-Host "Error al obtener las reglas del Firewall. Verifique si el comando se ejecuto con privilegios de Administrador y reintente." -ForegroundColor Red
    }
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
            Write-Host "Se encontraron $(@($rules).Count) reglas que seran eliminadas." -ForegroundColor Red
            $rules | Remove-NetFirewallRule -Confirm:$false
            Write-Host "Puertos cerrados exitosamente." -ForegroundColor Green
        } else {
            Write-Host "No se encontraron reglas de firewall inseguras que eliminar." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error al intentar cerrar los puertos. Asegurese de tener permisos de Administrador." -ForegroundColor Red
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
    $shouldContinue = $true
    do {
        Write-Host "`nAuditoria de servicios no esenciales en ejecucion..." -ForegroundColor Yellow
        
        # Lista de servicios no esenciales que comunmente se pueden deshabilitar
        $nonEssentialServices = @(
            "Fax",
            "HomeGroupProvider",
            "Spooler", # Servicio de impresion
            "Themes",
            "WSearch", # Windows Search
            "DiagTrack", # Servicio de diagnostico
            "CDPSvc", # Connected Devices Platform
            "PcaSvc", # Program Compatibility Assistant Service
            "RemoteRegistry",
            "SensorService" # Servicio de sensores de Windows
        )
    
        $runningNonEssential = Get-Service -Name $nonEssentialServices -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }

        if ($runningNonEssential.Count -gt 0) {
            Write-Host "Se encontraron los siguientes servicios no esenciales en ejecucion:" -ForegroundColor Red
            $runningNonEssential | Select-Object Name, DisplayName, Status | Format-Table -AutoSize
            Write-Host "`n¿Que desea hacer a continuacion?" -ForegroundColor Cyan
            Write-Host "1. Gestionar un servicio de esta lista"
            Write-Host "0. Volver al menu principal"
            
            $choice = Read-Host "Seleccione una opcion"
            
            if ($choice -eq "1") {
                Write-Host "`nOpciones para gestionar un servicio:" -ForegroundColor Cyan
                Write-Host "1. Iniciar servicio"
                Write-Host "2. Detener servicio"
                Write-Host "3. Deshabilitar servicio"
                Write-Host "4. Eliminar servicio (Advertencia)"
                $serviceAction = Read-Host "Seleccione una accion"
                
                $serviceName = Read-Host "Ingrese el nombre del servicio que desea gestionar"
                
                try {
                    $service = Get-Service -Name $serviceName -ErrorAction Stop
                    
                    switch ($serviceAction) {
                        "1" {
                            if ($service.Status -ne "Running") {
                                Start-Service -InputObject $service -ErrorAction Stop
                                Write-Host "Servicio '$serviceName' iniciado exitosamente." -ForegroundColor Green
                            } else {
                                Write-Host "El servicio '$serviceName' ya esta en ejecucion." -ForegroundColor Yellow
                            }
                        }
                        "2" {
                            if ($service.Status -ne "Stopped") {
                                Stop-Service -InputObject $service -ErrorAction Stop
                                Write-Host "Servicio '$serviceName' detenido exitosamente." -ForegroundColor Green
                            } else {
                                Write-Host "El servicio '$serviceName' ya esta detenido." -ForegroundColor Yellow
                            }
                        }
                        "3" {
                            Set-Service -InputObject $service -StartupType Disabled -ErrorAction Stop
                            Write-Host "Servicio '$serviceName' deshabilitado exitosamente." -ForegroundColor Green
                        }
                        "4" {
                            Write-Host "ADVERTENCIA: ¿Esta seguro de que quiere eliminar el servicio '$serviceName'? Esto no se puede deshacer. (S/N)" -ForegroundColor Red
                            $confirm = Read-Host
                            if ($confirm -eq "S" -or $confirm -eq "s") {
                                Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" | Invoke-CimMethod -MethodName Delete -ErrorAction Stop
                                Write-Host "Servicio '$serviceName' eliminado exitosamente." -ForegroundColor Green
                            } else {
                                Write-Host "Operacion de eliminacion cancelada." -ForegroundColor Yellow
                            }
                        }
                        default {
                            Write-Host "Accion no valida." -ForegroundColor Red
                        }
                    }
                } catch {
                    Write-Host "Error: No se pudo encontrar o manipular el servicio '$serviceName'. Asegurese de que el nombre es correcto y de tener permisos de Administrador." -ForegroundColor Red
                }
            } elseif ($choice -eq "0") {
                $shouldContinue = $false
            } else {
                Write-Host "Opcion no valida. Intente de nuevo." -ForegroundColor Red
            }
        } else {
            Write-Host "No se encontraron servicios no esenciales en ejecucion." -ForegroundColor Green
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
            $shouldContinue = $false
        }
    } while ($shouldContinue)
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
    
    if ($suspiciousProcesses.Count -gt 0) {
        Write-Host "Se encontraron los siguientes procesos sospechosos en ejecucion:" -ForegroundColor Red
        $suspiciousProcesses | Format-Table -AutoSize
        
        Write-Host "`n¿Que desea hacer a continuacion?" -ForegroundColor Cyan
        Write-Host "1. Detener un proceso de esta lista"
        Write-Host "2. Eliminar una entrada de la lista de Autorun"
        Write-Host "0. Volver al menu principal"
        
        $option = Read-Host "Seleccione una opcion"
        
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
                        Write-Host "Error al eliminar la clave. Asegurese de tener permisos de Administrador." -ForegroundColor Red
                    }
                } else {
                    Write-Host "No se encontro la clave. Intente de nuevo." -ForegroundColor Red
                }
            }
            "0" {
                # Volver al menu principal.
            }
            default {
                Write-Host "Opcion no valida. Volviendo al menu principal." -ForegroundColor Red
            }
        }
    } elseif ($suspiciousEntries.Count -gt 0) {
        Write-Host "Se encontraron entradas de inicio automatico sospechosas, pero no hay procesos en ejecucion asociados." -ForegroundColor Yellow
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
                    Write-Host "No se encontro la clave. Intente de nuevo." -ForegroundColor Red
                }
            }
            "0" {
                # Volver al menu principal.
            }
            default {
                Write-Host "Opcion no valida. Volviendo al menu principal." -ForegroundColor Red
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
function Start-MediTool {
    while ($true) {
        Clear-Host
        Set-WindowFocus

        Write-Host "=============================================" -ForegroundColor Green
        Write-Host "=  1.5   Herramienta de Seguridad MediTool  =" -ForegroundColor Green
        Write-Host "=============================================" -ForegroundColor Green
        Write-Host "Bienvenido a MediTool, tu solucion de seguridad Blue Team."
        Write-Host "Por favor, selecciona una opcion del menu:`n"

        $menuOptions = @(
            [PSCustomObject]@{ ID = 1; Opcion = "Revisar Estado de RDP y Ultimas Conexiones" },
            [PSCustomObject]@{ ID = 2; Opcion = "Auditar Reglas de Firewall Inseguras" },
            [PSCustomObject]@{ ID = 3; Opcion = "Cerrar Puertos Inseguros (RDP/WinRM)" },
            [PSCustomObject]@{ ID = 4; Opcion = "Administrar el servicio de RDP" },
            [PSCustomObject]@{ ID = 5; Opcion = "Administrar la Telemetria de Windows" },
            [PSCustomObject]@{ ID = 6; Opcion = "Buscar Tareas Programadas Maliciosas" },
            [PSCustomObject]@{ ID = 7; Opcion = "Auditar Servicios No Esenciales" },
            [PSCustomObject]@{ ID = 8; Opcion = "Buscar Cuentas de Usuario Inactivas" },
            [PSCustomObject]@{ ID = 9; Opcion = "Verificar Firmas de Archivos Criticos" },
            [PSCustomObject]@{ ID = 10; Opcion = "Verificar Procesos en Ejecucion sin Firma" },
            [PSCustomObject]@{ ID = 11; Opcion = "Detener Procesos Sin Firma" },
            [PSCustomObject]@{ ID = 12; Opcion = "Bloquear Ejecucion de Archivo" },
            [PSCustomObject]@{ ID = 13; Opcion = "Auditar Registro de Inicio Automatico (Autorun)" },
            [PSCustomObject]@{ ID = 14; Opcion = "Analizar Conexiones de Red" },
            [PSCustomObject]@{ ID = 15; Opcion = "Buscar Archivos de 0 Bytes" },
            [PSCustomObject]@{ ID = 16; Opcion = "Buscar Archivos Ocultos" },
            [PSCustomObject]@{ ID = 17; Opcion = "Auditar Inicios de Sesion Fallidos" },
            [PSCustomObject]@{ ID = 18; Opcion = "Generar Reporte de Seguridad (JSON)" },
            [PSCustomObject]@{ ID = 19; Opcion = "Informacion del Usuario y Sistema" },
            [PSCustomObject]@{ ID = 20; Opcion = "Actualizar todas las aplicaciones (winget)" },
            [PSCustomObject]@{ ID = 21; Opcion = "Verificacion de Estado (ISO 27001 simplificado)" },
            [PSCustomObject]@{ ID = 22; Opcion = "Limpiar Archivos Temporales del Sistema" },
            [PSCustomObject]@{ ID = 23; Opcion = "Chequeos de Hardening (PEAS)" },
            [PSCustomObject]@{ ID = 24; Opcion = "Chequeos de Credenciales (Mimikatz)" },
            [PSCustomObject]@{ ID = 25; Opcion = "Auditar Eventos de Seguridad Criticos" },
            [PSCustomObject]@{ ID = 26; Opcion = "Verificar Politicas de Seguridad Locales" },
            [PSCustomObject]@{ ID = 88; Opcion = "Activar Windows (Advertencia de Seguridad)" },
            [PSCustomObject]@{ ID = 99; Opcion = "Mensaje del Creador (h00kGh0st)" },
            [PSCustomObject]@{ ID = 0; Opcion = "Salir" }
        )

        $menuOptions | Format-Table -Property @{ Expression = "ID"; Width = 4 }, Opcion -HideTableHeaders
        $selection = Read-Host "Ingresa el numero de la opcion que deseas ejecutar"

        switch ($selection) {
            '1' { Get-RdpStatusAndConnections }
            '2' { Get-FirewallStatus }
            '3' { Repair-FirewallPorts }
            '4' { Set-RDP }
            '5' { Manage-WindowsTelemetry }
            '6' { Show-Findings -Title "Tareas Programadas Sospechosas" -Data (Find-MaliciousScheduledTasks) -NotFoundMessage "No se encontraron tareas programadas sospechosas." }
            '7' { Audit-NonEssentialServices }
            '8' { Show-Findings -Title "Cuentas de Usuario Inactivas" -Data (Find-InactiveUsers) -NotFoundMessage "No se encontraron cuentas de usuario inactivas." }
            '9' { Verify-FileSignatures }
            '10' { Show-Findings -Title "Procesos en Ejecucion sin Firma Digital" -Data (Find-UnsignedProcesses) -NotFoundMessage "No se encontraron procesos sin firma." }
            '11' { Stop-SuspiciousProcess }
            '12' { Block-FileExecution }
            '13' { Find-RegistryAutorun }
            '14' { Test-NetworkConnections }
            '15' { Find-OrphanedAndZeroByteFiles }
            '16' { Find-HiddenFilesAndScan }
            '17' { Get-FailedLogons | Format-Table -AutoSize }
            '18' { Export-JsonSecurityReport }
            '19' { Get-UserInfo | Format-List }
            '20' { Update-AllWingetApps }
            '21' {
                Write-Host "'nTesteando ISO 27001 Status... (Demora un poquito)" -ForegroundColor Cyan
                Test-ISO27001Status 
            }
            '22' { Remove-SysJunk }
            '23' { Invoke-PeasHardeningChecks }
            '24' { Invoke-CredentialHardeningChecks }
            '25' { Invoke-CriticalEventsAudit }
            '26' { Invoke-LocalPolicyChecks  }
            '88' { Enable-WindowsActivation }
            '99' { Write-Host "`nCopyright (c) 2023 h00kGh0st" -ForegroundColor Cyan }
            '0' {
                Clear-TempFolder
                Write-Host "`nSaliendo del programa. ¡Adios!" -ForegroundColor Green
                exit
            }
            default {
                Write-Host "`nOpcion no valida. Por favor, intente de nuevo." -ForegroundColor Red
            }
        }

        if ($selection -ne '0') {
            Write-Host "`nPresione Enter para continuar..." -ForegroundColor White
            Read-Host | Out-Null
        }
    }
}
#endregion

# --- Punto de Entrada del Script ---
# Aquí se inicia la herramienta.
Start-MediTool