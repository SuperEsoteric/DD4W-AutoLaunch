# Launches Docker Desktop as a scheduled task.
$DockerScriptName="LaunchDockerDesktop"
$DockerScriptFile="LaunchDockerDesktop.ps1"
$ScriptRepository="$([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))\PowerShellScript-DockerAdmin"
$DockerScriptLogLocation="$ScriptRepository\$ScriptName\Logs"
$DockerScriptLogName="$DockerScriptName_$((Get-Date).tostring("yyyy-MM-dd")).log"
$i = 0


function CheckServiceState ($ServNameCheck) {
    $a = $(Get-Service $ServNameCheck | Where-Object {$_.Status -EQ "Running"})
    return $a
}

function StartServ ($DispName, $ServName) {
    if (([string]::IsNullOrEmpty($(CheckServiceState($ServName)))) -and ($i -lt 50)) {
        Start-Service -Name $ServName ##-Verb runAs
        StartServ $DispName $ServName
        $i = $i++
    }
    $i = 0
    $b = $(Get-Service $ServName).Status
    return $b
}

# Check launching user is member of Hyper-V Admins local security group.
###if (!$([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole("Hyper-V Administrators")) {EXIT}

# Verify/Create log folder in C:\ProgramData for LaunchDockerDesktop script
$CurrentDir=(Get-Item -Path ".\").FullName
if (!(test-path "$DockerScriptLogLocation")) {
    md "$DockerScriptLogLocation"
    $ACL = Get-Acl "$ScriptRepository"
    $AR = New-Object System.Security.AccessControl.FileSystemAccessRule("Hyper-V Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ACL.SetAccessRule($AR)
    Set-Acl "$ScriptRepository" $ACL 
}

#Check/Start Docker Desktop Service prereq
$CurrDisp = "Hyper-V Host Compute Service"
$CurrServ = "vmcompute"
StartServ $CurrDisp $CurrServ

#Check/Start Hyper-V Host Compute Service prereq
$CurrDisp = "Docker Desktop Service"
$CurrServ = "com.docker.service"
StartServ $CurrDisp $CurrServ

# Allow Docker's 60 sec start delay, this is necessary with the free version
Start-Sleep -seconds 65

$StartResult = &Start-Process -FilePath “C:\Program Files\Docker\Docker\Docker Desktop.exe” 2>&1 

$EventMessage="INFO:    Docker Desktop started with result: $StartResult."

if (!(test-path "$DockerScriptLogLocation\$DockerScriptLogName" -PathType Leaf)) {
    New-Item "$DockerScriptLogLocation\$DockerScriptLogName" -ItemType "file"
} else {
    Add-Content "$DockerScriptLogLocation\$DockerScriptLogName" "$((Get-Date).tostring("yyyy-MM-dd_hh:mm:ss"))    $EventMessage"
}

