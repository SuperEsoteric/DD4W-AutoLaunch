# Launches Docker container as a scheduled task.
# Requires Docker TAG name to be set, if not provided in setup script.
$ContainerTag="htpmod-shiny"
$ScriptName="LaunchDockerContainer"
$ScriptRepository="$([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))\PowerShellScript-DockerAdmin"
$ScriptFileLocation="$ScriptRepository\$ScriptName"
$ScriptLogLocation="$ScriptFileLocation\Logs"
$ScriptLogName="$ContainerTag_$((Get-Date).tostring("yyyy-MM-dd")).log"
$DockerProcName="Docker Desktop"
$SelectedContainerArr = @()
$i=0

# Check launching user is member of Hyper-V Admins local security group.
if (!$([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole("Hyper-V Administrators")) {EXIT}

# Verify Docker Desktop process is running.
Do
{
$proc = Get-Process -ErrorAction SilentlyContinue
start-sleep -s 60
$i++
} While (($proc.name -NotContains "$DockerProcName") -and ($i -lt 100))

# Check the image exists, check if the container is already running, check if the container need to start, check if the container exists
if ([string]::IsNullOrEmpty($(docker image ls | Select-String -Pattern "$ContainerTag"))) {
    Write-Host 1
    $EventMessage="WARN:    No IMAGE exists for CONTAINER: $ContainerTag!`nCannot start $ContainerTag"
} elseif (-not ([string]::IsNullOrEmpty($(docker ps | Select-String -Pattern "$ContainerTag")))) {
    Write-Host 2
    $EventMessage="INFO:    $ContainerTag container is already running."
} elseif (-not ([string]::IsNullOrEmpty($(docker ps -f "status=exited" | Select-String -Pattern "$ContainerTag")))) {
    Write-Host 3
    $SelectedContainerArr = $((((docker ps -f "status=exited" | Select-String -Pattern " $ContainerTag " | Out-String) -replace "\s\s+", "," ).Trimend(",")).TrimStart(",")).Split(",")
    $SelectedContainerName = $SelectedContainerArr[$SelectedContainerArr.Count-1]
    $StartResult = &docker start $SelectedContainerName 2>&1 
    $EventMessage="INFO:    $SelectedContainerName started with result: $StartResult."
} elseif (([string]::IsNullOrEmpty($(docker ps -a | Select-String -Pattern "$ContainerTag"))) -and (-not ([string]::IsNullOrEmpty($(docker image ls | Select-String -Pattern "$ContainerTag"))))) {
    Write-Host 4
    $RunResult = &docker run -p 3838:3838 -p 8787:8787 -d $ContainerTag 2>&1
    $EventMessage="INFO:    $RunResult started successfully."
} else {
    $EventMessage="WARN:    $ContainerTag container could not be started. Unable to determine status."
}

if (!(test-path "$ScriptLogLocation")) {md "$ScriptLogLocation"}

if (!(test-path "$ScriptLogLocation\$ScriptLogName" -PathType Leaf)) {
    New-Item "$ScriptLogLocation\$ScriptLogName" -ItemType "file"
} else {
    Add-Content "$ScriptLogLocation\$ScriptLogName" "$((Get-Date).tostring("yyyy-MM-dd_hh:mm:ss"))    $EventMessage"
}

