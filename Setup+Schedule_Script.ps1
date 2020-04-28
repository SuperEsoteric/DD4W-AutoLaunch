#Requires -RunAsAdministrator
$Local_Uname="PS_ScheduledTasks"
$DockerScriptName="LaunchDockerDesktop"
$DockerScriptFile="LaunchDockerDesktop.ps1"
$TaskScriptName="LaunchDockerContainer"
$TaskScriptFile="LaunchDockerContainer.ps1"
$ScriptRepository="$([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))\PowerShellScript-DockerAdmin"
$TaskScriptFileLocation="$ScriptRepository\$TaskScriptName"
$TaskScriptLogLocation="$TaskScriptFileLocation\Logs"

# Add-Type to allow assigning batch logon rights to new local users, as required for non-admin launching of non-interactive scheduled tasks.
# Source: https://stackoverflow.com/questions/26392151/enabling-a-local-user-right-assignment-in-powershell#26393118
# Nuka Raku: https://stackoverflow.com/users/4106077/nuka-raku
Add-Type @'
using System;
using System.Collections.Generic;
using System.Text;

namespace LSA
{
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Management;
    using System.Runtime.CompilerServices;
    using System.ComponentModel;

    using LSA_HANDLE = IntPtr;

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }
    sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaOpenPolicy(
        LSA_UNICODE_STRING[] SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        int AccessMask,
        out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaAddAccountRights(
        LSA_HANDLE PolicyHandle,
        IntPtr pSID,
        LSA_UNICODE_STRING[] UserRights,
        int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern int LsaLookupNames2(
        LSA_HANDLE PolicyHandle,
        uint Flags,
        uint Count,
        LSA_UNICODE_STRING[] Names,
        ref IntPtr ReferencedDomains,
        ref IntPtr Sids
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);

    }
    /// <summary>
    /// This class is used to grant "Log on as a service", "Log on as a batchjob", "Log on localy" etc.
    /// to a user.
    /// </summary>
    public sealed class LsaWrapper : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRUST_INFORMATION
        {
            internal LSA_UNICODE_STRING Name;
            internal IntPtr Sid;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_TRANSLATED_SID2
        {
            internal SidNameUse Use;
            internal IntPtr Sid;
            internal int DomainIndex;
            uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_REFERENCED_DOMAIN_LIST
        {
            internal uint Entries;
            internal LSA_TRUST_INFORMATION Domains;
        }

        enum SidNameUse : int
        {
            User = 1,
            Group = 2,
            Domain = 3,
            Alias = 4,
            KnownGroup = 5,
            DeletedAccount = 6,
            Invalid = 7,
            Unknown = 8,
            Computer = 9
        }

        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;

        IntPtr lsaHandle;

        public LsaWrapper()
            : this(null)
        { }
        // // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr,
            (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0)
                return;
            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivileges(string account, string privilege)
        {
            IntPtr pSid = GetSIDInformation(account);
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilege);
            uint ret = Win32Sec.LsaAddAccountRights(lsaHandle, pSid, privileges, 1);
            if (ret == 0)
                return;
            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper()
        {
            Dispose();
        }
        // helper functions

        IntPtr GetSIDInformation(string account)
        {
            LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
            LSA_TRANSLATED_SID2 lts;
            IntPtr tsids = IntPtr.Zero;
            IntPtr tdom = IntPtr.Zero;
            names[0] = InitLsaString(account);
            lts.Sid = IntPtr.Zero;
            Console.WriteLine("String account: {0}", names[0].Length);
            int ret = Win32Sec.LsaLookupNames2(lsaHandle, 0, 1, names, ref tdom, ref tsids);
            if (ret != 0)
                throw new Win32Exception(Win32Sec.LsaNtStatusToWinError(ret));
            lts = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(tsids,
            typeof(LSA_TRANSLATED_SID2));
            Win32Sec.LsaFreeMemory(tsids);
            Win32Sec.LsaFreeMemory(tdom);
            return lts.Sid;
        }

        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe)
                throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
    public class Editor
    {
        public static void AddPrivileges(string account, string privilege)
        {
            using (LsaWrapper lsaWrapper = new LsaWrapper())
            {
                lsaWrapper.AddPrivileges(account, privilege);
            }
        }
    }
}
'@

# Create local user in the hyper-v admin group & grant batch login rights to run scheduled tasks.
if ([string]::IsNullOrEmpty($(Get-LocalUser| Where-Object{$_.Name -eq "$Local_Uname"}).ToString)) {
    $SecurePass = $Password = Read-Host -AsSecureString "Creating new local user: $Local_Uname.`n`nPlease enter password for new user.`n`nStore this password safely for future use.`n"
    New-LocalUser -Name "$Local_Uname" -Password $Password -FullName "PowerShell Scheduled Task User" -Description "Launches PowerShell scheduled tasks." -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "$Local_Uname"
    [LSA.Editor]::AddPrivileges("$Local_Uname", "SeBatchLogonRight")
    }

# Create folders in C:\ProgramData and copy Docker script & Task script 
$CurrentDir=(Get-Item -Path ".\").FullName
if (!(test-path "$TaskScriptLogLocation")) {md "$TaskScriptLogLocation"}
$ACL = Get-Acl "$ScriptRepository"
$AR = New-Object System.Security.AccessControl.FileSystemAccessRule("Hyper-V Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$ACL.SetAccessRule($AR)
Set-Acl "$ScriptRepository" $ACL 
Copy-Item "$CurrentDir\$DockerScriptFile" -Destination "$ScriptRepository\$DockerScriptFile"
Copy-Item "$CurrentDir\$TaskScriptFile" -Destination "$TaskScriptFileLocation\$TaskScriptFile"

#Set the value of the container tag to start after start up
$ContainerTagInput = Read-Host "`n`nTo start Docker container on startup,`n`nPlease enter the container TAG (case-senstive):`n"
(Get-Content "$TaskScriptFileLocation\$TaskScriptFile").replace('[MyCaseSensitiveContainerTag]', "$ContainerTagInput") | Set-Content "$TaskScriptFileLocation\$TaskScriptFile"

# Stupid cmdlet won't accept secure strings...
if ([string]::IsNullOrEmpty($SecurePass)) {$SecurePass = $Password = Read-Host -AsSecureString `n`n"Please enter password for $Local_Uname.`n`nThis should be same as previously entered.`n"}
$Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $Local_Uname, $SecurePass
$password = $Credentials.GetNetworkCredential().Password 

# Create New Docker Task Items & Register
$A = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-executionpolicy bypass -noprofile -file $ScriptRepository\$DockerScriptFile" -Id "$DockerScriptName"
$T = New-ScheduledTaskTrigger -AtStartup
$P = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$S = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2) -RunOnlyIfNetworkAvailable -ExecutionTimeLimit ([timeSpan] “24855.03:14:07”)
$D = New-ScheduledTask -Action $A -Trigger $T -Settings $S
Register-ScheduledTask -TaskName "$DockerScriptName" -Action $A -Principal $P -Trigger $T -Settings $S

# Create New Script Task Items & Register
$A = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-executionpolicy bypass -noprofile -file $TaskScriptFileLocation\$TaskScriptFile" -Id "$TaskScriptName"
$T = New-ScheduledTaskTrigger -AtStartup
$S = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2) -RunOnlyIfNetworkAvailable -ExecutionTimeLimit ([timeSpan] “24855.03:14:07”)
$D = New-ScheduledTask -Action $A -Trigger $T -Settings $S
Register-ScheduledTask -TaskName "$TaskScriptName" -Action $A -User "$env:COMPUTERNAME\$Local_Uname" -Password "$password" -RunLevel Highest -Trigger $T -Settings $S

$password = "Nothing to see HERE! Nothing!"

Read-Host -Prompt "Press Enter to continue"