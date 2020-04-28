DD4W-StartUpAutoLauncher launches a container in Docker Desktop for Windows automatically following system start up.

Docker Desktop for Windows is started with the System account via Task Scheduler. The specified container will launch in a second scheduled task as a batch logon. Scripts create the new member of the Hyper-V Administrators group, grants "SeBatchLogonRight." Creates a directory structure in C:\ProgramData for the scripts and basic log outputs.

Instructions:
  1) Clone or download the repository.
  2) Run "1-StartHere.cmd" as Administrator
  3) Enter a password for the new Hyper-V admin user. 
  4) Enter the TAG for the desired container to launch on startup.
  5) Reboot.
