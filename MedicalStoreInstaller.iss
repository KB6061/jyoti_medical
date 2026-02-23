; -----------------------------------------
; Medical Store Installer Script
; Version 1.0.0
; Path: A:\krishnabhandare705-project-main\jyoti_medical
; -----------------------------------------

[Setup]
AppName=Medical Store Management
AppVersion=1.0.0
AppPublisher=Krishna Bhandare
; Installs to C:\Program Files (x86)\Medical Store
DefaultDirName={autopf}\Medical Store
DefaultGroupName=Medical Store
DisableProgramGroupPage=no
LicenseFile=license.txt
SetupIconFile=logo.ico
OutputDir=output
OutputBaseFilename=MedicalStoreInstaller
Compression=lzma
SolidCompression=yes
WizardStyle=modern

; Settings
AllowNoIcons=yes
UsePreviousAppDir=no

[Files]
; IMPORTANT: Run this .iss script from the "jyoti_medical" folder.
; This copies everything from your PyInstaller 'dist' folder.
Source: "dist\MedicalStore\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Desktop shortcut
Name: "{commondesktop}\Medical Store"; Filename: "{app}\MedicalStore.exe"

; Start Menu shortcut
Name: "{group}\Medical Store"; Filename: "{app}\MedicalStore.exe"

[Run]
; Launch the app automatically after installation
Filename: "{app}\MedicalStore.exe"; Description: "Launch Medical Store"; Flags: nowait postinstall skipifsilent