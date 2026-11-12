#define AppName "Session Password Exporter"
#define AppExeName "session-password-exporter.exe"
#define AppPublisher "Eduard Rezunov"
#define AppRepository "https://github.com/EduardRe/SessionPasswordExporter"

[Setup]
AppId={{9F90A880-1371-4C2D-A6E5-4BF9B9665AF0}
AppName={#AppName}
AppVersion={#AppVersion}
SetupArchitecture={#InstallerArchitecture}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppRepository}
AppSupportURL={#AppRepository}
AppUpdatesURL={#AppRepository}/releases
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
LicenseFile="{#SourceRoot}\LICENSE"
OutputDir="{#OutputDirectory}"
OutputBaseFilename=session-password-exporter-{#AppVersion}-setup-windows-{#InstallerArchitecture}
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
SetupLogging=yes
WizardStyle=modern
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.ShortcutGroup=Shortcuts:
english.StartMenuShortcut=Create a Start Menu shortcut
english.DesktopShortcut=Create a desktop shortcut
russian.ShortcutGroup=Ярлыки:
russian.StartMenuShortcut=Создать ярлык в меню «Пуск»
russian.DesktopShortcut=Создать ярлык на рабочем столе

[Tasks]
Name: "startmenu"; Description: "{cm:StartMenuShortcut}"; GroupDescription: "{cm:ShortcutGroup}"
Name: "desktop"; Description: "{cm:DesktopShortcut}"; GroupDescription: "{cm:ShortcutGroup}"; Flags: unchecked

[Files]
Source: "{#SourceRoot}\target\{#TargetTriple}\release\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startmenu
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktop
