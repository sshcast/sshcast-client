#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef DistDir
  #define DistDir "dist"
#endif
#ifndef OutDir
  #define OutDir "."
#endif

[Setup]
SourceDir=..
AppId={{8E9D5B2A-4F6C-4C1B-9A3D-7E2F1A0B5C4D}
AppName=Sshcast
AppVersion={#AppVersion}
AppPublisher=Sshcast Contributors
AppPublisherURL=https://sshcast.net
AppSupportURL=https://github.com/sshcast/sshcast-client/issues
AppUpdatesURL=https://github.com/sshcast/sshcast-client/releases
DefaultDirName={localappdata}\Programs\Sshcast
DefaultGroupName=Sshcast
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DisableProgramGroupPage=yes
AllowNoIcons=yes
OutputDir={#OutDir}
OutputBaseFilename=sshcast-client-setup-windows-x86_64
SetupIconFile=windows\sshcast.ico
UninstallDisplayIcon={app}\sshcast-tray.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
AppMutex=net.sshcast.client.tray
CloseApplications=yes
RestartApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start Sshcast tray automatically when signing in to Windows"; GroupDescription: "Additional options:"
Name: "addpath"; Description: "Add sshcast-client CLI to user PATH"; GroupDescription: "Additional options:"

[Files]
Source: "{#DistDir}\sshcast-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\sshcast-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE-MIT"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE-APACHE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Sshcast\Sshcast"; Filename: "{app}\sshcast-tray.exe"
Name: "{autoprograms}\Sshcast\Uninstall Sshcast"; Filename: "{uninstallexe}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SshcastTray"; ValueData: """{app}\sshcast-tray.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\sshcast-tray.exe"; Description: "Launch Sshcast tray now"; Flags: nowait postinstall skipifsilent

[Code]
const
  EnvSubkey = 'Environment';
  PathValueName = 'Path';

function NormalizePathSegment(const Value: string): string;
begin
  Result := Uppercase(RemoveBackslashUnlessRoot(Trim(Value)));
end;

function PathContainsDir(const PathValue, Dir: string): Boolean;
var
  Target: string;
  Remaining: string;
  SepPos: Integer;
  Segment: string;
begin
  Result := False;
  Target := NormalizePathSegment(Dir);
  Remaining := PathValue;
  while Remaining <> '' do
  begin
    SepPos := Pos(';', Remaining);
    if SepPos > 0 then
    begin
      Segment := Copy(Remaining, 1, SepPos - 1);
      Remaining := Copy(Remaining, SepPos + 1, Length(Remaining) - SepPos);
    end
    else
    begin
      Segment := Remaining;
      Remaining := '';
    end;
    if (Trim(Segment) <> '') and (NormalizePathSegment(Segment) = Target) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure AddDirToUserPath(const Dir: string);
var
  OrigPath: string;
  CleanDir: string;
  NewPath: string;
begin
  CleanDir := RemoveBackslashUnlessRoot(Trim(Dir));
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvSubkey, PathValueName, OrigPath) then
    OrigPath := '';

  if PathContainsDir(OrigPath, CleanDir) then
    Exit;

  if Trim(OrigPath) = '' then
    NewPath := CleanDir
  else if OrigPath[Length(OrigPath)] = ';' then
    NewPath := OrigPath + CleanDir
  else
    NewPath := OrigPath + ';' + CleanDir;

  RegWriteExpandStringValue(HKEY_CURRENT_USER, EnvSubkey, PathValueName, NewPath);
end;

procedure RemoveDirFromUserPath(const Dir: string);
var
  OrigPath: string;
  Target: string;
  Remaining: string;
  SepPos: Integer;
  Segment: string;
  NewPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvSubkey, PathValueName, OrigPath) then
    Exit;

  if not PathContainsDir(OrigPath, Dir) then
    Exit;

  Target := NormalizePathSegment(Dir);
  Remaining := OrigPath;
  NewPath := '';
  while Remaining <> '' do
  begin
    SepPos := Pos(';', Remaining);
    if SepPos > 0 then
    begin
      Segment := Copy(Remaining, 1, SepPos - 1);
      Remaining := Copy(Remaining, SepPos + 1, Length(Remaining) - SepPos);
    end
    else
    begin
      Segment := Remaining;
      Remaining := '';
    end;

    if (Trim(Segment) <> '') and (NormalizePathSegment(Segment) <> Target) then
    begin
      if NewPath = '' then
        NewPath := Segment
      else
        NewPath := NewPath + ';' + Segment;
    end;
  end;

  if NewPath = OrigPath then
    Exit;

  if NewPath = '' then
    RegDeleteValue(HKEY_CURRENT_USER, EnvSubkey, PathValueName)
  else
    RegWriteExpandStringValue(HKEY_CURRENT_USER, EnvSubkey, PathValueName, NewPath);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if CheckForMutexes('net.sshcast.client.tray,Local\net.sshcast.client.tray') then
  begin
    Exec('taskkill.exe', '/F /IM sshcast-tray.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(300);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('addpath') then
      AddDirToUserPath(ExpandConstant('{app}'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveDirFromUserPath(ExpandConstant('{app}'));
end;
