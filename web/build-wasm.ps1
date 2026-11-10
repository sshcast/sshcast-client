$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ClientRoot = Split-Path -Parent $ScriptDir

$EmbeddedProto = Join-Path $ClientRoot "sshcast-proto\Cargo.toml"
if (Test-Path $EmbeddedProto) {
    $ProtoManifest = (Resolve-Path $EmbeddedProto).Path
    $TargetDir = Join-Path (Split-Path -Parent $ProtoManifest) "target"
} else {
    $ProtoManifest = Join-Path $ClientRoot "..\sshcast-proto\Cargo.toml"
    $TargetDir = Join-Path $ClientRoot "..\sshcast-proto\target"
}

if (Get-Command rustup -ErrorAction SilentlyContinue) {
    rustup target add wasm32-unknown-unknown
}

Write-Host "==> Building sshcast_proto.wasm (wasm32-unknown-unknown)..."
cargo build --manifest-path $ProtoManifest --target wasm32-unknown-unknown --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$WasmOut = Join-Path $TargetDir "wasm32-unknown-unknown\release\sshcast_proto.wasm"
$Dest = Join-Path $ScriptDir "sshcast_proto.wasm"
Copy-Item -Force $WasmOut $Dest
Write-Host "==> Wrote $Dest"
