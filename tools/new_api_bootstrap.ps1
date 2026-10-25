# Invoked as an in-memory script block. No execution-policy changes or elevation.
param([switch]$PrepareOnly,[switch]$Restore,[switch]$Terminal)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$work=$null
try {
  $root=if($env:CODEX_HOME){$env:CODEX_HOME}else{Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'}
  $runtime=Join-Path $root 'newapi-runtime'
  New-Item -ItemType Directory -Force -Path $runtime | Out-Null
  if((Get-Item -LiteralPath $runtime).Attributes -band [IO.FileAttributes]::ReparsePoint){throw '运行目录是链接，已停止。'}
  $work=Join-Path $runtime ('prepare.'+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $work | Out-Null
  Write-Host '正在自动检查并准备运行环境，首次可能需要下载，请稍候…'
  $arch=if($env:PROCESSOR_ARCHITEW6432){$env:PROCESSOR_ARCHITEW6432}else{$env:PROCESSOR_ARCHITECTURE}
  switch($arch.ToUpperInvariant()){
    'ARM64' {$target='aarch64-pc-windows-msvc';$digest='09f47edf90726084a70f9426f6e3ca4f46e9bf7cbf23b1716ec64d60b055fae3'}
    'AMD64' {$target='x86_64-pc-windows-msvc';$digest='a38b8d1902b7cfbc76b423ba1bb456f623f42064cdc72628b6075b89afd1019a'}
    default {throw '当前处理器不在已支持的 64 位平台中。'}
  }
  $script=Join-Path $work 'setup.py'
  Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/yushengsheng/linux-manager/17271fb01259c4c13fb1aba346a63cfce6a99ae1/tools/new_api_setup.py' -OutFile $script
  if((Get-FileHash -Algorithm SHA256 -LiteralPath $script).Hash.ToLowerInvariant() -ne 'a2ef8212851b29eead645a878248989e6562cd21323e88816eb60931ac930d54'){throw '配置程序校验失败，未执行。'}
  $archive=Join-Path $work 'uv.zip'
  Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/astral-sh/uv/releases/download/0.13.5/uv-$target.zip" -OutFile $archive
  if((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant() -ne $digest){throw '运行组件校验失败，未执行。'}
  Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $work 'uv')
  $uv=(Get-ChildItem -Path (Join-Path $work 'uv') -Filter uv.exe -Recurse | Select-Object -First 1).FullName
  if(!$uv){throw '官方运行组件结构异常。'}
  $previousCache=$env:UV_CACHE_DIR;$previousPython=$env:UV_PYTHON_INSTALL_DIR;$previousEncoding=$env:PYTHONIOENCODING;$previousUtf8=$env:PYTHONUTF8
  $env:UV_CACHE_DIR=Join-Path $runtime 'cache';$env:UV_PYTHON_INSTALL_DIR=Join-Path $runtime 'python'
  $env:PYTHONIOENCODING='utf-8';$env:PYTHONUTF8='1'
  try {
    $arguments=@('run','--no-project','--no-config','--managed-python','--python','3.13',$script,'--auto-prepare')
    if($PrepareOnly){$arguments+='--prepare-only'}
    if($Restore){$arguments+='--restore'}
    if($Terminal){$arguments+='--terminal'}
    & $uv @arguments
    if($LASTEXITCODE -ne 0){throw '自动配置未完成，请查看上方提示。'}
  }finally{$env:UV_CACHE_DIR=$previousCache;$env:UV_PYTHON_INSTALL_DIR=$previousPython;$env:PYTHONIOENCODING=$previousEncoding;$env:PYTHONUTF8=$previousUtf8}
}catch{
  [Console]::Error.WriteLine('未完成：'+$_.Exception.Message+' 不需要预先切换管理员或关闭执行策略。')
  exit 1
}finally{
  if($work -and (Test-Path -LiteralPath $work)){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
}
