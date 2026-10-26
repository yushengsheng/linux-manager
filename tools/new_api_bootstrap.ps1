# Native Windows configuration: PowerShell/.NET plus the already installed Codex.
param([switch]$PrepareOnly,[switch]$Restore,[switch]$Terminal,
      [string]$Origin=$env:NEWAPI_SETUP_ORIGIN,[string]$Model='gpt-6.1-sol')
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$connection=$null
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12

function ConvertTo-NewApiMap($Value){
  if($null -eq $Value){return $null}
  if($Value -is [Collections.IDictionary]){
    $map=@{};foreach($key in $Value.Keys){$map[$key]=ConvertTo-NewApiMap $Value[$key]};return $map
  }
  if($Value -is [Management.Automation.PSCustomObject]){
    $map=@{};foreach($item in $Value.PSObject.Properties){$map[$item.Name]=ConvertTo-NewApiMap $item.Value};return $map
  }
  if($Value -is [Collections.IList]){
    $items=@();foreach($item in $Value){$items+=,(ConvertTo-NewApiMap $item)};return ,$items
  }
  return $Value
}

function ConvertTo-NewApiCanonical($Value){
  if($Value -is [Collections.IDictionary]){
    $map=[ordered]@{};foreach($key in ($Value.Keys | Sort-Object)){$map[$key]=ConvertTo-NewApiCanonical $Value[$key]};return $map
  }
  if($Value -is [Collections.IList]){
    $items=@();foreach($item in $Value){$items+=,(ConvertTo-NewApiCanonical $item)};return ,$items
  }
  return $Value
}

function Get-NewApiHash([AllowNull()][byte[]]$Bytes){
  if($null -eq $Bytes){return $null}
  $sha=[Security.Cryptography.SHA256]::Create()
  try{return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}

function Read-NewApiBytes([string]$Path){
  if(!(Test-Path -LiteralPath $Path)){return $null}
  $file=Get-Item -LiteralPath $Path
  if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 8MB){throw '配置或备份文件类型、大小异常，未覆盖。'}
  return ,[IO.File]::ReadAllBytes($Path)
}

function Set-NewApiPrivate([string]$Path,[switch]$Directory){
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $existing=Get-Acl -LiteralPath $Path
  $rules=@($existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  $bad=@($rules | Where-Object {$_.IdentityReference.Value -ne $sid.Value -or $_.AccessControlType -ne 'Allow' -or $_.IsInherited})
  $full=@($rules | Where-Object {($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl})
  if($existing.AreAccessRulesProtected -and !$bad.Count -and $full.Count){return}
  if($Directory){
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
  }else{
    $acl=New-Object Security.AccessControl.FileSecurity
    $inherit=[Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner($sid)
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-NewApiPrivate([string]$Path,[byte[]]$Bytes){
  if(Test-Path -LiteralPath $Path){[void](Read-NewApiBytes $Path)}
  $temporary=Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.newapi-write.'+[Guid]::NewGuid().ToString('N'))
  try{
    $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$file.Dispose()
    Set-NewApiPrivate $temporary
    $file=[IO.File]::OpenWrite($temporary)
    try{$file.Write($Bytes,0,$Bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temporary,$Path,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
    Set-NewApiPrivate $Path
  }finally{if(Test-Path -LiteralPath $temporary){[IO.File]::Delete($temporary)}}
}

function Write-NewApiJson([string]$Path,$Value){
  $bytes=[Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 100 -Compress))
  if($bytes.Length -gt 8MB){throw '生成的配置数据超过大小上限，未继续写入。'}
  Write-NewApiPrivate $Path $bytes
}

function Get-NewApiHome {
  $path=$env:CODEX_HOME
  if(!$path){$path=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'}
  if(![IO.Path]::IsPathRooted($path)){throw 'CODEX_HOME 必须是绝对路径，请与桌面版使用同一目录。'}
  $path=[IO.Path]::GetFullPath($path)
  if(!(Test-Path -LiteralPath $path)){[void][IO.Directory]::CreateDirectory($path)}
  if((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Codex 配置目录是链接，请先确认真实目录。'}
  [void](Read-NewApiBytes (Join-Path $path 'config.toml'))
  return $path
}

function Invoke-NewApiProcess([string]$File,[string]$Arguments,[int]$Timeout=10000){
  $process=New-Object Diagnostics.Process
  try{
    $process.StartInfo.FileName=$File;$process.StartInfo.Arguments=$Arguments
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    [void]$process.Start()
    $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
    if(!$process.WaitForExit($Timeout)){$process.Kill();[void]$process.WaitForExit(5000);return $null}
    if($process.ExitCode -eq 0){return $output.GetAwaiter().GetResult()}
  }catch{return $null}finally{$process.Dispose()}
}

function Find-NewApiCodex {
  $paths=New-Object 'Collections.Generic.List[string]'
  if($env:NEWAPI_CODEX_BINARY){$paths.Add($env:NEWAPI_CODEX_BINARY)}
  Get-Command codex.exe -CommandType Application -All -ErrorAction SilentlyContinue | ForEach-Object {$paths.Add($_.Source)}
  $local=$env:LOCALAPPDATA;if(!$local){$local=[Environment]::GetFolderPath('LocalApplicationData')}
  foreach($relative in @('OpenAI/Codex/bin/*/codex.exe','Programs/OpenAI/Codex/bin/codex.exe','Programs/Codex/resources/codex.exe','Programs/Codex/resources/codex-cli/codex.exe')){
    Get-ChildItem -Path (Join-Path $local $relative) -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | ForEach-Object {$paths.Add($_.FullName)}
  }
  if(Get-Command Get-AppxPackage -ErrorAction SilentlyContinue){
    Get-AppxPackage '*Codex*' -ErrorAction SilentlyContinue | ForEach-Object {
      foreach($relative in @('app/resources/codex.exe','app/resources/codex-cli/codex.exe','resources/codex.exe')){$paths.Add((Join-Path $_.InstallLocation $relative))}
    }
  }
  $seen=@{}
  foreach($path in $paths){
    if($seen.ContainsKey($path) -or !(Test-Path -LiteralPath $path -PathType Leaf)){continue}
    $seen[$path]=$true
    $version=Invoke-NewApiProcess $path '--version'
    if($version -match 'codex-cli\s+(\d+)\.(\d+)\.(\d+)'){
      if([version]::new([int]$Matches[1],[int]$Matches[2],[int]$Matches[3]) -ge [version]'0.164.0'){return $path}
    }
  }
  throw '未找到支持安全配置接口的 Codex。请安装或更新官方 Windows 桌面版后重试；不会下载其他运行环境。'
}

function Stop-NewApiRpc($Rpc){
  if(!$Rpc -or $Rpc.closed){return}
  $Rpc.closed=$true;$process=$Rpc.process
  try{
    if($Rpc.started){
      if($Rpc.writer){$Rpc.writer.Close()}else{$process.StandardInput.Close()}
      if(!$process.WaitForExit(5000)){$process.Kill();[void]$process.WaitForExit(5000)}
    }
  }finally{$process.Dispose()}
}

function Invoke-NewApiRpc($Rpc,[string]$Method,$Params){
  $Rpc.index++
  $packet=@{id=$Rpc.index;method=$Method;params=$Params} | ConvertTo-Json -Depth 100 -Compress
  $Rpc.writer.WriteLine($packet);$Rpc.writer.Flush()
  $timer=[Diagnostics.Stopwatch]::StartNew()
  for($line=0;$line -lt 512;$line++){
    $remaining=35000-[int]$timer.ElapsedMilliseconds
    if($remaining -le 0){throw 'Codex 配置接口超时。'}
    $pending=$Rpc.process.StandardOutput.ReadLineAsync()
    if(!$pending.Wait($remaining)){throw 'Codex 配置接口超时；请检查安装或应用控制策略。'}
    $text=$pending.GetAwaiter().GetResult()
    if($null -eq $text -or $text.Length -gt 8MB){throw 'Codex 配置接口退出或返回异常数据。'}
    try{$answer=ConvertTo-NewApiMap ($text | ConvertFrom-Json)}catch{throw 'Codex 配置接口 JSON 格式不兼容或响应异常，未输出配置内容。'}
    if($answer.id -ne $Rpc.index){continue}
    if($answer.ContainsKey('error')){throw 'Codex 拒绝配置操作；请检查客户端版本、原配置格式或企业管理策略。原始错误可能含密钥，不会输出。'}
    return $answer.result
  }
  throw 'Codex 配置接口返回过多无关消息，已停止。'
}

function New-NewApiRpc([string]$Codex,[string]$Directory){
  $process=New-Object Diagnostics.Process
  $process.StartInfo.FileName=$Codex
  $process.StartInfo.Arguments='-c features.plugins=false app-server --stdio'
  $process.StartInfo.WorkingDirectory=$Directory
  $process.StartInfo.EnvironmentVariables['CODEX_HOME']=$Directory
  $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
  $process.StartInfo.RedirectStandardInput=$true;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
  $process.StartInfo.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
  $rpc=@{process=$process;index=0;closed=$false;started=$false}
  try{
    [void]$process.Start();$rpc.started=$true;$rpc.errors=$process.StandardError.ReadToEndAsync()
    # .NET Framework otherwise uses the console code page for redirected stdin.
    $rpc.writer=[IO.StreamWriter]::new($process.StandardInput.BaseStream,[Text.UTF8Encoding]::new($false))
    [void](Invoke-NewApiRpc $rpc 'initialize' @{clientInfo=@{name='newapi_windows_setup';version='2.0'}})
    $rpc.writer.WriteLine('{"method":"initialized","params":{}}');$rpc.writer.Flush()
    return $rpc
  }catch{Stop-NewApiRpc $rpc;throw}
}

function Get-NewApiUserLayer($Read){
  foreach($layer in $Read.layers){if($layer.name.type -eq 'user' -and !$layer.name.profile){return $layer}}
  return @{config=@{};version=$null}
}

function Get-NewApiBase([string]$Address){
  try{
    $uri=[Uri]$Address.Trim()
    if(!$uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or !$uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.Port -eq 0 -or $uri.AbsolutePath.TrimEnd('/') -notin @('','/v1','/keys')){throw 'invalid'}
    return $uri.GetLeftPart([UriPartial]::Authority)+'/v1'
  }catch{throw '请输入有效的 HTTPS 根地址，可带 /v1 或 /keys，保留真实端口；不要带账号密码或查询参数。'}
}

function Invoke-NewApiHttp([string]$Uri,[string]$Key,$Body=$null){
  if(!$Key -or $Key.Length -gt 4096 -or $Key -match '\s'){throw '个人 API 密钥为空、过长或含空白。'}
  $request=[Net.HttpWebRequest]::Create($Uri)
  $request.AllowAutoRedirect=$false;$request.Timeout=60000;$request.ReadWriteTimeout=30000
  $request.Headers['Authorization']='Bearer '+$Key;$request.Accept='application/json'
  $response=$null;$stream=$null;$memory=New-Object IO.MemoryStream
  try{
    if($null -ne $Body){
      $request.Method='POST';$request.ContentType='application/json'
      $bytes=[Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 20 -Compress))
      $request.ContentLength=$bytes.Length;$upload=$request.GetRequestStream()
      try{$upload.Write($bytes,0,$bytes.Length)}finally{$upload.Dispose()}
    }
    $response=$request.GetResponse()
    if([int]$response.StatusCode -ne 200){throw '接口返回了重定向或异常状态。'}
    $stream=$response.GetResponseStream();$buffer=New-Object byte[] 16384;$timer=[Diagnostics.Stopwatch]::StartNew()
    while($true){
      if($timer.Elapsed.TotalSeconds -ge 90){throw '接口读取超过时限。'}
      $count=$stream.Read($buffer,0,$buffer.Length);if(!$count){break}
      if($memory.Length+$count -gt 4MB){throw '接口响应超过大小上限。'}
      $memory.Write($buffer,0,$count)
    }
    return ConvertTo-NewApiMap ([Text.Encoding]::UTF8.GetString($memory.ToArray()) | ConvertFrom-Json)
  }catch [Net.WebException]{
    if($_.Exception.Response){
      $status=[int]$_.Exception.Response.StatusCode;$_.Exception.Response.Close()
      if($status -in @(401,403)){throw 'API 密钥被拒绝；请确认使用个人 API Key，并检查额度与模型权限。'}
      throw ('New API 接口返回 HTTP '+$status+'；请检查默认模型和 Responses 接口支持。')
    }
    throw '无法访问 New API 接口，请检查证书、网络和代理。未跳过 HTTPS 验证。'
  }finally{
    if($stream){$stream.Dispose()};if($response){$response.Close()};$memory.Dispose();$request.Abort()
  }
}

function Get-NewApiModels([string]$Base,[string]$Key){
  $reply=Invoke-NewApiHttp ($Base+'/models') $Key
  if($reply.data -isnot [Collections.IList]){throw '模型列表格式不正确，未修改配置。'}
  $models=New-Object 'Collections.Generic.List[string]'
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($row in $reply.data){
    $id=$row.id
    if($id -is [string] -and $id.Length -gt 0 -and $id.Length -le 200 -and $id -notmatch '[\x00-\x1f]' -and $id -notmatch '(?i)image|tts|transcrib|whisper|embed|rerank|video|audio|speech|sora|auto-review' -and $seen.Add($id)){$models.Add($id)}
  }
  if(!$models.Count -or $models.Count -gt 1000){throw '没有可用于 Codex 聊天的模型，或模型数量异常。未修改配置。'}
  $models.Sort([StringComparer]::Ordinal)
  return ,($models.ToArray())
}

function Get-NewApiReasoningLevels([string]$Model){
  # Exact official model IDs only; unknown gateway aliases keep their own metadata.
  # https://developers.openai.com/api/docs/guides/deployment-checklist#set-up-reasoningeffort
  if($Model -cin @('gpt-6.1-sol','gpt-6-astra')){return @('low','medium','high','xhigh','max')}
  if($Model -cin @('gpt-6-sol','gpt-6-luna')){return @('none','low','medium','high','xhigh','max')}
  return @()
}

function Test-NewApiResponses([string]$Base,[string]$Key,[string]$Selected){
  Write-Host '正在用一条短请求检查默认模型的 Responses 接口…'
  $body=@{model=$Selected;input='Reply OK.';max_output_tokens=32;store=$false}
  if(@(Get-NewApiReasoningLevels $Selected).Count){$body.reasoning=@{effort='low'}}
  $reply=Invoke-NewApiHttp ($Base+'/responses') $Key $body
  if($reply.object -ne 'response' -or $reply.status -notin @('completed','incomplete') -or $reply.output -isnot [Collections.IList]){throw '默认模型未返回有效的 Responses 响应，未修改配置。'}
}

function Get-NewApiCatalog([string[]]$Models,[string]$Directory,$Existing){
  $metadata=[Collections.Hashtable]::new([StringComparer]::Ordinal);$sources=@((Join-Path $Directory 'models_cache.json'))
  if($Existing.model_catalog_json -is [string] -and [IO.Path]::IsPathRooted($Existing.model_catalog_json)){$sources+=$Existing.model_catalog_json}
  foreach($source in $sources){
    try{
      $bytes=Read-NewApiBytes $source;if($null -eq $bytes){continue}
      $listing=ConvertTo-NewApiMap ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
      foreach($row in $listing.models){if($row.slug -is [string]){$metadata[$row.slug]=$row}}
    }catch{continue}
  }
  $rows=@();$index=0
  foreach($name in $Models){
    $row=@{slug=$name;display_name=$name;description='New API gateway model';default_reasoning_level=$null;supported_reasoning_levels=@();shell_type='unified_exec';visibility='list';supported_in_api=$true;priority=$index;upgrade=$null;context_window=32768;input_modalities=@('text');support_verbosity=$false;default_verbosity=$null;apply_patch_tool_type='freeform';truncation_policy=@{mode='tokens';limit=10000};experimental_supported_tools=@();base_instructions='You are a coding assistant. Follow the user and repository instructions. Use the available tools when needed. Verify your work and describe the result accurately.'}
    if($metadata.ContainsKey($name)){foreach($key in $metadata[$name].Keys){$row[$key]=$metadata[$name][$key]}}
    $levels=@(Get-NewApiReasoningLevels $name)
    if($levels.Count){
      # Repair old generated catalogs too: their empty levels must not win over known capabilities.
      $row.supported_reasoning_levels=@($levels | ForEach-Object {@{effort=$_;description=($_+' reasoning effort')}})
      if($row.default_reasoning_level -cnotin $levels){$row.default_reasoning_level='medium'}
    }
    $row.slug=$name;$row.visibility='list';$row.supported_in_api=$true;$row.priority=$index;$row.upgrade=$null
    $rows+=,$row;$index++
  }
  return @{models=$rows}
}

function Get-NewApiExpectedBytes([string]$Backup,[string]$Codex,[AllowNull()][byte[]]$Original,$Edits){
  # Prepare with the real TOML writer in isolation. Exact output bytes let us
  # recognize our own commit after a lost reply without discarding others' edits.
  $stage=Join-Path $Backup ('.preview.'+[Guid]::NewGuid().ToString('N'));$rpc=$null
  New-Item -ItemType Directory -Path $stage | Out-Null;Set-NewApiPrivate $stage -Directory
  try{
    $path=Join-Path $stage 'config.toml'
    [byte[]]$bytes=@();if($null -ne $Original){$bytes=$Original}
    Write-NewApiPrivate $path $bytes
    $rpc=New-NewApiRpc $Codex $stage
    $read=Invoke-NewApiRpc $rpc 'config/read' @{includeLayers=$true};$layer=Get-NewApiUserLayer $read
    $params=@{filePath=$path;reloadUserConfig=$false;edits=$Edits}
    if($layer.version){$params.expectedVersion=$layer.version}
    $result=Invoke-NewApiRpc $rpc 'config/batchWrite' $params
    if($result.status -ne 'ok'){throw '配置被企业策略覆盖，原配置未修改。'}
    return ,(Read-NewApiBytes $path)
  }finally{
    Stop-NewApiRpc $rpc
    $resolved=[IO.Path]::GetFullPath($stage)
    if([IO.Path]::GetDirectoryName($resolved) -eq [IO.Path]::GetFullPath($Backup) -and [IO.Path]::GetFileName($resolved) -match '^\.preview\.[a-f0-9]{32}$' -and !((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)){
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
}

function Set-NewApiConfiguration([string]$Directory,[string]$Codex,[string]$Base,[string]$Key,[string]$Selected,[string[]]$Models){
  if($Selected -cnotin $Models){throw '默认模型不在此密钥可用的聊天模型中。'}
  $target=Join-Path $Directory 'config.toml';$original=Read-NewApiBytes $target
  $rpc=$null;$written=$null;$attempted=$false;$backup=$null;$expected=$null;$createdEmpty=$false
  try{
    $rpc=New-NewApiRpc $Codex $Directory
    $before=Invoke-NewApiRpc $rpc 'config/read' @{includeLayers=$true};$layer=Get-NewApiUserLayer $before
    if($layer.config.profile){throw '现有配置使用旧式 profile。请先按当前桌面版迁移 profile；原配置未覆盖。'}
    $parent=Join-Path $Directory 'newapi-backups'
    if(!(Test-Path -LiteralPath $parent)){[void][IO.Directory]::CreateDirectory($parent)}
    if((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint){throw '备份目录是链接，已停止。'}
    Set-NewApiPrivate $parent -Directory
    $backup=Join-Path $parent ((Get-Date -Format 'yyyyMMdd-HHmmss-')+[Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $backup | Out-Null;Set-NewApiPrivate $backup -Directory
    if($null -ne $original){Write-NewApiPrivate (Join-Path $backup 'original') $original}
    $state=@{existed=($null -ne $original);mode=384;created_ns=([DateTime]::UtcNow.Ticks-621355968000000000)*100;original_sha256=(Get-NewApiHash $original);restored=$false}
    Write-NewApiJson (Join-Path $backup 'state.json') $state
    $catalog=Join-Path $backup 'models.json'
    Write-NewApiJson $catalog (Get-NewApiCatalog $Models $Directory $layer.config)
    $provider=@{name='New API';base_url=$Base;wire_api='responses';experimental_bearer_token=$Key;requires_openai_auth=$false;supports_websockets=$false}
    $expected=ConvertTo-NewApiMap $layer.config
    $expected.model=$Selected;$expected.model_provider='newapi_gateway';$expected.model_catalog_json=$catalog
    $levels=@(Get-NewApiReasoningLevels $Selected)
    $repairReasoning=$levels.Count -gt 0 -and $layer.config.model_reasoning_effort -cnotin $levels
    if($repairReasoning){
      $effort='medium';if($layer.config.model_reasoning_effort -cin @('none','minimal')){$effort='low'}
      $expected.model_reasoning_effort=$effort
    }
    if(!$expected.model_providers){$expected.model_providers=@{}}
    $expected.model_providers.newapi_gateway=$provider
    $expectedJson=(ConvertTo-NewApiCanonical $expected) | ConvertTo-Json -Depth 100 -Compress
    $edits=@()
    foreach($entry in @(@('model',$Selected),@('model_provider','newapi_gateway'),@('model_catalog_json',$catalog),@('model_providers.newapi_gateway',$provider))){$edits+=@{keyPath=$entry[0];value=$entry[1];mergeStrategy='replace'}}
    if($repairReasoning){$edits+=@{keyPath='model_reasoning_effort';value=$effort;mergeStrategy='replace'}}
    $expectedBytes=Get-NewApiExpectedBytes $backup $Codex $original $edits
    $params=@{filePath=$target;reloadUserConfig=$false;edits=$edits}
    if($layer.version){$params.expectedVersion=$layer.version}
    if((Get-NewApiHash (Read-NewApiBytes $target)) -ne (Get-NewApiHash $original)){throw '配置被其他程序修改，已停止，请重试。'}
    # Ensure the token is never first written into a broadly readable file.
    if($null -eq $original){
      $empty=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$empty.Dispose();$createdEmpty=$true
    }
    Set-NewApiPrivate $target
    $attempted=$true
    $result=Invoke-NewApiRpc $rpc 'config/batchWrite' $params
    $current=Read-NewApiBytes $target
    $after=Invoke-NewApiRpc $rpc 'config/read' @{includeLayers=$true}
    $afterJson=(ConvertTo-NewApiCanonical (Get-NewApiUserLayer $after).config) | ConvertTo-Json -Depth 100 -Compress
    if($afterJson -ne $expectedJson -or (Get-NewApiHash $current) -ne (Get-NewApiHash $expectedBytes) -or (Get-NewApiHash (Read-NewApiBytes $target)) -ne (Get-NewApiHash $current)){throw '配置出现了额外修改，已停止，未覆盖其他程序的设置。'}
    $written=$current;$state.installed_sha256=Get-NewApiHash $written
    Write-NewApiJson (Join-Path $backup 'state.json') $state
    if($result.status -ne 'ok' -or $after.config.model_provider -ne 'newapi_gateway' -or $after.config.model -ne $Selected -or $after.config.model_providers.newapi_gateway.experimental_bearer_token -ne $Key){throw '企业策略或其他配置覆盖了本次设置，正在恢复原配置。'}
    Set-NewApiPrivate $target
    return @{model=$Selected;backup_id=[IO.Path]::GetFileName($backup);model_count=$Models.Count}
  }catch{
    $failure=$_.Exception.Message
    Stop-NewApiRpc $rpc;$rpc=$null
    if($attempted -and $null -eq $written -and $expected){
      try{
        $current=Read-NewApiBytes $target
        if((Get-NewApiHash $current) -eq (Get-NewApiHash $expectedBytes)){$written=$current}
      }catch{}
    }
    if($null -ne $written){
      $state.installed_sha256=Get-NewApiHash $written;Write-NewApiJson (Join-Path $backup 'state.json') $state
      if((Get-NewApiHash (Read-NewApiBytes $target)) -eq $state.installed_sha256){
        if($null -eq $original){[IO.File]::Delete($target)}else{Write-NewApiPrivate $target $original}
        $state.restored=$true;Write-NewApiJson (Join-Path $backup 'state.json') $state
      }
    }elseif($createdEmpty){
      $current=Read-NewApiBytes $target
      if($null -ne $current -and !$current.Length){[IO.File]::Delete($target)}
    }
    throw $failure
  }finally{Stop-NewApiRpc $rpc}
}

function Restore-NewApiConfiguration([string]$Directory){
  $parent=Join-Path $Directory 'newapi-backups';$target=Join-Path $Directory 'config.toml';$backups=@()
  if(!(Test-Path -LiteralPath $parent)){throw '没有可恢复的本命令备份。'}
  if((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint){throw '备份目录是链接，已停止。'}
  foreach($folder in (Get-ChildItem -LiteralPath $parent -Directory)){
    if($folder.Name -notmatch '^\d{8}-\d{6}-[a-f0-9]{8}$' -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)){continue}
    $state=ConvertTo-NewApiMap ([Text.Encoding]::UTF8.GetString((Read-NewApiBytes (Join-Path $folder.FullName 'state.json'))) | ConvertFrom-Json)
    if(!$state.restored -and $state.installed_sha256){$backups+=@{folder=$folder.FullName;state=$state;created=$(if($state.created_ns){$state.created_ns}else{($folder.LastWriteTimeUtc.Ticks-621355968000000000)*100})}}
  }
  $latest=$backups | Sort-Object { $_.created } -Descending | Select-Object -First 1
  if(!$latest){throw '没有可恢复的本命令备份。'}
  if((Get-NewApiHash (Read-NewApiBytes $target)) -ne $latest.state.installed_sha256){throw '配置后来已被修改，已停止恢复，避免覆盖其他设置。'}
  if($latest.state.existed){
    $original=Read-NewApiBytes (Join-Path $latest.folder 'original')
    if($null -eq $original -or ($latest.state.original_sha256 -and (Get-NewApiHash $original) -ne $latest.state.original_sha256)){throw '原配置备份缺失或校验失败，未修改当前配置。'}
    Write-NewApiPrivate $target $original
  }else{[IO.File]::Delete($target)}
  $latest.state.restored=$true;Write-NewApiJson (Join-Path $latest.folder 'state.json') $latest.state
}

function Read-NewApiConnection([string]$Address,[switch]$UseTerminal){
  if($UseTerminal){
    if(!$Address){$Address=Read-Host 'New API HTTPS 地址'}
    $secret=Read-Host '个人 API 密钥' -AsSecureString
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try{$key=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$secret.Dispose()}
    return @{origin=$Address;key=$key}
  }
  Add-Type -AssemblyName System.Windows.Forms
  $form=New-Object Windows.Forms.Form;$form.Text='New API / Codex';$form.ClientSize=[Drawing.Size]::new(510,180);$form.StartPosition='CenterScreen'
  $urlLabel=New-Object Windows.Forms.Label;$urlLabel.Text='New API HTTPS URL';$urlLabel.SetBounds(15,15,475,20)
  $url=New-Object Windows.Forms.TextBox;$url.SetBounds(15,38,475,25);$url.Text=$Address
  $keyLabel=New-Object Windows.Forms.Label;$keyLabel.Text='Personal API key';$keyLabel.SetBounds(15,75,475,20)
  $key=New-Object Windows.Forms.TextBox;$key.SetBounds(15,98,475,25);$key.UseSystemPasswordChar=$true
  $ok=New-Object Windows.Forms.Button;$ok.Text='Continue';$ok.SetBounds(380,140,110,28);$ok.DialogResult='OK'
  $form.Controls.AddRange(@($urlLabel,$url,$keyLabel,$key,$ok));$form.AcceptButton=$ok
  try{if($form.ShowDialog() -ne 'OK'){throw '已取消，未修改配置。'};return @{origin=$url.Text;key=$key.Text}}finally{$form.Dispose()}
}

function Select-NewApiModel([string[]]$Models,[string]$Default,[switch]$UseTerminal){
  if($Default -cnotin $Models){$Default=$Models[0]}
  if($UseTerminal){
    for($i=0;$i -lt $Models.Count;$i++){Write-Host ('{0}. {1}' -f ($i+1),$Models[$i])}
    $choice=Read-Host ('默认模型 '+$Default+'；回车使用默认，或输入序号')
    if(!$choice){return $Default}
    $number=0;if(![int]::TryParse($choice,[ref]$number) -or $number -lt 1 -or $number -gt $Models.Count){throw '模型序号无效，未修改配置。'}
    return $Models[$number-1]
  }
  $form=New-Object Windows.Forms.Form;$form.Text='Codex default model';$form.ClientSize=[Drawing.Size]::new(500,110);$form.StartPosition='CenterScreen'
  $list=New-Object Windows.Forms.ComboBox;$list.SetBounds(15,15,470,28);$list.DropDownStyle='DropDownList';$list.Items.AddRange([object[]]$Models);$list.SelectedItem=$Default
  $ok=New-Object Windows.Forms.Button;$ok.Text='Configure';$ok.SetBounds(370,65,115,28);$ok.DialogResult='OK'
  $form.Controls.AddRange(@($list,$ok));$form.AcceptButton=$ok
  try{if($form.ShowDialog() -ne 'OK'){throw '已取消，未修改配置。'};return [string]$list.SelectedItem}finally{$form.Dispose()}
}

# Entry point. Tests load the functions above with disposable homes and keys.
try{
  $directory=Get-NewApiHome
  if($Restore){Restore-NewApiConfiguration $directory;Write-Host '已恢复原配置。请正常退出并重新打开 Codex，新建会话。';return}
  Write-Host '正在检查已安装的 Codex 桌面版；不会下载 Python、uv 或新的 Codex…'
  $codex=Find-NewApiCodex
  if($PrepareOnly){
    $rpc=$null
    try{$rpc=New-NewApiRpc $codex $directory;[void](Invoke-NewApiRpc $rpc 'config/read' @{includeLayers=$true})}finally{Stop-NewApiRpc $rpc}
    Write-Host '本机 Codex 和配置接口可用，无需准备其他运行环境。';return
  }
  $connection=Read-NewApiConnection $Origin -UseTerminal:$Terminal
  $base=Get-NewApiBase $connection.origin
  Write-Host '正在读取此密钥可用的聊天模型…'
  $models=Get-NewApiModels $base $connection.key
  $selected=Select-NewApiModel $models $Model -UseTerminal:$Terminal
  Test-NewApiResponses $base $connection.key $selected
  $result=Set-NewApiConfiguration $directory $codex $base $connection.key $selected $models
  Write-Host ('配置完成：默认模型 {0}，聊天模型 {1} 个；备份 {2}。' -f $result.model,$result.model_count,$result.backup_id)
  Write-Host '请正常退出并重新打开 Codex，新建会话后使用。旧登录信息、其他服务商和插件设置保留。'
}catch{
  $message=$_.Exception.Message
  if($connection -and $connection.key){$message=$message.Replace($connection.key,'[redacted]')}
  [Console]::Error.WriteLine($message)
  # A failed pasted command must not close the user's interactive PowerShell.
  throw '配置未完成。请检查上方提示；不需要管理员窗口或关闭执行策略。'
}finally{if($connection){$connection.key=$null}}
