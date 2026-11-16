#requires -Version 5.1
# Native UI checks with synthetic files and public-key-only signature inspection.
param([string]$ModulePath=(Join-Path $PSScriptRoot 'ActSigner.UI.psm1'))
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA'){throw 'Use native powershell.exe -STA.'}
. (Join-Path $PSScriptRoot 'CSPSigner.Preview.Tests.ps1') -FixtureOnly
Import-Module (Join-Path (Split-Path -Parent $ModulePath) 'ActSigner.Core.psm1') -Force -Global -DisableNameChecking
Import-Module (Join-Path (Split-Path -Parent $ModulePath) 'ActSigner.CryptoPro.psm1') -Force -Global -DisableNameChecking
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$root=Join-Path ([IO.Path]::GetTempPath()) ('cspsigner-preview-ui-'+[guid]::NewGuid().ToString('N'))
$second=$root+'-second'
foreach($directory in @($root,$second)){[void][IO.Directory]::CreateDirectory($directory)}
$document=Join-Path $root 'document.pdf';$print=Join-Path $root 'print.pdf';$archive=Join-Path $root 'backup.zip'
[byte[]]$bytes=[Text.Encoding]::ASCII.GetBytes('%PDF-1.4 synthetic UI document')
[IO.File]::WriteAllBytes($document,$bytes)
[IO.File]::WriteAllText($print,'%PDF-1.4 different printed representation')
[IO.File]::WriteAllBytes($archive,[byte[]]@(1,2,3))
[IO.File]::WriteAllBytes((Join-Path $root 'foreign.sig'),[PreviewCmsFixture]::Sign($bytes,$true,$true))
[IO.File]::WriteAllText((Join-Path $second 'other.txt'),'unsigned second source')
[IO.File]::WriteAllBytes((Join-Path $second 'other.zip'),[byte[]]@(4,5,6))
$module=Import-Module $ModulePath -Force -PassThru
& $module {param($Root)
 $script:previewFixtureRoot=$Root
 function script:Get-ActSignerSettings {
  [pscustomobject]@{SourceRoot=$script:previewFixtureRoot;SeparateOutputRoot=$script:previewFixtureRoot+'-output';SaveBesideSources=$true;SignatureNaming='signer'}
 }
} $root
$certificate=[pscustomobject]@{DisplayName='SYNTHETIC PREVIEW TEST';Subject='CN=SYNTHETIC';Issuer='CN=SYNTHETIC';FileLabel='ivanov';Thumbprint=('A'*40);Source='Synthetic';StoreKind='Synthetic';NotBefore=[datetime]'2020-01-01';NotAfter=[datetime]'2030-01-01'}
$otherCertificate=$certificate.PSObject.Copy();$otherCertificate.FileLabel='petrov';$otherCertificate.Thumbprint=('B'*40)
$state=@{Phase=0;Form=$null;Error=$null;Calls=0;BeforeCalls=0;Plan=$null;Certificates=@($certificate);Throw=$false;PhaseStarted=[datetime]::UtcNow;Saves=@()}
$provider={
 param($SourceRoot,$DestinationRoot,$SignatureNaming,$SignerLabel,$SourceFiles,$Recurse)
 $state.Calls++
 if($state.Throw){throw 'SYNTHETIC PREVIEW FAILURE'}
 $scope=@{};if(@($SourceFiles).Count -gt 0){$scope.SourceFiles=[string[]]$SourceFiles}
 $state.Plan=Get-ActPlan -Root $SourceRoot -OutputRoot $DestinationRoot -SignatureNaming $SignatureNaming -SignerLabel $SignerLabel -AllFiles -Recurse:([bool]$Recurse) @scope
 return $state.Plan
}.GetNewClosure()
$walk={param($Parent)
 $queue=New-Object 'System.Collections.Generic.Queue[System.Windows.Forms.Control]';$queue.Enqueue($Parent)
 while($queue.Count -gt 0){$control=$queue.Dequeue();$control;foreach($child in $control.Controls){$queue.Enqueue($child)}}
}
$assert={param([bool]$Condition,[string]$Message) if(-not $Condition){throw ('ASSERT: '+$Message)}}
$next={param([int]$Phase) $state.Phase=$Phase;$state.PhaseStarted=[datetime]::UtcNow;$state.BeforeCalls=$state.Calls}.GetNewClosure()
$priorSave=Get-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -ErrorAction SilentlyContinue
$priorSaveBlock=$null;if($null -ne $priorSave){$priorSaveBlock=$priorSave.ScriptBlock}
$save={param($SourceRoot,$SeparateOutputRoot,$SaveBesideSources,$SignatureNaming,$SelectOnlySignedFiles)
 $state.Saves+=@([bool]$SelectOnlySignedFiles);return $true
}.GetNewClosure()
Set-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -Value $save
$timer=New-Object Windows.Forms.Timer;$timer.Interval=75
$timer.Add_Tick({
 try{
  if(([datetime]::UtcNow-$state.PhaseStarted).TotalSeconds -gt 5){throw ('Automatic preview did not complete phase '+$state.Phase+' without pressing Refresh.')}
  if($null -eq $state.Form){
   $forms=@([Windows.Forms.Application]::OpenForms);if($forms.Count -eq 0){return}
   $state.Form=$forms[0];$controls=@(& $walk $state.Form)
   $state.Grid=@($controls | Where-Object {$_ -is [Windows.Forms.DataGridView]})[0]
   $state.Source=@($controls | Where-Object {$_.AccessibleName -eq 'Папка с исходными файлами'})[0]
   $state.Output=@($controls | Where-Object {$_.AccessibleName -eq 'Папка для файлов и подписей'})[0]
   $state.Naming=@($controls | Where-Object {$_.AccessibleName -eq 'Signature filename format'})[0]
   $state.Certificate=@($controls | Where-Object {$_.AccessibleName -eq 'Сертификат для подписания'})[0]
   $state.Summary=@($controls | Where-Object {$_.AccessibleName -eq 'Итоги поиска и выбора файлов'})[0]
   $state.Beside=@($controls | Where-Object {$_ -is [Windows.Forms.CheckBox] -and $_.Text -eq 'Сохранять рядом с исходниками'})[0]
   $state.RefreshCert=@($controls | Where-Object {$_ -is [Windows.Forms.Button] -and $_.Text -eq 'Обновить'})[0]
   $state.Pick=@($controls | Where-Object {$_ -is [Windows.Forms.Button] -and $_.Text -eq 'Выбрать файлы...'})[0]
   $options=@($controls | Where-Object {$_.AccessibleName -eq 'Автовыбор только подписанных файлов'})
   & $assert ($options.Count -eq 1) 'A default-ON signed-file preselection option must be available.'
   $state.OnlySigned=$options[0]
   & $assert $state.OnlySigned.Checked 'An old profile without the new option must default to ON.'
  }
  $grid=$state.Grid
  if($state.Phase -eq 0){
   if($grid.Rows.Count -ne 3){return}
   & $assert ($state.Calls -eq 1) 'A saved source must be scanned once automatically on startup.'
   $checked=@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value})
   & $assert ($checked.Count -eq 1 -and $checked[0].Tag.SourcePath -ceq $document) 'Only the exact signed document may be preselected; print and archive stay visible unchecked.'
   & $assert ($state.Form.AcceptButton.Enabled -and $state.Naming.SelectedIndex -eq 1) 'A signed source must remain signable with the chosen short naming format.'
   $state.OnlySigned.Checked=$false;& $next 1;return
  }
  if($state.Phase -eq 1){
   if($grid.Rows.Count -ne 3){return}
   & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 2) 'Turning the option OFF must restore folder defaults while leaving archives unchecked.'
   & $assert (-not $state.Form.AcceptButton.Enabled) 'Selected files with the same target name must be blocked before starting the batch.'
   & $assert (@($grid.Rows | Where-Object {[string]$_.Cells[2].Value -match 'имя подписи'}).Count -eq 2) 'Conflicting selected targets must be identified in the preview.'
   $printRow=@($grid.Rows | Where-Object {$_.Tag.SourcePath -ceq $print})[0];$printRow.Cells[0].Value=$false
   & $assert $state.Form.AcceptButton.Enabled 'Unchecking the conflicting source must immediately enable signing.'
   $state.OnlySigned.Checked=$true;& $next 2;return
  }
  if($state.Phase -eq 2){
   if($grid.Rows.Count -ne 3){return}
   & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 1) 'Turning the option ON must recompute automatic choices.'
   $state.Naming.SelectedIndex=0;$state.Beside.Checked=$false
   $state.Output.Text=$root+'-typing';$state.Output.Text=$root+'-output'
   & $next 3;return
  }
  if($state.Phase -eq 3){
   if($grid.Rows.Count -ne 3){return}
   & $assert ($state.Calls -eq $state.BeforeCalls+1) 'A burst of naming/output edits must cause one automatic refresh.'
   & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 1) 'Parameter changes must retain checkbox choices.'
   & $assert (-not [IO.Directory]::Exists($root+'-output')) 'Preview must not create the output directory.'
   $state.Pick.PerformClick()
   & $assert ($grid.Rows.Count -eq 2 -and @($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 2) 'Explicit picks must remain explicit even without a confirmed signature, including archives.'
   @($grid.Rows | Where-Object {$_.Tag.SourcePath -ceq $archive})[0].Cells[0].Value=$false
   $state.Naming.SelectedIndex=2;& $next 4;return
  }
  if($state.Phase -eq 4){
   if($grid.Rows.Count -ne 2){return}
   & $assert (@($state.Plan.SourceFiles).Count -eq 2 -and -not $state.Plan.Recurse) 'Automatic refresh must retain exact explicit-file scope.'
   & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 1) 'Automatic refresh must retain unchecked explicit files.'
   $state.Source.Text=$second+'-partial';$state.Source.Text=$second+'-partial2';$state.Source.Text=$second
   & $next 5;return
  }
  if($state.Phase -eq 5){
   if($grid.Rows.Count -ne 2 -or $state.Calls -eq $state.BeforeCalls){return}
   & $assert ($state.Calls -eq $state.BeforeCalls+1 -and @($state.Plan.SourceFiles).Count -eq 0 -and $state.Plan.Recurse) 'Typing a different source must perform one fresh folder scan.'
   & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 0) 'A new unsigned source must not inherit old checked paths.'
   $state.OnlySigned.Checked=$false;& $next 6;return
  }
  if($state.Phase -eq 6){
   if($grid.Rows.Count -ne 2){return}
   & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 1) 'Option OFF must allow signing a new unsigned file.'
   $state.Certificates=@($certificate,$otherCertificate);$state.RefreshCert.PerformClick();$state.Certificate.SelectedIndex=1
   & $next 7;return
  }
  if($state.Phase -eq 7){
   if($grid.Rows.Count -ne 2){return}
   & $assert (@($grid.Rows | Where-Object {$_.Tag.SignaturePath.EndsWith('other_petrov.sig')}).Count -eq 2 -and $state.Naming.SelectedIndex -eq 2) 'Certificate changes must rebuild both same-basename targets while retaining the selected naming format.'
   & $assert (@($grid.Rows | Where-Object {[bool]$_.Cells[0].Value}).Count -eq 1 -and $state.Form.AcceptButton.Enabled) 'Only the checked source may participate in target-name conflicts.'
   $state.Throw=$true;$state.Naming.SelectedIndex=0;& $next 8;return
  }
  if($state.Phase -eq 8){
   if($state.Calls -eq $state.BeforeCalls){return}
   & $assert ($grid.Rows.Count -eq 0 -and -not $state.Form.AcceptButton.Enabled -and $state.Summary.Text -like '*SYNTHETIC PREVIEW FAILURE*') 'An automatic discovery error must be inline and leave signing unavailable.'
   $state.Throw=$false;$state.Naming.SelectedIndex=2;& $next 9;return
  }
  if($state.Phase -eq 9){
   if($grid.Rows.Count -ne 2){return}
   & $assert $state.Form.AcceptButton.Enabled 'Automatic preview must recover after an error.'
   & $assert ($state.Saves -contains $false -and $state.Saves -contains $true) 'Both option states must be saved.'
   $state.Phase=10;$timer.Stop();$state.Form.CancelButton.PerformClick()
  }
 }catch{
  $state.Error=$_.Exception.ToString();$timer.Stop()
  foreach($form in @([Windows.Forms.Application]::OpenForms)){$form.Close()}
 }
}.GetNewClosure())
try{
 $timer.Start()
 $result=Show-ActSignerWindow -CertificateProvider {[pscustomobject]@{Certificates=$state.Certificates;Warnings=@()}}.GetNewClosure() -PlanProvider $provider -FilePickerProvider {return @($print,$archive)}.GetNewClosure()
 if($null -ne $state.Error){throw $state.Error}
 & $assert ($state.Phase -eq 10 -and $null -eq $result) 'Every automatic preview scenario must finish without signing.'
 Write-Host 'PASS: automatic startup/parameter refresh, exact signed-file preselection, checkbox preference, selected collision guard, explicit scope, debounce and inline error recovery.'
}finally{
 $timer.Stop();$timer.Dispose();Remove-Module $module -Force
 if($null -eq $priorSaveBlock){Remove-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -ErrorAction SilentlyContinue}else{Set-Item -LiteralPath 'Function:\global:Save-ActSignerSettings' -Value $priorSaveBlock}
 foreach($directory in @($root,$second)){
  $full=[IO.Path]::GetFullPath($directory)
  if(-not $full.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup target'}
  Remove-Item -LiteralPath $full -Recurse -Force
 }
}
