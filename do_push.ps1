Set-Location $PSScriptRoot
git push origin master 2>&1
Write-Host "PUSH_EXIT:$LASTEXITCODE"
git log --oneline -3 2>&1
