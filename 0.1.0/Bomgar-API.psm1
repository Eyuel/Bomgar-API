$script:defaultBomgarVaultFolder = "$Env:LOCALAPPDATA\Bomgar-API\"
$script:defaultBomgarVaultLocation = "$Env:LOCALAPPDATA\Bomgar-API\bomgarVault.conf"

function Initialize-BomgarAPI{
    param (
    [Parameter(Mandatory=$false)]
    [bool] $ReturnBaseURL=$false
    )
    $vaultFile = $script:defaultBomgarVaultLocation
    if(Test-Path $vaultFile)
    {
        $vaultValue = Get-BomgarVault -VaultPath $vaultFile
        $AuthCred, $baseURL = $vaultValue.vaultKey, $vaultValue.baseURL
    }
    else
    {
        Write-Host "You currently don't have a localvault setup. Please enter your Bomgar API Credentials"
        $userResponse = Invoke-BomgarCredPrompt
        $AuthCred, $baseURL = $userResponse.vaultKey, $userResponse.baseURL
        $userPrompt = Read-Host "Would you like to save your API credentials in an encrypted Vault? 'Y' for yes any other key for no."
        if($userPrompt -eq 'y'){
            New-BomgarVault -BaseURL $baseURL -AuthCred $AuthCred -VaultPath $vaultFile
        }
    }
    $script:vaultObject = @{"BaseURL"=$baseURL; "vaultKey"=$AuthCred}
    return $script:vaultObject
}

function Invoke-BomgarCredPrompt{
    Write-Host "Welcome to Bomgar API Services."
    Write-Host "Initializing your Authentication."
    $apiKey = Read-Host "Enter your API KEY"
    $apiSecret = Read-Host "Enter your API SECRET"
    $baseURL = Read-Host "Enter the baseURL"
    $authHeader = ConvertTo-Base64 ("$($apiKey):$($apiSecret)")
    $script:vaultObject = @{"BaseURL"=$baseURL; "vaultKey"=$authHeader}
    return $script:vaultObject
}
function New-BomgarVault{
    param (
    [Parameter(Mandatory=$false)]
    [string] $BaseURL,
    [Parameter(Mandatory=$false)]
    [string] $AuthCred,
    [Parameter(Mandatory=$false)]
    [string] $VaultPath=$script:defaultBomgarVaultLocation
    )
    if(!($BaseURL) -or !($AuthCred)){
        $userResponse = Invoke-BomgarCredPrompt
        $BaseURL = $userResponse.baseURL
        $AuthCred = $userResponse.vaultKey
    }
    $vaultKey = ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $AuthCred -AsPlainText -Force)
    $script:vaultObject = @{"BaseURL"=$BaseURL; "vaultKey"=$vaultKey}
    if(!(Test-Path $script:defaultBomgarVaultFolder)){
        New-Item -Path $script:defaultBomgarVaultFolder -ItemType Directory | Out-Null
    }
    $encryptedVaultObject = @{"BaseURL"=$BaseURL; "vaultKey"=$vaultKey}
    $script:vaultObject = @{"BaseURL"=$BaseURL; "vaultKey"=$AuthCred}
    Set-Content -Value ($encryptedVaultObject | ConvertTo-Json) -Path $VaultPath
    return $script:vaultObject
}

function Set-BomgarVault{
    param (
    [Parameter(Mandatory=$false)]
    [string] $BaseURL,
    [Parameter(Mandatory=$false)]
    [string] $AuthCred,
    [Parameter(Mandatory=$false)]
    [string] $VaultPath=$script:defaultBomgarVaultLocation
    )
    try{
        $vaultValues = Get-BomgarVault $VaultPath
    } catch{
        Write-Host "Corrupted vault file. Try running Remove-BomgarVault first."
        Initialize-BomgarAPI
        return
    }
    if($vaultValues){
        $tempVaultKey = $vaultValues.vaultKey
        $tempBaseURL  = $vaultValues.baseURL
        if(!$BaseURL){$BaseURL = $tempBaseURL}
        if(!$AuthCred){$AuthCred = $tempVaultKey}
    }
    else{
        if(!$AuthCred -or !$BaseURL){
            Write-Host "Invalid or missing Bomgar Vault. Creating a new Vault."
            Initialize-BomgarAPI
            return
        }
    }
    $vaultKey = ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $AuthCred -AsPlainText -Force)
    $encryptedVaultObject = @{"BaseURL"=$BaseURL; "vaultKey"=$vaultKey}
    $script:vaultObject = @{"BaseURL"=$BaseURL; "vaultKey"=$AuthCred}
    Set-Content -Value ($encryptedVaultObject | ConvertTo-Json) -Path $VaultPath
}

function Get-BomgarVault{
    param (
    [Parameter(Mandatory=$false)]
    [string] $VaultPath=$script:defaultBomgarVaultLocation
    )
    if(!(Test-Path $VaultPath) -and !($script:vaultObject)){
        Write-Host "No Bomgar vault found. First create a vault using New-BomgarVault or running Initialize-BomgarAPI cmdlet"
        return
    }
    try{
        if($script:vaultObject){
            $localVaultObject = $script:vaultObject
            $baseURL = $localVaultObject.baseURL
            $AuthCred = $localVaultObject.vaultKey
        } else{
            $localVaultObject =  (Get-Content $VaultPath) | ConvertFrom-Json
            $encryptedAuth = $localVaultObject.vaultKey
            $baseURL = $localVaultObject.baseURL
            $secureAuth = ConvertTo-SecureString -String $encryptedAuth
            $AuthCred = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAuth))
        }
    } catch{
        Write-Host "Error reading from Bomgar vault. Try running Remove-BomgarVault command first."
        return
    }
    $script:vaultObject = @{"BaseURL"=$baseURL; "vaultKey"=$AuthCred}
    return $script:vaultObject
}

function Update-BomgarVault{
    if(!$script:vaultObject){
        Write-Host "No cached vault"
    } else{
        $localVaultObject = $script:vaultObject
        $baseURL = $localVaultObject.baseURL
        $AuthCred = $localVaultObject.vaultKey
        Set-BomgarVault -BaseURL $baseURL -AuthCred $AuthCred
    }
}
function Remove-BomgarVault{
    param (
    [Parameter(Mandatory=$false)]
    [string] $VaultPath=$script:defaultBomgarVaultFolder
    )
    if(Test-Path $VaultPath){
        Remove-Item $VaultPath -Recurse
    } else{
        Write-Host "No Bomgar vault found."
    }
}
function Get-BomgarAPIToken{
    $initObject = Initialize-BomgarAPI
    $authHeader, $baseURL = $initObject.vaultKey, $initObject.baseURL
    $header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $header.Add("Authorization", "Basic $($authHeader)")
    $body = @{grant_type="client_credentials"}
    $authUrl = "$baseURL/oauth2/token"
    $response = Invoke-RestMethod $authUrl -Method 'POST' -Headers $header -Body $body
    $authKey = $response.access_token
    return $authKey
}
function Get-BomgarJumpClients{
  param (
  [Parameter(Mandatory=$false)]
  [int] $curPage=0,
  [Parameter(Mandatory=$false)]
  [bool] $headerFlag=$false
  )
  $baseURI = (Get-BomgarVault).baseURL
  $authKey = Get-BomgarAPIToken
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("Authorization", "Bearer $($authKey)")
  $headers.Add("Accept", "application/json")
  try{
      $clientRequestURL = "$baseURI/api/config/v1/jump-client?current_page=$curPage"
      $jumpClientData = Invoke-RestMethod $clientRequestURL -Method 'Get' -Headers $headers
   } catch{
      $authKey = Get-BomgarAPIToken
  }
  if($headerFlag -eq $true){
      $jumpClientHeader = (Invoke-WebRequest $clientRequestURL -Method 'Get' -Headers $headers).Headers
      return $jumpClientHeader
  }
  return $jumpClientData
}

function Get-BomgarUsers{
    param (
    [Parameter(Mandatory=$false)]
    [int] $curPage=0,
    [Parameter(Mandatory=$false)]
    [bool] $headerFlag=$false
    )
    $baseURI = (Get-BomgarVault).baseURL
    $authKey = Get-BomgarAPIToken
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $($authKey)")
    $headers.Add("Accept", "application/json")
    try{
        $clientRequestURL = "$baseURI/api/config/v1/user?current_page=$curPage"
        $jumpClientData = Invoke-RestMethod $clientRequestURL -Method 'Get' -Headers $headers
     } catch{
        $authKey = Get-BomgarAPIToken
    }
    if($headerFlag -eq $true){
        $jumpClientHeader = (Invoke-WebRequest $clientRequestURL -Method 'Get' -Headers $headers).Headers
        return $jumpClientHeader
    }
    return $jumpClientData
}

function Invoke-AllBomgarUsers{
    $contentArray = @();
    $response = Get-BomgarUsers 0 $true
    $entries = [int] ($response.'x-bt-pagination-per-page')
    $total = [int] ($response.'x-bt-pagination-total')
    $numPages = [int] ($response.'x-bt-pagination-last-page')
    try{
        $entries = [int] $entries
        $total = [int] $total
        $numPages = [int] $numPages
    }catch{
        $entries = [int] $entries[0]
        $total = [int] $total[0]
        $numPages = [int] $numPages[0]
    } while($numPages -gt 0){
        $response = Get-BomgarUsers $numPages $false;
        $contentArray += $response;
        $numPages -= 1
}
    return $contentArray
}

function Invoke-AllBomgarClients{
    $contentArray = @();
    $response = Get-BomgarJumpClients 0 $true
    $entries = [int] ($response.'x-bt-pagination-per-page')
    $total = [int] ($response.'x-bt-pagination-total')
    $numPages = [int] ($response.'x-bt-pagination-last-page')
    try{
        $entries = [int] $entries
        $total = [int] $total
        $numPages = [int] $numPages
    }catch{

        $entries = [int] $entries[0]
        $total = [int] $total[0]
        $numPages = [int] $numPages[0]
    }
    while($numPages -gt 0){
        $response = Get-BomgarJumpClients $numPages $false;
        $contentArray += $response;
        $numPages -= 1
}
    return $contentArray
}


function ConvertTo-Base64 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$StringToEncode
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($StringToEncode)
    $base64String = [System.Convert]::ToBase64String($bytes)
    return $base64String
}

function ConvertFrom-Base64 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Base64String
    )
    $bytes = [System.Convert]::FromBase64String($Base64String)
    $plainText = [System.Text.Encoding]::UTF8.GetString($bytes)
    return $plainText
}




# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
Export-ModuleMember -Function *-*