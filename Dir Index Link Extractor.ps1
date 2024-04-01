# Function to download webpage content
function Download-Webpage {
    param(
        [string]$Url
    )
    $webRequest = [System.Net.WebRequest]::Create($Url)
    $webResponse = $webRequest.GetResponse()
    $reader = New-Object System.IO.StreamReader $webResponse.GetResponseStream()
    $content = $reader.ReadToEnd()
    $reader.Close()
    $webResponse.Close()
    return $content
}

# Function to extract file links from HTML content
function Get-FileLinks {
    param(
        [string]$HtmlContent
    )
    $regex = '(?<=href=")[^"]+(?=")'
    $matches = [regex]::Matches($HtmlContent, $regex)
    $fileLinks = @()
    foreach ($match in $matches) {
        $link = $match.Value
        if ($link -match '\.[a-zA-Z0-9]{1,4}$') {
            $fileLinks += $link
        }
    }
    return $fileLinks
}

# Main script
$directoryUrl = "https://example.com/"
$htmlContent = Download-Webpage -Url $directoryUrl
$fileLinks = Get-FileLinks -HtmlContent $htmlContent

# Output file links
foreach ($link in $fileLinks) {
    Write-Output $directoryUrl$link | Out-File -append -FilePath .\Files.txt
}