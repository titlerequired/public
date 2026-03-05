using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# Interact with query parameters or the body of the request.
$name = $Request.query.name
$regex = $Request.Query.Regex
$rBody = $request.Body.json
$sBody = $rBody
Write-Host "Request Received"
Write-Host "Regex Query: $regex"
Write-Host "RBody JSON : $rbody"
if($regex){
    [regex]$regexExpr = $regex
    $checkEx = $regexExpr.matches($rBody)
    $date = [datetime]::now
    if ($checkEx) {
        $jsonBody = [pscustomobject]@{
            Date    = $date.toString()
            Count   = ($checkEX.groups | measure-object).count
            expression = $regex
            matches = @(
                foreach ($match in $checkEx.groups) {
                    @{
                       group  = $match.name
                       Index  = $match.Index
                        Length = $match.length
                        Match  = $match.value
                    }
                }
            )
        }
    }
    else{
        $jsonBody = [pscustomobject]@{
            Date       = $date.toString()
            Count      = ($checkEX.groups | measure-object).count
            expression = $regex
            string = $sBody
        }
    }
    $body = $jsonBody | convertTo-Json -Depth 8
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
