<#
    .SYNOPSIS
    Script to add EU public holidays to Microsoft Teams.
    
    .DESCRIPTION
    This script will create the schedules for all returned public holidays from the openholidaysapi.org service.
    Version 0.1 1/5/2023 Robert Pearman

    Provided as is, no warranty and all that.

    .EXAMPLE
    .\Add-EuHolidays.ps1 -countryCode FR -startYear 2024 -endyear 2026
    
    .NOTES
    API Does not return dates in the past.
    
#>
param(
    [Parameter(mandatory=$true)]
    [string]$countryCode,
    [Parameter(mandatory=$true)]
    [string]$startYear,
    [Parameter(mandatory=$true)]
    [string]$endYear
)
$dateObjs = New-Object System.Collections.ArrayList
$dates = Invoke-RestMethod -uri "https://openholidaysapi.org/PublicHolidays?countryIsoCode=$countryCode&languageIsoCode=GB&validFrom=$startYear-01-01&validTo=$endYear-12-31" -ContentType "application/json"
if($dates){
    foreach ($date in $dates){
        $dateObj = [pscustomObject]@{
            Name = $date.name.text
            Start = Get-Date $date.startdate
            End = (get-date $date.endDate).AddDays(1) 
            Year = (Get-Date $date.startdate).year
        }
        $dateObjs.add($dateObj) | Out-Null
    }
    $years = $dateObjs | Group-Object Year 
    foreach ($year in $years){
        $holidays = $year.group
        $scheduleName = "Public Holidays - $countryCode - $($year.name)"
        Write-Output "Looking for schedule : $scheduleName"
        do{
            $schedule = Get-CsOnlineSchedule | where-object { $_.Name -eq $scheduleName }
            if(!($schedule)){
                Write-Output "Adding Schedule : $scheduleName"
                # Adding Christmas Day by default
                $christmasDay = New-CsOnlineDateTimeRange -Start (Get-Date -Format 25/12/$($year.name)) -end (Get-Date -Format 27/12/$($year.name))
                $schedule = New-CsOnlineSchedule -Name $scheduleName -FixedSchedule -DateTimeRanges $christmasDay
                Write-Output "Waiting 20 Seconds for Schedule Creation.."
                Start-Sleep 20
                $found = 0
                $skipDays = @(
                    "Christmas Day"
                    "Boxing Day"
                    "St. Stephen's Day"
                    "2nd Day of Christmas"
                )
                foreach ($holiday in $holidays){
       
                    if(($skipDays) -contains $holiday.Name){
                        # Skip
                    }
                    else{
                        Write-Output "Adding Holiday $($holiday.name)"
                        $hol = New-CsOnlineDateTimeRange -Start $holiday.start.date.ToString().split(" ")[0] -End $holiday.end.date.toString().split(" ")[0]
                        # check for duplicate dates
                        $schedule.FixedSchedule.DateTimeRanges += $hol
                        Set-CsOnlineSchedule -Instance $schedule
                    }
                }
                Write-Output "Saving Schedule $scheduleName"
            }
            else{
                Write-Output "Schedule Found!"
                $found = 1
            }
        }
        until($found -eq 1)
    }
}
else{
    Write-Warning "No Dates Found for : $countryCode"
}
