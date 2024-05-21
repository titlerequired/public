<#
    .SYNOPSIS
    Script to add EU public holidays to Microsoft Teams.
    
    .DESCRIPTION
    This script will create the schedules for all returned public holidays from the openholidaysapi.org service.
    Version 0.1 14/04/2023 Robert Pearman

    Provided as is, no warranty and all that.

    .EXAMPLE
    .\Add-UKHolidays.ps1
    
    .NOTES
    API Does not return dates in the past.
    
#>
$dates = (Invoke-Restmethod https://www.gov.uk/bank-holidays.json -ContentType "application/json") 
$currentDate = [datetime]::Now.date 
$engWalDates = $dates.'england-and-wales'.events
$scotDates = $dates.'scotland'.events
$niDates = $dates.'northern-ireland'.events
$dateObjs = New-Object System.Collections.ArrayList
$useDates = @(
    $engWalDates
    #$scotDates # commented out for Scotland
    #$niDates # commented out for Northern Ireland
)
foreach ($date in $useDates){
    $start = Get-Date $date.date
    $year = $start.Year
    if(($start) -ge $currentDate){
        $dateObj = [pscustomObject]@{
            Name = $date.title
            Start = $start
            End = $start.adddays(1) 
            Year = $year
        }
        $dateCheck = $dateObjs | Where-Object { ($_.Name -eq $dateObj.name) -and ($_.Start -eq $dateobj.start) } # look for duplicate dates
        if(!($dateCheck)){
            $dateObjs.add($dateObj) | Out-Null
        }
        else{
            Write-Output "Duplicate Date : $($dateObj.name)"
        }
    }
}
$years = $dateObjs | Group-Object Year 
foreach ($year in $years){
    $holidays = $year.group
    $scheduleName = "UK Bank Holidays - $($year.name)"
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
                "Christmas Day" # Skipped as already added during schedule setup
                "Boxing Day" # Skipped as already added during schedule setup
                "St Andrew’s Day" # Example Skip Day
                "St Patrick’s Day" # Example Skip Day
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