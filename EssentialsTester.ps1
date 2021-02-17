# Windows Server Essentials & SBS 2011 Essentials Configuration Tester Tool
# Written by Robert Pearman
$Global:CurrentVersion = "Version: 2.22"

# Tool designed to check basic IIS, Certificate and Service settings / configuration.
# Not a replacement for other troubleshooting or BPA.
# Provided AS IS - no warranties or anything like that
# Please send feedback or bugs to essentials@titlerequired.com

# Hope you find this tool useful.

# Build Log File
$date = Get-Date -format ddMM-HHmmss
$location = Get-Location
$myLocation = $location.Path
$logFileName = "EssentialsTester-$date.csv"
$logLocation = $env:tmp
$date
$logFile = $loglocation + "\" + $logFileName

if(!(Test-Path $logFile))
{
    New-Item $logFile -ItemType File | Out-Null
    Add-Content $logFile $Global:CurrentVersion
}

# IIS Functions
function apppools
{
    $appPools = (Get-ItemProperty IIS:\AppPools\* | Foreach { $_.Name })
    Add-Content $logFile "*** Application Pool Checks ***"
    foreach ($pool in $appPools)
    {

        $pool = Get-Itemproperty IIS:\AppPools\$pool | Select *
        $NColor = "White"
        $3Color = "Green"
        $RColor = "Green"
        $SColor = "Green"
        if (($pool.enable32BitAppOnWin64) -eq "True")
        {
            $3Color = "RED"
        }
        if (($pool.managedRuntimeVersion) -ne "v4.0")
        {
            $RColor = "RED"
            if ((($pool.Name) -match "DefaultAppPool") -and ($Global:OS) -match "Essentials2011" -or "Essentials2008")
            {
                $RColor = "Green"
            }
            if ((($pool.Name) -match "Classic .Net AppPool") -and ($Global:OS) -match "Essentials2011" -or "Essentials2008")
            {
                $RColor = "Green"
            }
        }
        if (($pool.State) -ne "Started")
        {
            $SColor = "RED"
        }
        $poolName = "Pool Name"
        $32bitApps = "Enabled 32bit Apps"
        $NETVersion = ".NET Version"
        $state = "State"

        $poolName = $poolName.PadRight(20, " ")
        $32bitApps = $32bitApps.PadRight(20, " ")
        $NETVersion = $NETVersion.PadRight(20, " ")
        $state = $state.PadRight(20, " ")
        if ((($Ncolor) -eq "Red") -or (($Rcolor) -eq "Red") -or (($Scolor) -eq "Red") -or (($3color) -eq "Red") )
        {
            Write-Host "$poolName : " -NoNewline; Write-Host $pool.Name -ForegroundColor $Ncolor
            Write-Host "$32bitApps : " -NoNewLine; Write-Host $pool.enable32BitAppOnWin64 -ForegroundColor $3color
            Write-Host "$NETVersion : " -NoNewline; Write-Host $pool.managedRuntimeVersion -ForegroundColor $Rcolor
            Write-Host "$State : " -NoNewline; Write-Host $pool.state -ForegroundColor $Scolor
            Write-Host ""

            # Log
            $poolNameError = $pool.Name
            $pool32error = $pool.enable32BitAppOnWin64
            $poolManError = $pool.managedRuntimeVersion
            $poolStateError = $pool.State
            Add-Content $logFile "Error Found"
            Add-Content $logFile "$poolNameError,$pool32error,$poolManError,$poolStateError"
        }
        else
        {
            $poolNameError = $pool.Name
            Add-Content $logFile "$poolNameError, OK"
        }
    }

}
function websites
{
    
    # Defaults
    Add-Content $logFile "*** Web Site Checks ***"
    if (($Global:OS) -eq "Essentials2016")
    {
        $default = "DefaultAppPool"
        $defaultP = "%SystemDrive%\inetpub\wwwroot"
    }
    else
    {
        # Pre 2016 Settings
        $default = "RootApp"
        $defaultP = "C:\Program Files\Windows Server\Bin\webapps\site"
    }
       
    $mac = "MacWebService_App"
    $macp = "C:\Program Files\Windows Server\Bin\WebApps\MacWebService"
    $ssl = "CertWebService_App"
    $sslP = "C:\Program Files\Windows Server\Bin\WebApps\CertWebService"
    $websites = (Get-Itemproperty IIS:\Sites\* | foreach { $_.Name })
    foreach ($site in $websites)
    {
        $site = (Get-Itemproperty IIS:\Sites\$site | Select *)
        
        $WColor = "GREEN"
        $AColor = "White"
        $EColor = "GREEN"
        $Scolor = "GREEN"

        if (($site.State) -ne "Started")
        {
            $scolor = "RED"
        }

        if (($site.Name) -eq "Default Web Site")
        {
            if (($site.ApplicationPool) -ne $default)
            {
                $Wcolor = "RED"
            }
            if (($site.PhysicalPath) -ne $defaultP)
            {
                $EColor = "RED"
            }
        }
        if (($site.Name) -eq "MAC Web Service")
        {
            if (($site.ApplicationPool) -ne $mac)
            {
                $Wcolor = "RED"
            }
            if (($site.PhysicalPath) -ne $MacP)
            {
                $EColor = "RED"
            }
        }
        if (($site.Name) -eq "WSS Certificate Web Service")
        {
            if (($site.ApplicationPool) -ne $ssl)
            {
                Wcolor = RED
            }
            if (($site.PhysicalPath) -ne $SSLP)
            {
                $EColor = "RED"
            }
        }
        $siteName = "Site Name"
        $AppPool = "App Pool"
        $content = "Content"
        $wstate = "State"

        $siteName = $siteName.PadRight(20, " ")
        $AppPool = $AppPool.PadRight(20, " ")
        $content = $content.PadRight(20, " ")
        $wstate = $wstate.PadRight(20, " ")
        # Fix formatting Error R2
        if(($Global:OS) -eq "Essentials2012R2")
        {
            $wstate = "State"
            $wstate = $wstate.PadRight(19, " ")
        }

        if ( (($AColor) -eq "Red") -or (($WColor) -eq "Red") -or (($EColor) -eq "Red") -or (($SColor) -eq "Red") )
        {
            Write-Host "$siteName : " -NoNewline; Write-Host $site.Name -ForegroundColor $Acolor
            Write-Host "$AppPool : " -NoNewline; Write-Host $site.ApplicationPool -ForegroundColor $Wcolor
            Write-Host "$content : " -NoNewline; Write-Host $site.PhysicalPath -ForegroundColor $Ecolor
            Write-Host "$wstate  : " -NoNewLine; Write-Host $site.State -ForegroundColor $Scolor

            Write-Host ""
                        # Log
            $siteNameError = $site.Name
            $siteAppPool = $site.ApplicationPool
            $sitePathError = $pool.PhysicalPath
            $siteStateError = $site.State
            Add-Content $logFile "Error Found"
            Add-Content $logFile "$SiteNameError,$SiteAppPool,$SitePathError,$SiteStateError"

        }
        else
        {
            $siteNameError = $site.Name
            Add-Content $logFile "$siteNameError,OK"    
        }
    }

}
function vdirectory
{
    Add-Content $logFile "*** Virtual Directory Check ***"
    # Defaults
    $CertSrvAppPool = "RootApp"
    $CertSrvPath = "C:\Windows\system32\CertSrv\en-US"
    $ConnectAppPool = "Client_App"
    $ConnectPath = "C:\Program Files\Windows Server\Bin\WebApps\Client"
    $HomeAppPool = "ConnectivityAppPool"
    $HomePath = "C:\Program Files\Windows Server\Bin\WebApps\CloudTest"
    $RemoteAppPool = "RemoteAppPool"
    $RemotePath = "C:\Program Files\Windows Server\Bin\WebApps\RemoteAccess"
    $RPCAppPool = "RootApp"
    $RPCPath = "%windir%\System32\RpcProxy"
    $RPCCAppPool = "RootApp"
    $RPCCPath = "%windir%\System32\RpcProxy"
    $ServicesAppPool = "WebApiService"
    $ServicesPath = "C:\Program Files\Windows Server\Bin\WebApps\WebApi"
    $SetupAppPool = "InitialConfiguration_App"
    $SetupPath = "C:\Program Files\Windows Server\Bin\WebApps\InitialConfiguration"
    $vdirs = "Connect","Home","Remote"
    
    if (($global:OS) -eq "Essentials2012R2")
    {
        $CertSrvAppPool = "DefaultAppPool"
        $vdirs = $vdirs+=("Services")
        $vdirs = $vdirs+=("CertSrv")
        # Test if Anywhere Access is enabled
        $AA = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Server\RDP')
        if (($AA) -ne "True")
        {
            Write-Host ""
            Write-Host "Anywhere Access not configured, skipping RPC Virtual Directories" -foregroundcolor Cyan
            Write-Host ""
        }
        else
        {
            $vdirs = $vdirs+=("RPC")
            $vdirs = $vdirs+=("RpcWithcert")
        }
    }
    if (($global:OS) -eq "Essentials2012")
    {
        $vdirs = $vdirs+=("Setup")
        $vdirs = $vdirs+=("Services")
        $vdirs = $vdirs+=("CertSrv")
        $vdirs = $vdirs+=("RPC")
        $vdirs = $vdirs+=("RpcWithcert")
    }
    if (($global:OS) -eq "Essentials2011")
    {
        $HomeAppPool = "RemoteAppPool"
        $vdirs = $vdirs+=("Setup")
        $vdirs = $vdirs+=("RPC")
        $vdirs = $vdirs+=("RpcWithcert")
    }
    if (($global:OS) -eq "Essentials2008")
    {
        $HomeAppPool = "RemoteAppPool"
        $vdirs = $vdirs+=("Setup")
        $vdirs = $vdirs+=("RPC")
        $vdirs = $vdirs+=("RpcWithcert")
    }
        
    foreach ($vdir in $vdirs)
    {


        $vdir = Get-Itemproperty "iis:\sites\default web site\$vdir" | select *
        $pool = "Green"
        $path = "Green"
    
    
        # CertSrvAppPool
        if (($vdir.Name) -eq "Certsrv")
        {
            if(($CertSrvAppPool) -ne $vdir.applicationPool )
            {
                $pool = "Red"
            }
            if(($CertSrvPath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
    
        # Connect AppPool
        if (($vdir.Name) -eq "Connect")
        {
            if (($ConnectAppPool) -ne $vdir.applicationPool)
            {
                $pool = "Red"
            }
            if(($ConnectPath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
   
        # Home AppPool
        if (($vdir.Name) -eq "Home")
        {
            if(($HomeAppPool) -ne $vdir.applicationPool)
            {
                $pool = "Red"
            }
            if(($HomePath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
    
        # Remote AppPool
        if (($vdir.Name) -eq "remote")
        {
            if(($RemoteAppPool) -ne $vdir.applicationPool)
            {
                $pool = "Red"
            }
             if(($RemotePath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
   
        # RPC AppPool
        if (($vdir.Name) -eq "RPC")
        {
            if(($RPCAppPool) -ne $vdir.applicationPool)
            {
                $pool = "Red"
            }
            if(($RPCPath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
   
        # RPCC AppPool
        if (($vdir.Name) -eq "RPCClient")
        {
            if(($RPCCAppPool) -ne $vdir.applicationPool)
            {
                $pool = "Red"
            }
            if(($RPCCPath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
    
        # Services AppPool
        if (($vdir.Name) -eq "Services")
        {
            if(($ServicesAppPool) -ne $vdir.applicationPool)
            {
                $pool = "Red"
            }
            if(($ServicesPath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
    
        # Setup
        if (($vdir.Name) -eq "Setup")
        {
            if(($SetupAppPool) -ne $vdir.applicationPool)
            {
                $pool = "Red"
            }
            if(($SetupPath) -ne $vdir.PhysicalPath)
            {
                $path = "Red"
            }
        }
        $vname = "Virtual Directory"
        $appPoolP = "Application Pool"
        $ContentP = "Content Path"
        
        $vName = $vName.PadRight(20, " ")
        $appPoolP = $appPoolP.PadRight(20, " ")
        $ContentP = $ContentP.PadRight(20, " ")
        if ((($pool) -eq "Red" -or ($path) -eq "Red"))
        {
            Write-Host "$vname : " -NoNewline; Write-Host $vdir.Path -ForegroundColor White
            Write-Host "$appPoolP : " -NoNewline; Write-Host $vdir.ApplicationPool -ForegroundColor $Pool
            Write-Host "$ContentP : " -NoNewline; Write-Host $vdir.PhysicalPath -ForegroundColor $Path
            Write-Host ""
            $verrorname = $vdir.Path
            $vappPool = $vdir.ApplicationPool
            $vContent = $vdir.physicalPath
            Add-Content $logFile "Error Found"
            Add-Content $logFile "$verrorname,$vappPool,$vContent"
        }
        else
        {
            $verrorname = $vdir.Path
            Add-Content $logFile "$verrorname,OK"
        }
    }

}
function isapi
{
    Add-Content $logFile "*** ISAPI Checks ***"
    # Defaults
    # 32-bit
    $filter32 = "%windir%\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_filter.dll"
    $bit32 = "runtimeVersionv4.0,bitness32"
    # 64-bit
    $filter64 = "%windir%\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_filter.dll"
    $bit64 = "runtimeVersionv4.0,bitness64"

    $filter6411 = "c:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_filter.dll"
    $filter3211 = "c:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_filter.dll"

    $isapif =  (get-webconfiguration -pspath iis:\sites\* -filter "/system.webserver/isapifilters/filter")
    $running = "Green"
    $bit = "Green"
    $path = "Green"
    foreach ($isapi in $isapif)
    {

        if (($isapi.Name) -match "ASP.Net_4.0_32bit")
        {
            if (($isapi.path) -inotmatch $filter32)
            {
                $path = "Red"
                if (($global:os) -match "Essentials2011" -or "Essentials2008")
                {
                    if (($isapi.path) -inotmatch $filter3211)
                    {
                        $Path = "Red"
                    }
                    else
                    {
                        $Path = "Green"
                    }
                }
            }
            if (($isapi.preCondition) -inotmatch $bit32)
            {
                $bit = "Red"
            }
        
        }
        if (($isapi.Name) -match "ASP.Net_4.0_64bit")    
        {
            if (($isapi.path) -inotmatch $filter64)
            {
                $path = "Red"
                if (($global:os) -match "Essentials2011" -or "Essentials2008")
                {
                    if (($isapi.path) -inotmatch $filter6411)
                    {
                        $Path = "Red"
                    }
                    else
                    {
                        $Path = "Green"
                    }
                }
            }
            if (($isapi.preCondition) -inotmatch $bit64)
            {
                $bit = "Red"
            }
        }
        if (($isapi.enabled) -inotmatch "true")
        {
            $running = "Red"
        }
        $isv = "ISAPI Version"
        $isvp  = "Path"
        $isve  = "Enabled"
        $isvn  = ".NET Version"

        $isv = $isv.PadRight(20, " ")
        $isvp = $isvp.PadRight(20, " ")
        $isve = $isve.PadRight(20, " ")
        $isvn = $isvn.PadRight(20, " ")
        if(( ($path) -eq "Red") -or (($running) -eq "Red") -or ($bit) -eq "Red")
        {
            Write-Host "$isv : " -NoNewline; Write-Host $isapi.Name -ForegroundColor White
            Write-Host "$isvp : " -NoNewline; Write-Host $isapi.path -ForegroundColor $Path
            Write-Host "$isve : " -NoNewline; Write-Host $isapi.enabled -ForegroundColor $Running
            Write-Host "$isvn : " -NoNewline; Write-Host $isapi.PreCondition -ForegroundColor $bit
            Write-Host ""
            $iapiName = $isapi.Name
            $iapiPath = $isapi.path
            $iapiEn = $isapi.enabled
            $iapiPre = $isapi.PreCondition
            Add-Content $logFile "Error Found"
            Add-Content $logFile "$iapiName,$iapiPath,$iapiEn,$iapiPre"
        }
        else
        {
            $iapiName = $isapi.Name
            $iapiPath = $isapi.path
            Add-Content $logFile "$iapiPath,OK"
        }

    }    
}
function IISSSL
{

    Add-Content $logFile "*** SSL Checks ***"
    $Websites = "WSS Certificate Web Service","Mac Web Service","Default Web Site"
    $WSSCert = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows Server\Identity").LocalMachineCert
    foreach ($site in $websites)
    {
        $Website = (Get-Website $site | select *)
        $thumbs = Get-WebBinding $site | where {$_.Protocol -eq "https" }

        foreach ($thumbprint in $thumbs)
        {
            $thumb = $thumbprint.CertificateHash
            $binding = $thumbprint.bindingInformation


            if (($thumb) -ne $WSSCert)
            {
                $color = "Red"
                $message = "Error: Does not match Dashboard Certificate"
                if(($site) -eq "Default Web Site")
                {
                    if(($binding) -eq "*:443:")
                    {
                        $color = "Green"
                    }
                }
            }
            else
            {
                $color = "Green"
                $message = "OK"
            }
            $wcert =  "Website Name"
            $sslc =  "SSL Certificate"

            $wcert = $wcert.PadRight(20, " ")
            $sslc = $sslc.PadRight(20, " ")
            if (($color) -eq "Red")
            {
                Write-Host "$wcert : " -nonewline; Write-Host "$Site $binding" -ForegroundColor White
                Write-Host "$sslc : " -nonewline; Write-Host $message -ForegroundColor $color
                Write-Host ""
                Add-Content $logFile "$site,$binding,$message"
            }
            else
            {
                Add-Content $logFile "$site,$binding,OK"
            }
        }
        
    }
}
function IISBinding
{
    Add-Content $logFile "*** IIS Binding Check ***"
    $Websites = "Default Web Site","Mac Web Service","WSS Certificate Web Service"
    $DefaultB1 = "http*:80:0"
    $DefaultB2 = "HTTPS*:443:0"
    $DefaultB3 = "HTTPS*:443:$env:Computername" + "1"
    $SSLB = "HTTPS*:65500:0"
    $MACB = "HTTPS*:65520:0"
    foreach ($site in $websites)
    {
        $missingBinding = "Binding Missing"
        $missingBinding = $missingBinding.PadRight(20, " ")
        
        if(($site) -eq "Default Web Site")
        {
            $bcount = (((Get-Website | Where { $_.Name -eq $site }).Bindings).Collection | Measure-Object).Count
            if (($bcount) -lt "3")
            {
                $AA = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Server\RDP')
                if (($AA) -ne "True")
                {
                    if (($bcount) -lt "2")
                    {
                        Write-Host "$missingBinding : " -NoNewline -ForegroundColor White; Write-Host "$site" -ForegroundColor Red
                        Write-Host ""
                        Add-Content $logFile "$site,Error"
                    }
                    else
                    {
                        Add-Content $logFile "$site,OK"
                    }
                           
                }
                else
                {
                    Write-Host "$missingBinding : " -NoNewline -ForegroundColor White; Write-Host "$site" -ForegroundColor Red
                    Write-Host ""
                    Add-Content $logFile "$site,Error"
                }
                
            }
            else
            {
                Add-Content $logFile "$site,OK"
            }     
   
        }
        if(($site) -eq "Mac Web Service")
        {
            $bcount = (((Get-Website | Where { $_.Name -eq $site }).Bindings).Collection | Measure-Object).Count
            if (($bcount) -lt "1")
            {
                Write-Host "$missingBinding : " -NoNewline -ForegroundColor White; Write-Host "$site" -ForegroundColor Red
                Write-Host ""
                Add-Content $logFile "$site,Error"
            }
            else
            {
                Add-Content $logFile "$site,OK"
            }     
    
        }
        if(($site) -eq "WSS Certificate Web Service")
        {
            $bcount = (((Get-Website | Where { $_.Name -eq $site }).Bindings).Collection | Measure-Object).Count
            if (($bcount) -lt "1")
            {
                Write-Host "$missingBinding : " -NoNewline -ForegroundColor White; Write-Host "$site" -ForegroundColor Red
                Write-Host ""
                Add-Content $logFile "$site, Error"
            }
            else
            {
                Add-Content $logFile "$site,OK"
            }     
            
        }




    }


    foreach ($site in $websites)
    {
        $Website = (Get-Website $site | select *)
        $Socket = ($website | foreach { $_.Bindings }).Collection
        
        foreach ($S in $socket)
        {
            $string = $s.Protocol + $s.bindingInformation + $s.sslFlags
            if (($website.Name) -eq "Default Web Site")
            {
                if(($s.Protocol) -eq "http")
                {
                    if (($string) -ne $DefaultB1)
                    {
                        $B1 = "Red"
                    }
                    else
                    {
                        $B1 = "Green"
                    }
                }
                if(($s.Protocol) -eq "HTTPS")
                {
                    if (($string) -ne $DefaultB2)
                    {
                        if(($string) -ne $defaultB3)
                        {
                            $B1 = "Red"    
                        }
                        else
                        {
                            $B1 = "Green"
                        }    
                    }
                    else
                    {
                        $B1 = "Green"
                    }
                }


            }
            if (($website.Name) -eq "WSS Certificate Web Service")
            {
                if (($string) -ne $SSLB)
                {
                    $B1 = "Red"
                }
                else
                {
                    $B1 = "Green"
                }
            }
            if (($website.Name) -eq "MAC Web Service")
            {
                if (($string) -ne $MACB)
                {
                    $B1 = "Red"
                }
                else
                {
                    $B1 = "Green"
                }
            }
            
            $wname = "Website Name"
            $wbind = "Binding"
            
            $wname = $wname.PadRight(20, " ")
            $wbind = $wbind.PadRight(20, " ")
            if (($b1) -eq "Red")
            {            
                Write-Host "$wname : " -NoNewline; Write-Host $Website.Name -ForegroundColor White
                Write-Host "$wbind : " -NoNewline; Write-Host $string -ForegroundColor $B1
                Write-Host ""
            }
        }

    }

}
function IISBinding11
{
    Add-Content $logFile "*** IIS Binding Check ***"
    $Websites = "Default Web Site","Mac Web Service","WSS Certificate Web Service"
    $DefaultB1 = "http*:80:0"
    $DefaultB1a = "HTTP*:65510:0"	
    $DefaultB2 = "HTTPS*:443:0"
    $DefaultB2a = "HTTPS*:65515:0"	
    $SSLB = "HTTPS*:65500:0"
    $MACB = "HTTPS*:65520:0"
    
    foreach ($site in $websites)
    {
        $Website = (Get-Website | Where { $_.Name -eq $site } | select *)
		$socket = Get-WebBinding $website.Name | select *
        #$Website
        foreach ($s in $socket)
        {
            $String = $s.Protocol + $s.BindingInformation + "0"
            if (($s.Protocol) -eq "http")
            {
                if (($string) -eq $defaultb1) 
                {
                    $b1 = "Green"   
                }
                else
                {
                    if (($string) -eq $defaultb1a)
                    {
                        $b1 = "Green"
                    }
                    else
                    {
                        $b1 = "Red"
                    }
                    
                }
            }
            if (($s.protocol) -eq "https")
            {
                if (($website.Name) -eq "Mac Web Service")
                {
                    if (($string) -ne $macb)
                    {
                        $b1 = "red"
                    }
                    else
                    {
                        $b1= "green"
                    }
                }
                
                if (($website.Name) -eq "WSS Certificate Web Service")
                {
                    if (($string) -ne $SSLb)
                    {
                        $b1 = "red"
                    }
                    else
                    {
                        $b1= "green"
                    }
                }
                if (($website.Name) -eq "Default Web Site")
                {
                    if (($string) -ne $defaultb2)
                    {
                        if (($string) -ne $defaultb2a)
                        {
                            $b1 = "Red"
                        }
                        else
                    {
                        $b1= "green"
                    }
                    }
                }    
            }

            $wname = "Website Name"
            $wbind = "Binding"
            
            $wname = $wname.PadRight(20, " ")
            $wbind = $wbind.PadRight(20, " ")
            if(($b1) -eq "Red")
            {                        
                Write-Host "$wname : " -NoNewline; Write-Host $Website.Name -ForegroundColor White
                Write-Host "$wbind : " -NoNewline; Write-Host $string -ForegroundColor $B1
                Write-Host ""
                $siteError = $website.Name
                Add-Content $logFile "$siteError,$string"
            }
            else
            {
                $siteError = $website.Name
                Add-Content $logFile "$siteError,OK"
            }
        }

        
    }
    

}
function IISAuthentication
{
    Add-Content $logFile "*** IIS Authentication ***"
    $ErrorActionPreference = "SilentlyContinue"
    $defaultAuth = "anonymousAuthentication"
    $defaultAuthE = "true"
    $sites = get-website | Sort Name

    foreach ($site in $sites)
    {

        $siteCollection = @()
        $name = $site.Name
        $siteCollection += $name
        $vDIRS = Get-ChildItem IIS:\Sites\$name | where {($_.NodeType -eq "directory") -or ($_.NodeType -eq "application") -or ($_.Mode -eq "d----")}
        foreach ($vDIR in $vDIRS)
        {
            $vName = $vDIR.Name
            $vName = "$name\$vName"
            $siteCollection += $vName

        }

        foreach ($dir in $siteCollection)
        {
            $auth = Get-WebConfiguration system.webServer/security/authentication/* "IIS:\Sites\$dir" | select *
            foreach ($obj in $auth)
            {
                $display = "True"
                $element = $obj.ElementTagName
                $element = $element.Split("/")
                $element = $element[3]
                $enabled = $obj.Enabled
                $site = $obj.PSPath
                $site = $site.Split("/")
                $site = $site[3]
                if ((($enabled) -eq "true") -and ($element) -eq $defaultAuth)
                {
                    $color = "Green"
                    #$display = "False"
                }
                else
                {
                    if (($enabled) -eq "True")
                    {
                        # Set Color to Red 
                        $color = "Red"
                        if (($dir) -eq "Default Web Site\Rpc")
                        {
                            if ((($element) -eq "basicAuthentication") -or ($element) -eq "windowsAuthentication" )
                            {
                                $color = "Green"

                            }
                        }
                    
                        if (($dir) -eq "Default Web Site\RpcWithCert")
                        {
                            if ((($element) -eq "iisClientCertificateMappingAuthentication") -or ($element) -eq "clientCertificateMappingAuthentication" )
                            {
                                $color = "Green"

                            }
                        }
                        # Essentials 2012
                        if ((($global:os) -eq "Essentials2012") -or (($global:os) -eq "Essentials2012R2") -or (($global:os) -eq "Essentials2016"))
                        {
                            if (($dir) -eq "Default Web Site\CertSrv")
                            {
                                if (($element) -eq "windowsAuthentication")
                                {
                                    $color = "Green"

                                }
                                else
                                {
                                    $color = "Red"
                                }
                            }
                            if (($dir) -eq "Default Web Site\Connect")
                            {
                                if (($element) -eq "digestAuthentication")
                                {
                                    $color = "Green"

                                }
                                else
                                {
                                    $color = "Red"
                                }
                            }       
                        }    
                    
                    }
                    else
                    {
                        # If Auth type is Disabled - Do Not Display
  
                    }
                }

                if (($color) -eq "Red")
                {
                    # Default - Only Show Auth Errors
                    $siteLabel = "Site"
                    $authLabel = "Authentication"
                    $enabledLabel = "Enabled"
                    $siteLabel = $siteLabel.PadRight(20," ")
                    $authLabel = $authLabel.PadRight(20," ")
                    $enabledLabel = $enabledLabel.PadRight(20," ")
                    Write-Host "$siteLabel : $dir"
                    Write-Host "$authLabel : " -nonewline; Write-Host "$element" -ForegroundColor $color
                    Write-Host "$enabledLabel : $enabled"
                    Write-Host ""
                    Add-Content $logFile "$dir,$element,Error"
                }
                else
                {
                    Add-Content $logFile "$dir,$element,OK"
                }
            }
            
            # SSL Settings
            $dir = $dir.Replace("\","/")
            $sslSettings = Get-WebConfigurationProperty -location $dir -filter "system.webServer/security/access" -name "sslFlags"
            if ((($sslSettings) -like "*Ssl*") -and ($dir) -eq "Default Web Site/Connect") 
            {
                $dirLabel = "Directory"
                $sslLabel = "SSL Settings"
                $dirLabel = $dirLabel.PadRight(20," ")
                $sslLabel = $sslLabel.PadRight(20," ")
                $color = "Red"
                Write-Host "$dirLabel : $dir"
                Write-Host "$sslLabel : " -nonewline; Write-Host "$sslSettings" -ForegroundColor $color
                Write-Host ""
                Add-Content $logFile "$dir,$sslSettings,Error"    
            }
                

            
        }
    }
}
# SSL Function
function SSLChecks
{
    Add-Content $logFile "*** SSL Checks ***"
    if (($global:os) -eq "Essentials2008")
    {
        # Check "C:\ProgramData\Microsoft\Windows Server\Data\CAROOT.cer" Matches Current CA
        # Read ProgramData for .Cer File
        $cert = Get-Item "C:\ProgramData\Microsoft\Windows Server\Data\CAROOT.cer"
        $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certPrint.Import($cert)
        # Capture Thumpprint String
        $ProgDCA = $certPrint.Thumbprint | Out-String

        # Capture CA Data
        Write-Host "Testing CA Name.." -ForegroundColor Yellow
        # Check CA is Alive
        $CAName = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\| foreach { $_.Active }
        $alive = (CertUtil -Ping -Config $env:COMPUTERNAME\$CAName | Out-String)
        $CAON = "Certificate Authority Online" 
        $CAON = $CAON.PadRight(29, " ")
        if ($alive.Contains("successfully"))
        {
            Write-Host "$CAON : " -NoNewLine; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "CA Online, OK"
        }
        else
        {
            Write-Host "$CAON : " -NoNewLine; Write-Host "Error" -ForegroundColor Red
            Add-Content $logFile "CA Online, Error"
        }
        Start-Sleep 2
        
        $CAHash = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$caname | foreach { $_.CACertHash } | out-string
        #$CAHash
        # Remove White Space from Hash
        $CAHash = $CAhash.Replace(" ","")
        #$Hash
        # Check CA Name
        $Server = $env:COMPUTERNAME
        $CANameResult = "Certificate Authority Name"
        $CANameResult = $CANameResult.PADRight(29," ")
        if (($CAName) -inotmatch "$Server-CA")
        {
            Write-Host "$CANameResult : " -NoNewline; Write-Host "Name Error" -ForegroundColor Red
            Add-Content $logFile "CA Name,$CAName,$server,Error"
        }
        else
        {
            Write-Host "$CANameResult : " -NoNewline; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "CA Name, OK"
        }
        # Find CA Cert In Local Personal Store
    
        $LocalCA = get-childitem cert:\localmachine\my | where { $_.Subject -like "*-CA" } | foreach { $_.Thumbprint } | out-string
        $CACertResult = "Certificate Authority Cert"
        $CACertResult = $CACertResult.PadRight(29," ")
        if (($CAHash) -match $LocalCA)
        {
            Write-Host "$CACertResult : " -nonewline; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "CA Cert,OK"
        }
        else
        {
            Write-Host "$CACertResult : " -nonewline; Write-Host "Errors Detected - Local Machine Store" -ForegroundColor RED
            Add-Content $logFile "CA Cert,$CAHash,$localCA,Error"
        }
        # Compare to ProgramData
        Write-Host ""
        Write-Host "Testing /Connect Certificate Package.." -ForegroundColor Yellow
        Start-Sleep 2
        $ConnectCert = "Connect Computer Certificate"
        $ConnectCert = $ConnectCert.PadRight(29," ")
        if (($CAHash) -inotmatch $ProgDCA)
        {
            Write-Host "$ConnectCert : " -nonewline; Write-Host "Errors Detected - ProgramData" -ForegroundColor RED
            Add-Content $logFile "Connect Cert,Error"
        }
        else
        {
            Write-Host "$ConnectCert : " -nonewline; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "Connect Cert,OK"
        }
        # WSS Dashboard Certificate
        Write-Host ""
        Write-Host "Testing Dashboard Certificate.." -ForegroundColor Yellow
        Start-Sleep 2
        $WSDashCert = Get-ItemProperty "HKLM:\Software\Microsoft\Windows Server\Identity" | foreach { $_.LocalMachineCert } 
        $WSSCert = Get-ChildItem cert:\localmachine\my | where { $_.Subject -eq "CN=$env:COMPUTERNAME" } | foreach { $_.Thumbprint }
        $currentLabel = "Current Dashboard Certificate".PadRight(29," ") 
        Write-Host "$currentLabel : " -NoNewline; Write-Host $wsDashCert -ForegroundColor Cyan
        foreach ($cert in $WSSCert)
        {
            $dash = "Dashboard Certificate"
            $dash = $dash.Padright(29," ")
            if (($Cert) -inotmatch "$WSDashCert")
            {
                Write-Host "$dash : " -NoNewline; Write-Host "Error : " -ForegroundColor Red -NoNewline;  Write-Host $cert
                Add-Content $logFile "Dashboard Cert,$wsDashCert,$wssCert,Error"
            }
            else
            {
                Write-Host "$dash : " -NoNewline; Write-Host "OK" -ForegroundColor Green
                Add-Content $logFile "Dashboard Cert,$wsDashCert,$wssCert,OK"
            }
        }

        # Test CRL Download
        # Set CRL Source & Destination
        Write-Host ""
        Write-Host "Testing CRL Download.." -ForegroundColor Yellow
        $source = "http://$Server/CertEnroll/$CAName.crl"
        $destination = "c:\windows\temp\crl.crl"
        $CRLLoc = "CRL Location"
        $CRLLoc = $CRLLoc.PadRight(29," ")
        $CRLDes = "CRL Destination"
        $CRLDes = $CRLDes.PadRight(29," ")
 
        # Download CRL
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($source,$destination)
        $CRLFile = (Test-Path $destination)
        $CRLD = "CRL Download"
        $CRLD = $CRLD.PadRight(29, " ")
        if (($CRLFile) -eq $false)
        {
            Write-Host "$CRLLoc : " -nonewline; Write-Host "$source" -ForegroundColor CYAN 
            Write-Host "$CRLDes : " -nonewline; Write-Host "$destination" -ForegroundColor CYAN
            Write-Host "$CRLD : " -nonewline; Write-Host "Failed" -ForegroundColor Red
            Add-Content $logFile "CRL Download,Error"    
        }
        else
        {
            Remove-Item $destination -Force
            Add-Content $logFile "CRL Download,OK"    
        }
        Write-Host ""
        Write-Host "Unable to fully Test Certificate Authority on this Operating System." -foregroundcolor CYAN
        Write-Host ""
    }
    else
    {
        Import-Module ActiveDirectory
          
        # Check "C:\ProgramData\Microsoft\Windows Server\Data\CAROOT.cer" Matches Current CA
        # Read ProgramData for .Cer File
        $cert = Get-Item "C:\ProgramData\Microsoft\Windows Server\Data\CAROOT.cer"
        $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certPrint.Import($cert)
        # Capture Thumpprint String
        $ProgDCA = $certPrint.Thumbprint | Out-String

        # Capture CA Data
        Write-Host "Testing CA Name.." -ForegroundColor Yellow
        # CA Name
        $CAName = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\| foreach { $_.Active }
        # Check CA is Alive
        $alive = (CertUtil -Ping -Config $env:COMPUTERNAME\$CAName | Out-String)
        $CAON = "Certificate Authority Online" 
        $CAON = $CAON.PadRight(29, " ")
        if ($alive.Contains("successfully"))
        {
            Write-Host "$CAON : " -NoNewLine; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "CA Online, OK"
        }
        else
        {
            Write-Host "$CAON : " -NoNewLine; Write-Host "Error" -ForegroundColor Red
            Add-Content $logFile "CA Online, Error"
        }
        Start-Sleep 2
        #$CAHash
        $CAHash = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$caname | foreach { $_.CACertHash } | out-string
        # Remove White Space from Hash
        $CAHash = $CAhash.Replace(" ","")
        #$Hash
        # Check CA Name
        $Server = $env:COMPUTERNAME
        $Domain = (Get-ADDomain).Name
        $CANameResult = "Certificate Authority Name"
        $CANameResult = $CANameResult.PADRight(29," ")
        if (($CAName) -inotmatch "$Domain-$Server-CA")
        {
            Write-Host "$CANameResult : " -NoNewline; Write-Host "Name Error" -ForegroundColor Red
            Add-Content $logFile "CA Name,$CAName,$server,Error"
        }
        else
        {
            Write-Host "$CANameResult : " -NoNewline; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "CA Name, OK"
        }



        # Find CA Cert In Local Personal Store
    
        $LocalCA = get-childitem cert:\localmachine\my | where { $_.Subject -like "*-CA" } | foreach { $_.Thumbprint } | out-string
        $CACertResult = "Certificate Authority Cert"
        $CACertResult = $CACertResult.PadRight(29," ")
        if (($CAHash) -match $LocalCA)
        {
            Write-Host "$CACertResult : " -nonewline; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "CA Cert,OK"
        }
        else
        {
            Write-Host "$CACertResult : " -nonewline; Write-Host "Errors Detected - Local Machine Store" -ForegroundColor RED
            Add-Content $logFile "CA Cert,$CAHash,$localCA,Error"
        }

        # Compare to ProgramData
        Write-Host ""
        Write-Host "Testing /Connect Certificate Package.." -ForegroundColor Yellow
        Start-Sleep 2
        $ConnectCert = "Connect Computer Certificate"
        $ConnectCert = $ConnectCert.PadRight(29," ")
        if (($CAHash) -inotmatch $ProgDCA)
        {
            Write-Host "$ConnectCert : " -nonewline; Write-Host "Errors Detected - ProgramData" -ForegroundColor RED
            Add-Content $logFile "Connect Cert,Error"
        }
        else
        {
            Write-Host "$ConnectCert : " -nonewline; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "Connect Cert,OK"
        }
        
        # Test CRL Download
        Write-Host ""
        Write-Host "Testing CRL Download.." -ForegroundColor Yellow
        # Set CRL Source & Destination
        $source = "http://$Server/CertEnroll/$CAName.crl"
        $destination = "c:\windows\temp\crl.crl"
        $CRLLoc = "CRL Location"
        $CRLLoc = $CRLLoc.PadRight(29," ")
        $CRLDes = "CRL Destination"
        $CRLDes = $CRLDes.PadRight(29," ")
        Write-Host "$CRLLoc : " -nonewline; Write-Host "$source" -ForegroundColor CYAN 
        Write-Host "$CRLDes : " -nonewline; Write-Host "$destination" -ForegroundColor CYAN 
        # Download CRL
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($source,$destination)
        $CRLFile = (Test-Path $destination)
        $CRLD = "CRL Download"
        $CRLD = $CRLD.PadRight(29, " ")
        if (($CRLFile) -eq $false)
        {
            Write-Host "$CRLD : " -nonewline; Write-Host "Failed" -ForegroundColor Red
            Add-Content $logFile "CRL Download,Error"    
        }
        else
        {
            Write-Host "$CRLD : " -nonewline; Write-Host "OK" -ForegroundColor Green
            Add-Content $logFile "CRL Download,OK"
            Remove-Item $destination -Force
        }

        if (($global:os) -InotMatch "Essentials2011")
        {
            # CRL Extensions
            Write-Host ""
            Write-Host "Testing CRL Distribution Configuration.." -ForegroundColor Yellow
            Start-Sleep 2
            $CDPS = ( Get-CACrlDistributionPoint | where-object { $_.Uri -like "http://<Server*" } )
            Write-Host ""
            Write-Host "It is normal to see some 'File Not Found' messages above when using this CmdLet (Get-CACrlDistributionPoint)" -ForegroundColor Cyan
            Write-Host ""
            $CRLE = "CRL Extension (CDP)"
            $CRLE = $CRLE.PadRight(29," ")
            $CRLD = "CRL Extension (CRL)"
            $CRLD = $CRLD.PadRight(29," ") 
            foreach ($CDP in $CDPS)
            {
                $cdpName = $cdp.Uri
                Add-Content $logFile "CRL CDP Add to Cert"
                if (($CDP.AddToCertificateCdp) -ne "True")
                {
                    Write-Host "$CRLE : " -NoNewline; Write-Host "Error" -ForegroundColor Red
                    Add-Content $logFile "CRL CDP,$cdpname,Error"
                }
                else
                {
                    Write-Host "$CRLE : " -NoNewline; Write-Host "OK" -ForegroundColor Green
                    Add-Content $logFile "CRL CDP,$cdpname,OK"
                }
                Add-Content $logFile "CRL CDP Add to Fresh Crl"
                if (($CDP.AddToFreshestCrl) -ne "True")
                {
                    Write-Host "$CRLD : " -NoNewline; Write-Host "Error" -ForegroundColor Red
                    Add-Content $logFile "CRL CDP,$cdpname,Error"
                }
                else
                {
                    Write-Host "$CRLD : " -NoNewline; Write-Host "OK" -ForegroundColor Green
                    Add-Content $logFile "CRL CDP,$cdpname,OK"
                }
            }
        }
        else
        {
            Write-Host ""
            Write-Host "Unable to fully Test Certificate Authority on this Operating System." -foregroundcolor CYAN
            Write-Host ""
        }
        # WSS Dashboard Certificate
        Write-Host ""
        Write-Host "Testing Dashboard Certificate.." -ForegroundColor Yellow
        Start-Sleep 2
        $WSDashCert = Get-ItemProperty "HKLM:\Software\Microsoft\Windows Server\Identity" | foreach { $_.LocalMachineCert } 
        $WSSCert = Get-ChildItem cert:\localmachine\my | where { $_.Subject -eq "CN=$env:COMPUTERNAME" } | foreach { $_.Thumbprint }
        $currentLabel = "Current Dashboard Certificate".PadRight(29," ") 
        Write-Host "$currentLabel : " -NoNewline; Write-Host $wsDashCert -ForegroundColor Cyan
        foreach ($cert in $WSSCert)
        {
            $dash = "Dashboard Certificate"
            $dash = $dash.Padright(29," ")
            if (($Cert) -inotmatch "$WSDashCert")
            {
                Write-Host "$dash : " -NoNewline; Write-Host "Error : " -ForegroundColor Red -NoNewline;  Write-Host $cert
                Add-Content $logFile "Dashboard Cert,$wsDashCert,$wssCert,Error"
            }
            else
            {
                Write-Host "$dash : " -NoNewline; Write-Host "OK" -ForegroundColor Green
                Add-Content $logFile "Dashboard Cert,$wsDashCert,$wssCert,OK"
            }
        }
    }
}
function ConnectSite
{
    Add-Content $logFile "**** Connect Site ****"
    $response = ""
    if (($Global:OS) -eq "Essentials2016")
    {
        $hostName = $env:computername
        $source = "http://$hostname/Connect/default.aspx"
    }
    else
    {
        $source = "http://$env:computername/Connect/default.aspx"
    }
    
    if(($Global:OS -eq "Essentials2008") -or ($Global:OS -eq "Essentials2011")) 
    {
        # SBS 2011 / Home Server / Storage Server
        $req = [System.Net.WebRequest]::Create($source)
        $res = $req.GetResponse()
        $response = $res.StatusCode
        $response = [int]$response

    }
    else
    {
        try{
            $request = Invoke-WebRequest $source
            $response = $request.StatusCode

        }
        catch
        {
            $response = $_.Exception.Response    
            $response = [int]$response.StatusCode
        }
    
    }
    $conLabel = "Connect Website"
    $conLabel = $conlabel.PadRight(20," ")
    
    if (($response) -ne "200")
    {
        $conStatus = "Error"
        $conColor = "Red"
    }
    else
    {
        $conStatus = "OK"
        $conColor = "Green"
    }
    if (($conColor) -eq "Red")
    {
        Write-Host "$conLabel : " -NoNewline; Write-Host "$conStatus" -ForegroundColor $conColor -NoNewline; Write-Host " : $response"
        Write-Host ""
    }
    Add-Content $logFile "$response,$conStatus"

}
function tls
{
    Add-Content $logFile "**** TLS TEST ****"    Write-Host "Checking TLS Version 1.0" -ForegroundColor Yellow    $regPathProto = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"    $regPathCipher = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"    # SSL 2, 3 TLS 1.0 TLS 1.1 TLS 1.2    $protoCols = @(    "TLS 1.0"    )
    foreach($protoCol in $protoCols)    {        $protoColPath = $regPathProto + "\" + $protoCol
        $protoColLabel = $protoCol
        $protoColLabel = $protoColLabel.PadRight(36," ")
        $serverProtoLabel = $protoCol + "\" + "Server"
        $clientProtoLabel = $protoCol + "\" + "Client"
        $serverProtoLabel = $serverProtoLabel.PadRight(32," ")
        $clientProtoLabel = $clientProtoLabel.PadRight(32," ")
        if(!(Test-Path $protoColPath))        {            $tlsCol = "Green"            $tlsMessage = "OK"            # Write-Host "$protoColLabel - " -NoNewline;Write-Host "Path Missing" -ForegroundColor Yellow        }        else        {            $tlsCol = "Yellow"            $tlsMessage = "Error"            $serverProtocol = $protoColPath + "\" + "Server"            if(!(Test-Path $serverProtocol))            {                # Write-Host "$serverProtoLabel - " -NoNewline; Write-Host "Path Missing" -ForegroundColor Yellow            }            else            {                # Look for Item Property                $serverProtoColPropertyDefault = (Get-ItemProperty $serverProtocol).DisabledbyDefault                $serverProtoColPropertyEnabled = (Get-ItemProperty $serverProtocol).Enabled                if(($serverProtoColPropertyDefault -eq "0") -and ($serverProtoColPropertyEnabled -eq "1"))                {                    # Write-Host "$serverProtoLabel - " -NoNewline; Write-Host "Disabled" -ForegroundColor Gray                    $tlsCol = "Green"                    $tlsMessage = "OK"                }                else                {                    $tlsCol = "Red"                    $tlsMessage = "Error"                }            }        }
    }
    Add-Content $logFile "$tlsMessage,$serverProtoColPropertyDefault,$serverProtoColPropertyEnabled"
    if(($tlsCol) -ne "Green")
    {
        Write-Host "$protocolLabel : " -NoNewline ; Write-Host $tlsMessage -ForegroundColor $tlsCol
    }
    Write-Host ""
}
function sfccheck
{
    Write-Host "Checking for Web.Config Corruption.." -ForegroundColor Yellow
    Write-Host ""
    Add-Content $logFile "**** SFC Check TEST ****"
    $sfcCheck = Get-Content "$env:ProgramFiles\Windows Server\Bin\WebApps\Site\web.config" | Where-Object {$_ -like "*%SBSPRODUCTBINPLACEHOLDER%*" }
    $sfcLabel = "SFC Web.Config".PadRight(20," ")
    $sfcOK = "OK"
    $sfcColor = "Green"
    if($sfcCheck)
    {
        $sfcOK = "Error"
        $sfcColor = "Red"
        Add-Content $logFile "SFC Check : Corrupt"
    }
    else
    {
        Add-Content $logFile "SFC Check : OK"
    }
    Write-Host "$sfcLabel : " -NoNewline; Write-Host $sfcOk -ForegroundColor $sfcColor
    Write-Host ""
}
# General Tests
function services
{
    Add-Content $logFile "*** Service Checks ***"
    $services = (Get-Service | where {( $_.DisplayName -like "*Certificate Services*") -or ($_.DisplayName -like "*Windows Server*") } | Sort DisplayName)
    $server = $env:COMPUTERNAME    Write-Host "Testing Services on: " -ForegroundColor White -nonewline; Write-Host " $server" -ForegroundColor Yellow
    Write-Host ""
    foreach ($service in $services)
    {
        #$service
        $Start =  (Get-WmiObject Win32_Service | where {$_.Name -eq $Service.Name }).StartMode
        if (($start) -eq "Auto")
        {
            $startc = "Green"
        }
        if (($start) -eq "Manual")
        {
            $startc = "Yellow"
        }
        if (($start) -eq "Disabled")
        {
            $startc = "Gray"
        }
        $State =  (Get-WmiObject Win32_Service | where {$_.Name -eq $Service.Name }).State
        if (($state) -eq "Running" -and $start -eq "Auto")
        {
            $statec = "Green"
        }
        if (($state) -eq "Running" -and $start -eq "Manual")
        {
            $statec = "Green"
        }
        if (($state) -eq "Running" -and $start -eq "Disabled")
        {
            $statec = "Yellow"
        }
        if (($state) -ne "Running" -and $start -eq "Auto")
        {
            $statec = "Red"
        }
        if (($state) -ne "Running" -and $start -eq "Manual")
        {
            $statec = "Yellow"
        }
        if (($state) -ne "Running" -and $start -eq "Disabled")
        {
            $statec = "Gray"
        }
        $name = $Service.Displayname.ToString()
        $name = $name.Replace("Windows Server Essentials","WSS")
        $name = $name.Replace("Windows Server","WSS")
        $namelength = $name.Length
        if (($Global:OS) -eq "Essentials2012R2")
        {
            $name = $name.PadRight(37, " ")
        }
        else
        {
            $name = $name.PadRight(45, " ")
        }
           
        Write-Host "$name : " -ForegroundColor White -nonewline;Write-Host "$state " -ForegroundColor $statec -nonewline; Write-Host $start -ForegroundColor $startc
        Add-Content $logFile "$name,$state,$statec,$start,$startc"
    }
    
}
function ports
{
    Add-Content $logFile "*** Port Check ***"    $ErrorActionPreference = "SilentlyContinue"    $serverPorts = "80","443","6602","8912","65520","65500"    $os = ((Get-WMIObject Win32_OperatingSystem).Caption).ToString()    if (($os.Contains("Server") -eq "true"))    {        $server = $env:COMPUTERNAME        Write-Host "Testing Service Ports on : " -ForegroundColor White -nonewline; Write-Host " $server" -ForegroundColor Yellow        Write-Host ""    }    else    {        # My IP
        $ipv4 = Get-WmiObject Win32_NetworkAdapter | Where-Object { ($_.AdapterType -eq "Ethernet 802.3") -and ( $_.NetConnectionStatus -eq "2") }
        $ipA = (Get-WmiObject Win32_NetworkadapterConfiguration| Where-Object { $_.Index -eq $ipv4.Index })
        $myIP = $ipA.IPAddress[0]
        $myDNS = $ipA.DNSServerSearchOrder[0]
        Add-Content $logFile "My IP  : $myIP"
        Add-Content $logFile "My DNS : $myDNS"
        Write-Host "IP Address : " -NoNewline; Write-Host "$myIP" -ForegroundColor Yellow        Write-Host "DNS Server : " -NoNewline; Write-Host "$myDNS" -ForegroundColor Yellow        Write-Host ""        Write-Host "Enter the hostname of your Essentials Server :"        $server = read-host        Write-Host "Connecting to.." -ForegroundColor White -nonewline; Write-Host " $server" -ForegroundColor Yellow        $ip = [System.Net.Dns]::GetHostAddresses($server)        if (($ip) -ne $null)
        {
            Write-Host "IP Address Resolved: " -ForegroundColor Cyan -nonewline;
            if (($ip[1]) -eq $null)
            {
                Write-Host $ip[0].IPAddressToString
                $dnsS = $ip[0].IPAddressToString
            }
            else
            {
                # Server IP Detected
                $ip[1].IpAddressToString
                $dnsS = $ip[1].IPAddressToString
            }
            if (($myDNS) -ne $dnsS)
            {
                $dns = "Error"
                $dnsC = "Red"
            }
            else
            {
                $dns = "OK"
                $dnsC = "Green"
            }
            $dnsMessage = "Client DNS Server"
            $dnsMessage = $dnsMessage.PadRight(32," ")
            Write-Host "$dnsMessage : " -NoNewline; Write-Host $dns -ForegroundColor $dnsC
            Add-Content $logFile "$dnsMessage,$dns"
        }
        else
        {
            $resolvedIP = $ip[2].IPAddressToString
            if (($resolvedIP) -eq $myIP)
            {
                Write-Host "DNS Error - Server Not Found" -ForegroundColor Red
                Write-Host
                
            }
            else
            {
                Write-Host "DNS Error - IP Resolution" -ForegroundColor Yellow
                Write-Host
                
            }
            
            Write-Host "Please Check your Client IP Configuration."
            Write-Host ""
            Exit

        }    }        # Test Ports    foreach ($port in $serverPorts)    {        Start-sleep 3        $ErrorActionPreference = "SilentlyContinue"        $socket = new-object Net.Sockets.TcpClient        $socket.Connect("$server",$port)        If (($socket.Connected) -eq "True")        {            $r = "OK"            $rc = "Green"        }        else        {            $r = "Error"            $rc = "Red"        }            if (($port) -eq "80")        {            Write-Host "TCP 80 (Used for Websites)       : " -ForegroundColor White -NoNewline; Write-Host $r -ForegroundColor $rc               Add-Content $logFile "TCP 80,$r"        }        if (($port) -eq "443")        {            Write-Host "TCP 443 (Used for Websites)      : " -ForegroundColor White -NoNewline; Write-Host $r -ForegroundColor $rc               Add-Content $logFile "TCP 443,$r"        }        if (($port) -eq "6602")        {            Write-Host "TCP 6602 (Used for Status)       : " -ForegroundColor White -NoNewline; Write-Host $r -ForegroundColor $rc               Add-Content $logFile "TCP 6602,$r"        }        if (($port) -eq "8912")        {            Write-Host "TCP 8912 (Used for Backups)      : " -ForegroundColor White -NoNewline; Write-Host $r -ForegroundColor $rc               Add-Content $logFile "TCP 8192,$r"        }        if (($port) -eq "65520")        {            Write-Host "TCP 65520 (Used for Mac Website) : " -ForegroundColor White -NoNewline; Write-Host $r -ForegroundColor $rc               Add-Content $logFile "TCP 65520,$r"        }        if (($port) -eq "65500")        {            Write-Host "TCP 65500 (Used for CA Website)  : " -ForegroundColor White -NoNewline; Write-Host $r -ForegroundColor $rc               Add-Content $logFile "TCP 65500,$r"        }        $socket.Close()    }
}
function clienttest
{
    Write-Host "*****************************************************************"  -ForegroundColor CYAN
    Write-Host "**   Essentials Server Configuration Tester (Client Version)   **" -ForegroundColor CYAN
    Write-Host "*****************************************************************"  -ForegroundColor CYAN
    Write-Host ""
    Write-Host "OS Detected: " -NoNewline; Write-Host (Get-WMIObject Win32_OperatingSystem).Caption -ForegroundColor Yellow
    Write-Host "" 
    if (($Global:Version) -gt $Global:CurrentVersion)    {        Write-Host "!! New Version Available !!" -ForegroundColor Black -BackgroundColor Green    }   
    ports
    Write-Host ""
    Write-Host "Review your results, items in red should be investigated."
    Write-Host ""
    
}
function rolecheck
{
    $2012Roles = @(
    "AD-Certificate",
    "ADCS-Cert-Authority",
    "ADCS-Web-Enrollment",
    "AD-Domain-Services",
    "DNS",
    "FileAndStorage-Services",
    "File-Services",
    "FS-FileServer",
    "Storage-Services",
    "NPAS",
    "NPAS-Policy-Server",
    "Remote-Desktop-Services",
    "RDS-Gateway",
    "Web-Server",
    "Web-WebServer",
    "Web-Common-Http",
    "Web-Default-Doc",
    "Web-Dir-Browsing",
    "Web-Http-Errors",
    "Web-Static-Content",
    "Web-Http-Redirect",
    "Web-DAV-Publishing",
    "Web-Health",
    "Web-Http-Logging",
    "Web-Custom-Logging",
    "Web-Log-Libraries",
    "Web-ODBC-Logging",
    "Web-Request-Monitor",
    "Web-Http-Tracing",
    "Web-Performance",
    "Web-Stat-Compression",
    "Web-Dyn-Compression",
    "Web-Security",
    "Web-Filtering",
    "Web-Basic-Auth",
    "Web-CertProvider",
    "Web-Client-Auth",
    "Web-Digest-Auth",
    "Web-Cert-Auth",
    "Web-IP-Security",
    "Web-Url-Auth",
    "Web-Windows-Auth",
    "Web-App-Dev",
    "Web-Net-Ext45",
    "Web-ASP",
    "Web-Asp-Net45",
    "Web-ISAPI-Ext",
    "Web-ISAPI-Filter",
    "Web-Includes",
    "Web-Mgmt-Tools",
    "Web-Mgmt-Console",
    "Web-Mgmt-Compat",
    "Web-Metabase",
    "Web-Lgcy-Mgmt-Console",
    "Web-Lgcy-Scripting",
    "Web-WMI",
    "Web-Scripting-Tools",
    "Web-Mgmt-Service",
    "NET-Framework-45-Features",
    "NET-Framework-45-Core",
    "NET-Framework-45-ASPNET",
    "NET-WCF-Services45",
    "NET-WCF-HTTP-Activation45",
    "NET-WCF-TCP-PortSharing45",
    "BitLocker",
    "EnhancedStorage",
    "GPMC",
    "InkAndHandwritingServices",
    "Server-Media-Foundation",
    "RSAT",
    "RSAT-Feature-Tools",
    "RSAT-Feature-Tools-BitLocker",
    "RSAT-Feature-Tools-BitLocker-RemoteAdminTool",
    "RSAT-Feature-Tools-BitLocker-BdeAducExt",
    "RSAT-Role-Tools",
    "RSAT-AD-Tools",
    "RSAT-AD-PowerShell",
    "RSAT-ADDS",
    "RSAT-AD-AdminCenter",
    "RSAT-ADDS-Tools",
    "RSAT-ADCS",
    "RSAT-ADCS-Mgmt",
    "RSAT-DNS-Server",
    "RSAT-RemoteAccess",
    "RSAT-RemoteAccess-PowerShell",
    "RPC-over-HTTP-Proxy",
    "User-Interfaces-Infra",
    "Server-Gui-Mgmt-Infra",
    "Desktop-Experience",
    "Server-Gui-Shell",
    "PowerShellRoot",
    "PowerShell",
    "PowerShell-ISE",
    "WAS",
    "WAS-Process-Model",
    "WAS-Config-APIs",
    "Windows-Server-Backup",
    "WoW64-Support"
    )
    $2012r2Roles = @(
    "AD-Certificate",    "ADCS-Cert-Authority",    "ADCS-Web-Enrollment",    "AD-Domain-Services",    "DNS",    "FileAndStorage-Services",    "File-Services",    "FS-FileServer",    "FS-BranchCache",    "FS-DFS-Namespace",    "Storage-Services",    "Web-Server",    "Web-WebServer",    "Web-Common-Http",    "Web-Default-Doc",    "Web-Dir-Browsing",    "Web-Http-Errors",    "Web-Static-Content",    "Web-Http-Redirect",    "Web-Health",    "Web-Http-Logging",    "Web-Log-Libraries",    "Web-Request-Monitor",    "Web-Http-Tracing",    "Web-Performance",    "Web-Stat-Compression",    "Web-Security",    "Web-Filtering",    "Web-Basic-Auth",    "Web-Windows-Auth",    "Web-App-Dev",    "Web-Net-Ext45",    "Web-ASP",    "Web-Asp-Net45",    "Web-ISAPI-Ext",    "Web-ISAPI-Filter",    "Web-Includes",    "Web-Mgmt-Tools",    "Web-Mgmt-Console",    "Web-Mgmt-Compat",    "Web-Metabase",    "ServerEssentialsRole",    "NET-Framework-45-Features",    "NET-Framework-45-Core",    "NET-Framework-45-ASPNET",    "NET-WCF-Services45",    "NET-WCF-HTTP-Activation45",    "NET-WCF-TCP-PortSharing45",    "BranchCache",    "GPMC",    "InkAndHandwritingServices",    "Server-Media-Foundation",    "RSAT",    "RSAT-Role-Tools",    "RSAT-AD-Tools",    "RSAT-AD-PowerShell",    "RSAT-ADDS",    "RSAT-AD-AdminCenter",    "RSAT-ADDS-Tools",    "RSAT-ADCS",    "RSAT-ADCS-Mgmt",    "RSAT-DNS-Server",    "RSAT-RemoteAccess",    "RSAT-RemoteAccess-PowerShell",    "FS-SMB1",    "User-Interfaces-Infra",    "Server-Gui-Mgmt-Infra",    "Server-Gui-Shell",    "PowerShellRoot",    "PowerShell",    "PowerShell-ISE",    "WAS",    "WAS-Process-Model",    "WAS-Config-APIs",    "Search-Service",    "Windows-Server-Backup",    "WoW64-Support"    
    )
    $2016Roles = @(
    "AD-Certificate",    "ADCS-Cert-Authority",    "ADCS-Web-Enrollment",    "AD-Domain-Services",    "DNS",    "FileAndStorage-Services",    "File-Services",    "FS-FileServer",    "FS-BranchCache",    "FS-DFS-Namespace",    "Storage-Services",    "NPAS",    "RemoteAccess",    "DirectAccess-VPN",    "Remote-Desktop-Services",    "RDS-Gateway",    "Web-Server",    "Web-WebServer",    "Web-Common-Http",    "Web-Default-Doc",    "Web-Dir-Browsing",    "Web-Http-Errors",    "Web-Static-Content",    "Web-Http-Redirect",    "Web-Health",    "Web-Http-Logging",    "Web-Log-Libraries",    "Web-Request-Monitor",    "Web-Http-Tracing",    "Web-Performance",    "Web-Stat-Compression",    "Web-Security",    "Web-Filtering",    "Web-Basic-Auth",    "Web-Client-Auth",    "Web-IP-Security",    "Web-Windows-Auth",    "Web-App-Dev",    "Web-Net-Ext45",    "Web-ASP",    "Web-Asp-Net45",    "Web-ISAPI-Ext",    "Web-ISAPI-Filter",    "Web-Includes",    "Web-Mgmt-Tools",    "Web-Mgmt-Console",    "Web-Mgmt-Compat",    "Web-Metabase",    "Web-Scripting-Tools",    "WDS",    "WDS-Deployment",    "WDS-Transport",    "ServerEssentialsRole",    "NET-Framework-45-Features",    "NET-Framework-45-Core",    "NET-Framework-45-ASPNET",    "NET-WCF-Services45",    "NET-WCF-HTTP-Activation45",    "NET-WCF-TCP-PortSharing45",    "BranchCache",    "GPMC",    "CMAK",    "RSAT",    "RSAT-Role-Tools",    "RSAT-AD-Tools",    "RSAT-AD-PowerShell",    "RSAT-ADDS",    "RSAT-AD-AdminCenter",    "RSAT-ADDS-Tools",    "RSAT-ADCS",    "RSAT-ADCS-Mgmt",    "RSAT-DNS-Server",    "RSAT-NPAS",    "RSAT-RemoteAccess",    "RSAT-RemoteAccess-Mgmt",    "RSAT-RemoteAccess-PowerShell",    "RPC-over-HTTP-Proxy",    "FS-SMB1",    "Windows-Defender-Features",    "Windows-Defender",    "Windows-Defender-Gui",    "Windows-Internal-Database",    "PowerShellRoot",    "PowerShell",    "PowerShell-ISE",    "WAS",    "WAS-Process-Model",    "WAS-Config-APIs",    "Search-Service",    "Windows-Server-Backup",    "WoW64-Support"
    )

    Write-Host "Checking Installed Roles.." -ForegroundColor Yellow
    $installedRoles = (Get-WindowsFeature | where { $_.InstallState -eq "Installed" }).Name
    $roleCounter = 0
    $missingRoles = @()
    if(($global:OS) -eq "Essentials2012R2")
    {
        $osRoles = $2012R2Roles
    }
    if(($global:OS) -eq "Essentials2012")
    {
        $osRoles = $2012Roles
    }
    if(($global:OS) -eq "Essentials2016")
    {
        $osRoles = $2016Roles
    }
    foreach ($role in $osRoles)
    {
        if(($installedRoles) -inotcontains $role)
        {
            $roleCounter++
            $missingRoles += $role
        }
    }
    $roleCountLabel = "Roles Missing".PadRight(20," ")
    $roleMissingLabel = "Role Name".PadRight(20," ")
    if(($roleCounter) -ge 1)
    {
        Write-Host ""
        
        Write-Host "$roleCountLabel : " -NoNewline; Write-Host $roleCounter -ForegroundColor Yellow
        foreach ($role in $missingRoles)
        {
            Write-Host "$roleMissingLabel : " -NoNewline; Write-Host $role -ForegroundColor Red
        }
    }
    else
    {
        #$roleOKLabel = "Role Install Check".PadRight(20," ")
        #Write-Host "$roleOKLabel : " -NoNewline; Write-Host "OK" -ForegroundColor Green
    }
    Write-Host ""
}

# Menu
function menu
{
    Add-Content $logFile "*** Menu Loaded ***"
    Write-Host "************************************************"  -ForegroundColor CYAN
    Write-Host "* Essentials Server Configuration Tester *" -ForegroundColor CYAN
    Write-Host "************************************************"  -ForegroundColor CYAN
    Write-Host ""
    $osdLabel = "OS Detected".PadRight(20)
    $pTypeLabel = "System Type".PadRight(20)
    Write-Host "$osdLabel : " -NoNewline; Write-Host $os -ForegroundColor Yellow
    $currentIP = get-netIPConfiguration
    $serverIp = $currentIP.IPv4Address.IPAddress
    $dnsServers = $currentIP.DNSServer | where { $_.AddressFamily -eq "2" } | foreach { $_.ServerAddresses }
    $serverIPLabel = "Local IP Address".PadRight(20," ")
    $dnsServerLabel = "IPv4 DNS Servers".PadRight(20," ")
    Write-Host "$serverIPLabel : " -NoNewline; Write-Host $serverIP -ForegroundColor Cyan
    $sDNSCol = "Red"
    if(($pType) -eq "1")
    {
        Write-Host "$pTypeLabel : " -NoNewline; Write-Host "Client System" -ForegroundColor Green
    }
    else
    {
        if(($pType) -eq "3")
        {
            Write-Host "$pTypeLabel : " -NoNewline; Write-Host "Member Server" -ForegroundColor Magenta
            $sDNSCol = "Cyan"
        }
        if(($pType) -eq "2")
        {
            Write-Host "$pTypeLabel : " -NoNewline; Write-Host "Domain Controller" -ForegroundColor Cyan
            $dnsF = (Get-DnsServerForwarder).IPAddress
            $dnsForwarder = ""
            foreach ($forward in $dnsF)
            {
                $dnsF = $forward.IPAddressToString
                $dnsForwarder = $dnsForwarder,$dnsF -join ", "
            }
            $dnsForwarder = $dnsForwarder.Substring(1).Trim()
            $dnsForwarderLabel = "DNS Forwarder".PadRight(20, " ")
            if(($dnsServers) -contains $serverIp)
            {
                $sDNSCol = "Cyan"
            }
            if(($dnsServers) -contains "127.0.0.1")
            {
                $sDNSCol = "Cyan"
            }
        }
        $dnsServers = $dnsServers -join ", "
        Write-Host "$dnsServerLabel : " -NoNewline; Write-Host $dnsServers -ForegroundColor $sDNSCol
        if($dnsForwarder)
        {
            Write-Host "$dnsForwarderLabel : "-NoNewline; Write-Host $dnsForwarder -ForegroundColor Cyan
        }
        Write-Host ""
    }
    Write-Host "This tool will check your current Configuration against known Essentials Server Values."
    Write-Host "Written by Robert Pearman (WindowsServerEssentials.com) July 2018"
    Write-Host ""
    Write-Host "Version Info: " -nonewline;Write-Host $global:CurrentVersion -ForegroundColor Magenta
    if (($Global:Version) -gt $Global:CurrentVersion)    {        Write-Host "!! New Version Available !!" -ForegroundColor Black -BackgroundColor Green    }
    Write-Host ""

    Write-Host "1. Test IIS" -ForegroundColor Yellow
    Write-Host "2. Test CA Infrastructure" -ForegroundColor Yellow
    Write-Host "3. Test Services" -ForegroundColor Yellow
    Write-Host "4. Test Service Ports" -ForegroundColor Yellow
    Write-Host "5. Test Role Install" -ForegroundColor Yellow
    Write-Host "0. Quit" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Enter Task.." -foregroundcolor CYAN
    $task = Read-Host
    if (($task) -eq "1")
    {
        Write-Host "Only Errors will be shown." -ForegroundColor CYAN
        Write-Host ""
        Write-Host "Checking Websites.." -ForegroundColor Yellow
        Write-Host ""
        websites

        Write-Host "Checking Connect Site.." -ForegroundColor Yellow
        Write-Host ""
        ConnectSite
        
        Write-Host "Checking Virtual Directories.." -ForegroundColor Yellow
        Write-Host ""
        vdirectory

        Write-Host "Checking AppPools.." -ForegroundColor Yellow
        Write-Host ""
        apppools

        Write-Host "Checking ISAPI Filters.." -ForegroundColor Yellow
        Write-Host ""
        isapi
        
        Write-Host "Checking IIS SSL.." -ForegroundColor Yellow
        Write-Host ""
        IISSSL
        TLS
        if(($global:OS) -eq "Essentials2012")
        {
            sfccheck
        }

        Write-Host "Checking IIS Bindings.." -ForegroundColor Yellow
        Write-Host ""
        if ((($Global:OS) -eq "Essentials2011") -or ($Global:OS -eq "Essentials2008"))
        {
            IISBinding11    
        }
        else
        {
            IISBinding
        }
        Write-Host "Checking IIS Authentication.." -ForegroundColor Yellow
        IISAuthentication
        Write-Host ""
        
        Write-Host "Review your results, items in red should be investigated." -ForegroundColor Yellow
        Write-Host ""
        menu
    }
    if (($task) -eq "2")
    {
        SSLChecks
        Write-Host ""
        Write-Host "Review your results, items in red should be investigated." -ForegroundColor Yellow
        Write-Host ""
        menu
    }
    if (($task) -eq "3")
    {
        services
        Write-Host ""
        Write-Host "Review your results, items in red should be investigated." -ForegroundColor Yellow
        Write-Host ""
        menu
    }
    if (($task) -eq "4")
    {
        ports
        Write-Host "" 
        Write-Host "Review your results, items in red should be investigated." -ForegroundColor Yellow 
        Write-Host ""
        menu
    }
    if (($task) -eq "5")
    {
        rolecheck
        Write-Host "" 
        Write-Host "Review your results, items in red should be investigated." -ForegroundColor Yellow 
        Write-Host ""
        menu
    }
    if (($task) -eq "0")
    {
        exit
    }
}
cls
Write-Host "Loading..."
# Version Check
$source = "http://www.msjr.co.uk/EssentialsConfigVersion.txt"$destination = "c:\windows\temp\E.log"$wc = New-Object System.Net.WebClient$wc.DownloadFile($source,$destination)$Global:Version = Get-Content $destinationRemove-Item $destination -force
cls
# Test Admin
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator" ))
{
    Write-Host "You must run PowerShell 'As Administrator' to use this tool." -foregroundcolor YELLOW
    Write-Host ""
    Exit
    
}
else
{
    # Test OS
    $osInfo = Get-WMIObject Win32_OperatingSystem
    $OS = $osInfo.Caption
    $pType = $osInfo.ProductType
    Add-Content $logFile $OS
    $checkOS = $os.Contains("Essentials")
    if (($CheckOS) -eq "True")
    {
        Import-Module WebAdministration
        $checkOS = $os.Contains("2011")
        if (($CheckOS) -eq "True")
        {
            $Global:OS = "Essentials2011"
            Menu
        }
        $checkOS = $os.Contains("2008")
        if (($CheckOS) -eq "True")
        {
            $Global:OS = "Essentials2008"
            Menu
        }
        $checkOS = $os.Contains("2012")
        if (($CheckOS) -eq "True")
        {
            $checkOS = $os.Contains("R2")
            if (($checkOS) -eq "True")
            {
                $Global:OS = "Essentials2012R2"
                menu
            }
            else
            {
                $Global:OS = "Essentials2012"
                menu
            }
        }
        $checkOS = $os.Contains("2016")
        if (($checkOS) -eq "True")
        {
            Import-Module WebAdministration
            $Global:OS = "Essentials2016"
            Menu 
        }
    }                                                                        
    else
    {
        $checkOS = $os.Contains("2016")
        if (($checkOS) -eq "True")
        {
            Import-Module WebAdministration
            $Global:OS = "Essentials2016"
            Menu 
        }
        $checkOS = $os.Contains("R2")
        if (($checkOS) -eq "True")
        {
            Import-Module WebAdministration
            $Global:OS = "Essentials2012R2"
            Menu
        }
        else
        {
            $checkOS = $os.Contains("Home Server")
            if (($checkOS) -eq "True")
            {
                Import-Module WebAdministration
                $Global:OS = "Essentials2008"
                Menu 
            }
            else
            {
                # Load Client Tests          
                ClientTest
            }
        }
    }
}