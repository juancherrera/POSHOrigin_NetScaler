#Requires -Version 5.0
#Requires -Module NetScaler

enum Ensure {
    Absent
    Present
}

[DscResource()]
class LBVirtualServer {
    [DscProperty(key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN

    [DscProperty(Mandatory)]
    [string]$IPAddress

    [DscProperty()]
    [ValidateLength(0, 256)]
    [string]$Comment = ''

    [DscProperty(Mandatory)]
    [ValidateRange(1, 65534)]
    [int]$Port

    [DscProperty()]
    [ValidateSet('DHCPRA','DIAMTER', 'DNS', 'DNS_TCP', 'DLTS', 'FTP', 'HTTP', 'MSSQL', 
        'MYSQL', 'NNTP', 'PUSH','RADIUS', 'RDP', 'RTSP', 'SIP_UDP', 'SSL', 'SSL_BRIDGE', 
        'SSL_DIAMETER', 'SSL_PUSH', 'SSL_TCP', 'TCP', 'TFTP', 'UDP')]
    [string]$ServiceType = 'HTTP'

    [DscProperty()]
    [ValidateSet('ROUNDROBIN', 'LEASTCONNECTION', 'LEASTRESPONSETIME', 'LEASTBANDWIDTH', 
        'LEASTPACKETS', 'CUSTOMLOAD', 'LRTM', 'URLHASH', 'DOMAINHASH', 'DESTINATIONIPHASH', 
        'SOURCEIPHASH', 'TOKEN', 'SRCIPDESTIPHASH', 'SRCIPSRCPORTHASH', 'CALLIDHASH')]
    [string]$LBMethod = 'ROUNDROBIN'

    [DscProperty()]    
    [ValidateSet('SOURCEIP', 'COOKIEINSERT', 'SSLSESSION', 'CUSTOMSERVERID', 'RULE', 'URLPASSIVE', 'DESTIP', 'SRCIPDESTIP', 'CALLID' ,'RTSPID', 'FIXSESSION', 'NONE')]
    [string]$PersistenceType = 'SOURCEIP'

    [DscProperty()]
    [string]$HttpRedirectURL = ''

    [DscProperty()]
    [ValidateSet('PASSIVE', 'ACTIVE')]
    [string]$ICMPVSRResponse = 'PASSIVE'

    [DscProperty()]
    [int]$TimeOut = 2

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
        try {
            switch ($this.Ensure) {
            'Present' {
                if ($NSObject.Ensure -eq [ensure]::Present) {
                    if ($NSObject.name -ne $this.Name) {
                        Write-Warning -Message 'NetScaler does not support changing virtual server name on an existing virtual server. Virtual server must be deleted and recreated.'
                    }
                    if ($NSObject.ipaddress -ne $this.IPAddress) {
                        Set-NSLBVirtualServer -Name $this.Name -IPAddress $this.IPAddress -Verbose:$false -Confirm:$false
                        Write-Verbose -Message "Setting virtual server IP [$($this.IPAddress)]"
                    }
                    if ($NSObject.comment -ne $this.Comment) {
                        Write-Verbose -Message "Setting virtual server Comment [$($this.Comment)]"
                        Set-NSLBVirtualServer -Name $this.Name -Comment $this.Comment -Verbose:$false -Force
                    }                    
                    if ($NSObject.Port -ne $this.Port) {
                        Write-Warning -Message 'NetScaler does not support changing virtual server port on an existing virtual server. Virtual server must be deleted and recreated.'
                    }
                    if ($NSObject.ServiceType -ne $this.ServiceType) {
                        Write-Warning -Message 'NetScaler does not support changing virtual server service type on an existing virtual server. Virtual server must be deleted and recreated.'
                    }
                    if ($NSObject.lbmethod -ne $this.LBMethod) { 
                        Set-NSLBVirtualServer -Name $this.Name -LBMethod $this.LBMethod -Verbose:$false -Force
                        Write-Verbose -Message "Setting virtual server load balance method [$($this.LBMethod)]"
                    }
                    if ($NSObject.persistencetype -ne $this.PersistenceType) { 
                        Set-NSLBVirtualServer -Name $this.Name -PersistenceType $this.PersistenceType -Verbose:$false -Force
                        Write-Verbose -Message "Setting virtual server persistence [$($this.PersistenceType)]"
                    }
                    if ($NSObject.httpredirecturl -ne $this.HttpRedirectURL) { 
                        Set-NSLBVirtualServer -Name $this.Name -HttpRedirectURL $this.HttpRedirectURL -Verbose:$false -Force
                        Write-Verbose -Message "Setting virtual server redirect [$($this.HttpRedirectURL)]"
                    }                 
                    if ($NSObject.icmpvsrresponse -ne $this.ICMPVSRResponse) { 
                        Set-NSLBVirtualServer -Name $this.Name -ICMPVSRResponse $this.ICMPVSRResponse -Verbose:$false -Force
                        Write-Verbose -Message "Setting virtual server icmpvsrresponse [$($this.ICMPVSRResponse)]"
                    }
                    if ($NSObject.timeout -ne $this.TimeOut) { 
                        Set-NSLBVirtualServer -Name $this.Name -TimeOut $this.TimeOut -Verbose:$false -Force
                        Write-Verbose -Message "Setting virtual server timeout [$($this.TimeOut)]"
                    }
                } else {
                    Write-Verbose -Message "Creating virtual server [$($this.Name)]"
                    $params = @{
                        Name = $this.Name
                        IPAddress = $this.IPAddress
                        ServiceType = $this.ServiceType
                        Port = $this.Port
                        LBMethod = $this.LBMethod
                        PersistenceType = $this.PersistenceType
                        ICMPVSRResponse = $this.ICMPVSRResponse
                        TimeOut = $this.TimeOut
                        Comment = $this.Comment
                    }
                    if ($null -ne $this.HttpRedirectURL) {
                        $params.HttpRedirectURL = $this.HttpRedirectURL
                    }                    
                    New-NSLBVirtualServer @params -ErrorAction SilentlyContinue
                }
            } 'Absent' {
                try {   
                    Write-Verbose -Message "Removing virtual server: $($this.Name)"
                    Remove-NSLBVirtualServer -Name $this.Name -Confirm:$false -Verbose:$false -Force
                } catch {
                    write-host "Virtual Server $this.Name was not found"
                }
            }
          }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

    [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {

                        if ($NSObject.name -ne $this.Name) {
                            Write-Verbose -Message "Virtual server Name does not match [$($NSObject.name) <> $($this.Name)"
                            $pass = $false
                        }    
                        if ($NSObject.ipaddress -ne $this.IPAddress) {
                            Write-Verbose -Message "Virtual server IP address does not match [$($NSObject.ipaddress) <> $($this.IPAddress)"
                            $pass = $false
                        }
                        if ($NSObject.comment -ne $this.Comment) {
                            Write-Verbose -Message "Virtual server Comment do not match [$($NSObject.comment) <> $($this.Comment)]"
                            $pass = $false
                        }                                             
                        if ($NSObject.port -ne $this.Port) {
                            Write-Verbose -Message "Virtual server port does not match [$($NSObject.port) <> $($this.Port)"
                            $pass = $false
                        }
                        if ($NSObject.servicetype -ne $this.ServiceType) {
                            Write-Verbose -Message "Virtual server service type does not match [$($NSObject.servicetype) <> $($this.ServiceType)"
                            $pass = $false
                        }
                        if ($NSObject.lbmethod -ne $this.LBMethod) { 
                            Write-Verbose -Message "Virtual server load balance method does not match [$($NSObject.lbmethod) <> $($this.LBMethod)"
                            $pass = $false
                        }
                        if ($NSObject.persistencetype -ne $this.PersistenceType) { 
                            Write-Verbose -Message "Virtual server Persistence Type does not match [$($NSObject.persistencetype) <> $($this.PersistenceType)"
                            $pass = $false
                        }
                        if ($NSObject.ICMPVSRResponse -ne $this.ICMPVSRResponse) { 
                            Write-Verbose -Message "Virtual server ICMP Response does not match [$($NSObject.ICMPVSRResponse) <> $($this.ICMPVSRResponse)"
                            $pass = $false
                        }                        
                        if ($NSObject.httpredirectURL -ne $this.HTTPRedirectURL) { 
                            Write-Verbose -Message "Virtual server HTTP Redirect does not match [$($NSObject.httpredirectURL) <> $($this.HTTPRedirectURL)"
                            $pass = $false
                        }
                        if ($NSObject.timeout -ne $this.TimeOut) { 
                            Write-Verbose -Message "Virtual server Timeout does not match [$($NSObject.timeout) <> $($this.TimeOut)"
                            $pass = $false
                        }                                                                                           
                   } else {
                        Write-Verbose -Message "Resource [$($this.Name)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBVirtualServer]Get() {
        $t = $null
        $t = $this.Init()
        try {
           $s = Get-NSLBVirtualServer -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }
        
        $obj = [LBVirtualServer]::new()
        $obj.Name = $this.Name
        $obj.IPAddress = $this.IPAddress
        $obj.Port = $this.Port
        $obj.ServiceType = $this.ServiceType
        $obj.Comment = $this.Comment      
        $obj.LBMethod = $this.LBMethod
        $obj.PersistenceType = $this.PersistenceType
        $obj.HTTPRedirectURL = $this.HTTPRedirectURL
        $obj.ICMPVSRResponse = $this.ICMPVSRResponse
        $obj.TimeOut = $this.TimeOut
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Name = $s.Name 
            $obj.IPAddress = $s.ipv46
            $obj.Port = $s.port
            $obj.ServiceType = $s.servicetype
            if ($s.comment) { $obj.Comment = $s.comment }            
            $obj.LBMethod = $s.lbmethod
            $obj.PersistenceType = $s.persistencetype
            if ($s.redirurl) { $obj.HTTPRedirectURL = $s.redirurl }
            $obj.ICMPVSRResponse = $s.icmpvsrresponse       
            $obj.TimeOut = $s.timeout
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }    
}

[DscResource()]
class LBServer {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN

    [DscProperty(Mandatory)]
    [string]$IPAddress

    [DscProperty()]
    [ValidateLength(0, 256)]
    [string]$Comment = ''

    [DscProperty()]
    [ValidateSet('ENABLED', 'DISABLED')]
    [string]$State = 'ENABLED'

    [DscProperty()]
    [bool]$ParameterExport = $false

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
        try {
            switch ($this.Ensure) {
            'Present' {
                if ($NSObject.Ensure -eq [ensure]::Present) {
                    if ($NSObject.ipaddress -ne $this.IPAddress) {
                        Write-Verbose -Message "Setting server IP [$($this.IPAddress)]"
                        Set-NSLBServer -Name $this.Name -IPAddress $this.IPAddress -Force -Verbose:$false
                    }
                    if ($NSObject.comment -ne $this.Comment) {
                        Write-Verbose -Message "Setting server Comment [$($this.Comment)]"
                        Set-NSLBServer -Name $this.Name -Comment $this.Comment -Force -Verbose:$false
                    }
                    if ($NSObject.state -ne $this.State) { 
                        Write-Verbose -Message "Setting server state [$($this.State)]"
                        if ($this.State -eq 'ENABLED') {
                            Enable-NSLBServer -Name $this.Name -Force -Verbose:$false
                        } else {
                            Disable-NSLBServer -Name $this.Name -Force -Verbose:$false
                        }
                    }
                } else {
                    Write-Verbose -Message "Creating server [$($this.Name)]"
                    $params = @{
                        Name = $this.Name
                        IPAddress = $this.IPAddress
                        Comment = $this.Comment
                        Confirm = $false
                        Verbose = $false
                    }
                    if ($null -ne $this.TrafficDomainId) {
                        $params.TrafficDomainId = $this.TrafficDomainId
                    }
                    New-NSLBServer @params
                }
            } 'Absent' {
                try {   
                    Write-Verbose -Message "Removing server: $($this.Name)"
                    Remove-NSLBServer -Name $this.Name -Confirm:$false -Verbose:$false -Force
                } catch {
                    write-host "Virtual Server $this.Name was not found"
                }
            }
          }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

    [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        Write-Verbose -Message "Server [$($this.Name)] exists"

                        if ($NSObject.ipaddress -ne $this.IPAddress) {
                            Write-Verbose -Message "Server IP address does not match [$($NSObject.ipaddress) <> $($this.IPAddress)]"
                            $pass = $false
                        }
                        if ($NSObject.comment -ne $this.Comment) {
                            Write-Verbose -Message "Server Comment does not match [$($NSObject.comment) <> $($this.Comment)]"
                            $pass = $false
                        }
                        if ($NSObject.state -ne $this.State) { 
                            Write-Verbose -Message "Server state does not match [$($NSObject.state) <> $($this.State)]"
                            $pass = $false
                        }
                    } else {
                        Write-Verbose -Message "Server [$($this.Name)] was not found"
                        $pass = $false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBServer]Get() {
        $t = $null
        $t = $this.Init()
        try {
           $s = Get-NSLBServer -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }
        
        $obj = [LBServer]::new()
        $obj.Name = $this.Name
        $obj.IPAddress = $this.IPAddress
        $obj.Comment = $this.Comment
        $obj.State = $this.State
        $obj.Credential = $this.Credential
        $obj.NetScalerFQDN = $this.NetScalerFQDN
        $obj.ParameterExport = $this.ParameterExport
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.IPAddress = $s.ipaddress
            $obj.Comment = $s.comment
            $obj.State = $s.state
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBMonitor {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [ValidateSet('PING', 'TCP', 'HTTP', 'TCP-ECV', 'HTTP-ECV', 'UDP-ECV', 'DNS', 'FTP', 'LDNS-PING',
        'LDNS-TCP', 'RADIUS', 'USER', 'HTTP-INLINE', 'SIP-UDP', 'LOAD', 'FTP-EXTENDED', 'SMTP', 'SNMP',
        'NNTP', 'MYSQL', 'MYSQL-ECV', 'MSSQL-ECV', 'ORACLE-ECV', 'LDAP', 'POP3', 'CITRIX-XML-SERVICE',
        'CITRIX-WEB-INTERFACE', 'DNS-TCP', 'RTSP', 'ARP', 'CITRIX-AG', 'CITRIX-AAC-LOGINPAGE', 'CITRIX-AAC-LAS',
        'CITRIX-XD-DDC', 'ND6', 'CITRIX-WI-EXTENDED', 'DIAMETER', 'RADIUS_ACCOUNTING', 'STOREFRONT')]
    [string]$Type = 'HTTP'

    [DscProperty(Mandatory)]
    [ValidateRange(1, 20940000)]
    [int]$Interval = 5
    
    [DscProperty(Mandatory)]
    [ValidateSet('SEC', 'MSEC', 'MIN')]
    [string]$IntervalType = 'SEC'

    [DscProperty(Mandatory)]
    [ValidateRange(1, 20939000)]
    [int]$ResponseTimeout = 2

    [DscProperty(Mandatory)]
    [ValidateSet('SEC', 'MSEC', 'MIN')]
    [string]$ResponseTimeoutType = 'SEC'

    [DscProperty(Mandatory)]
    [ValidateRange(1, 20939000)]
    [int]$Downtime = 30

    [DscProperty(Mandatory)]
    [ValidateSet('SEC', 'MSEC', 'MIN')]
    [string]$DowntimeType = 'SEC'

    [DscProperty(Mandatory)]
    [DscProperty()]
    [int]$DestinationPort

    [DscProperty(Mandatory)]
    [ValidateRange(1, 127)]
    [int]$Retries = 3

    [DscProperty(Mandatory)]
    [ValidateRange(0, 32)]
    [int]$SuccessRetries = 1

    [DscProperty()]
    [string]$DestinationIP

    [DscProperty()]
    [ValidateRange(0, 20939000)]
    [int]$Deviation

    [DscProperty()]
    [ValidateRange(0, 100)]
    [int]$ResponseTimeoutThreshold

    [DscProperty()]
    [ValidateRange(0, 32)]
    [int]$AlertRetries

    [DscProperty()]
    [ValidateRange(0, 32)]
    [int]$FailureRetries

    [DscProperty()]
    [ValidateRange(1, 127)]
    [string]$NetProfile

    [DscProperty()]
    [ValidateSet('YES', 'NO')]
    [string]$TOS = 'NO'

    [DscProperty()]
    [ValidateRange(1, 63)]
    [int]$TOSID

    [DscProperty()]
    [ValidateSet('ENABLED', 'DISABLED')]
    [string]$State = 'ENABLED'

    [DscProperty()]
    [ValidateSet('Yes', 'NO')]
    [string]$Reverse = 'NO'

    [DscProperty()]
    [ValidateSet('YES', 'NO')]
    [string]$Transparent = 'NO'

    [DscProperty()]
    [ValidateSet('ENABLED', 'DISABLED')]
    [string]$LRTM = 'DISABLED'

    [DscProperty()]
    [ValidateSet('YES', 'NO')]
    [string]$Secure = 'NO'

    [DscProperty()]
    [ValidateSet('YES', 'NO')]
    [string]$IPTunnel = 'NO'

    [DscProperty()]
    [string]$ScriptName

    [DscProperty()]
    [string]$DispatcherIP

    [DscProperty()]
    [int]$DispatcherPort

    [DscProperty()]
    [string]$ScriptArgs

    [DscProperty()]
    [System.Collections.Hashtable]$CustomProperty

    [DscProperty()]
    [string]$ResponseCode

    [DscProperty()]
    [string]$HTTPRequest

    [DscProperty()]
    [string]$Send

    [DscProperty()]
    [string]$Recv

    [DscProperty()]
    [bool]$ParameterExport = $false
    
    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $NSObject = $this.Get()
        try {
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
        try {
            switch ($this.Ensure) {
            'Present' {
                # Does the record already exist?
                if ($NSObject.Ensure -eq [ensure]::Present) {

                    #Run tests and set any needed attributes to match desired configuration
                    if ($NSObject.monitorname -ne $this.Name) {
                        Write-Warning -Message "Setting Name cannot be changed to [$($this.Name)]. Object must be recreated."
                    }
                    if ($NSObject.type -ne $this.Type) {
                        Write-Warning -Message "Setting Type cannot be changed to [$($this.Type)]. Object must be recreated."
                    }
                    if ($NSObject.interval -ne $this.Interval) {
                        Write-Verbose -Message "Setting Interval [$($this.Interval)]"
                        Set-NSLBMonitor -Name $this.Name -Interval $this.Interval -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.units3 -ne $this.IntervalType) {
                        Write-Verbose -Message "Setting Interval Type [$($this.IntervalType)]"
                        Set-NSLBMonitor -Name $this.Name -IntervalType $this.IntervalType -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.resptimeout -ne $this.ResponseTimeout) {
                        Write-Verbose -Message "Setting Response Timeout was changed to [$($this.ResponseTimeout)]"
                        Set-NSLBMonitor -Name $this.Name -ResponseTimeout $this.ResponseTimeout -ResponseTimeoutType $this.ResponseTimeoutType -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.destip -ne $this.DestinationIP) {
                        Write-Verbose -Message "Setting Destination IP was changed to [$($this.DestinationIP)]"
                        Set-NSLBMonitor -Name $this.Name -DestinationIP $this.DestinationIP -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.downtime -ne $this.Downtime) {
                        Write-Verbose -Message "Setting Downtime was changed to [$($this.Downtime)]"
                        Set-NSLBMonitor -Name $this.Name -Downtime $this.Downtime -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.units2 -ne $this.DowntimeType) {
                        Write-Verbose -Message "Setting Downtime Type was changed to [$($this.DowntimeType)]"
                        Set-NSLBMonitor -Name $this.Name -DowntimeType $this.DowntimeType -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.retries -ne $this.Retries) {
                        Write-Verbose -Message "Setting Retries was changed to [$($this.Retries)]"
                        Set-NSLBMonitor -Name $this.Name -Retries $this.Retries -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.successretries -ne $this.SuccessRetries) {
                        Write-Verbose -Message "Setting Success Retries was changed to [$($this.SuccessRetries)]"
                        Set-NSLBMonitor -Name $this.Name -SuccessRetries $this.SuccessRetries -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.tos -ne $this.TOS) {
                        Write-Verbose -Message "Setting TOS was changed to [$($this.TOS)]"
                        Set-NSLBMonitor -Name $this.Name -TOS $this.TOS -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.state -ne $this.State) {
                        Write-Verbose -Message "Setting State was changed to [$($this.State)]"
                        Set-NSLBMonitor -Name $this.Name -State $this.State -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.reverse -ne $this.Reverse) {
                        Write-Verbose -Message "Setting Reverse was changed to [$($this.Reverse)]"
                        Set-NSLBMonitor -Name $this.Name -Reverse $this.Reverse -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.transparent -ne $this.Transparent) {
                        Write-Verbose -Message "Setting Transparent was changed to [$($this.Transparent)]"
                        Set-NSLBMonitor -Name $this.Name -Transparent $this.Transparent -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.lrtm -ne $this.LRTM) {
                        Write-Verbose -Message "Setting LRTM was changed to [$($this.LRTM)]"
                        Set-NSLBMonitor -Name $this.Name -LRTM $this.LRTM -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.secure -ne $this.Secure) {
                        Write-Verbose -Message "Setting Secure was changed to [$($this.Secure)]"
                        Set-NSLBMonitor -Name $this.Name -Secure $this.Secure -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.iptunnel -ne $this.IPTunnel) {
                        Write-Verbose -Message "Setting IPTunnel was changed to [$($this.IPTunnel)]"
                        Set-NSLBMonitor -Name $this.Name -IPTunnel $this.IPTunnel -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.failureretries -ne $this.FailureRetries) {
                        Write-Verbose -Message "Setting Failure Retries was changed to [$($this.FailureRetries)]"
                        Set-NSLBMonitor -Name $this.Name -FailureRetries $this.FailureRetries -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.destport -ne $this.DestinationPort) {
                        Write-Verbose -Message "Setting Destination Port was changed to [$($this.DestinationPort)]"
                        Set-NSLBMonitor -Name $this.Name -DestinationPort $this.DestinationPort -Verbose:$false -ErrorAction SilentlyContinue
                    }
                    if ($NSObject.respcode -ne $this.ResponseCode) {
                        Write-Verbose -Message "Setting Response Code was changed to [$($this.ResponseCode)]"
                        try {
                            Set-NSLBMonitor -Name $this.Name -ResponseCode $this.ResponseCode -Verbose:$false -ErrorAction SilentlyContinue
                        } catch { $null }
                    }
                    if ($NSObject.httprequest -ne $this.HTTPRequest) {
                        Write-Verbose -Message "Setting HTTP Request was changed to [$($this.HTTPRequest)]"
                        # Set-NSLBMonitor -Name $this.Name -HTTPRequest $this.HTTPRequest -Verbose:$false -ErrorAction SilentlyContinue
                    }
                } else {
                    Write-Verbose -Message "Creating monitor [$($this.Name)]"
                    $params = @{
                        name = $this.Name
                        type = $this.Type
                        interval = $this.Interval
                        intervaltype = $this.IntervalType
                        responseTimeoutType = $this.ResponseTimeoutType
                        downtime = $this.Downtime
                        downtimeType = $this.DowntimeType
                        retries = $this.Retries
                        responsetimeout = $this.ResponseTimeout
                        successretries = $this.SuccessRetries
                        failureRetries = $this.FailureRetries
                        state = $this.State
                        destinationport = $this.DestinationPort
                        destinationip = $this.DestinationIP
                        reverse = $this.Reverse
                        lrtm = $this.LRTM
                        transparent = $this.Transparent
                        tos = $this.TOS
                        secure = $this.Secure
                    }
                    if ($PSBoundParameters.ContainsKey('Transparent')) {
                        $params.Add('Transparent', $this.Transparent)
                    }
                    if ($PSBoundParameters.ContainsKey('LRTM')) {
                        $params.Add('LRTM', $this.LRTM)
                    }
                    if ($PSBoundParameters.ContainsKey('Secure')) {
                        $params.Add('Secure', $this.Secure)
                    }
                    if ($PSBoundParameters.ContainsKey('IPTunnel')) {
                        $params.Add('IPTunnel', $this.IPTunnel)
                    }          
                    if ($PSBoundParameters.ContainsKey('TOS')) {
                        $params.Add('TOS', $this.TOS)
                    }
                    if ($PSBoundParameters.ContainsKey('Reverse')) {
                        $params.Add('Reverse', $this.Reverse)
                    }        
                    if ($PSBoundParameters.ContainsKey('DestinationIP')) {
                        $params.Add('DestinationIP', $this.DestinationIP)
                    }
                    if ($PSBoundParameters.ContainsKey('Deviation')) {
                        $params.Add('Deviation', $this.Deviation)
                    }
                    if ($PSBoundParameters.ContainsKey('ResponseTimeoutThreshold')) {
                        $params.Add('ResponseTimeoutThreshold', $this.ResponseTimeoutThreshold)
                    }
                    if ($PSBoundParameters.ContainsKey('AlertRetries')) {
                        $params.Add('AlertRetries', $this.AlertRetries)
                    }
                    if ($PSBoundParameters.ContainsKey('FailureRetries')) {
                        $params.Add('FailureRetries', $this.FailureRetries)
                    }
                    if ($PSBoundParameters.ContainsKey('NetProfile')) {
                        $params.Add('NetProfile', $this.NetProfile)
                    }
                    if ($PSBoundParameters.ContainsKey('TOSID')) {
                        $params.Add('TOSID', $this.TOSID)
                    }
                    if ($PSBoundParameters.ContainsKey('ScriptName')) {
                        $params.Add('ScriptName', $this.ScriptName)
                    }
                    if ($PSBoundParameters.ContainsKey('DispatcherIP')) {
                        $params.Add('DispatcherIP', $this.DispatcherIP)
                    }
                    if ($PSBoundParameters.ContainsKey('ScriptArgs')) {
                        $params.Add('ScriptArgs', $this.ScriptArgs)
                    }
                    if ($PSBoundParameters.ContainsKey('CustomProperty')) {
                        ## Add each custom property to the $params Hashtable
                        foreach ($CustomProperty in $this.CustomProperty.Keys) {
                            $params.Add($CustomProperty.ToLower(), $CustomProperty[$CustomProperty])
                        }
                    }
                    if ($PSBoundParameters.ContainsKey('ResponseCode')) {
                        $params.Add('ResponseCode', $this.ResponseCode)
                    }
                    if ($PSBoundParameters.ContainsKey('HTTPRequest')) {
                        $params.Add('HTTPRequest', $this.HTTPRequest)
                    }
                    if ($PSBoundParameters.ContainsKey('Send')) {
                        $params.Add('Send', $this.Send)
                    }
                    if ($PSBoundParameters.ContainsKey('Recv')) {
                        $params.Add('Recv', $this.Recv)
                    }
                    if ($PSBoundParameters.ContainsKey('DispatcherPort')) {
                        $params.Add('DispatcherPort', $this.DispatcherPort)
                    }
                    New-NSLBMonitor @params -ErrorAction SilentlyContinue
                }
            } 'Absent' {
                try {
                    $params = @{
                        name = $this.Name
                        type = $this.Type
                    }     
                    Remove-NSLBMonitor @params -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Verbose -Message "Removing Netscaler monitor: $($this.Name)"
                } catch {
                    write-host "Monitor $this.Name was not found"
                }
            }
            }#
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

    [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        Write-Verbose -Message "Monitor [$($this.Name)] exists"
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Verbose -Message "Monitor Name does not match [$($NSObject.monitorname) <> $($this.Name)]"
                            $pass = $false
                        }
                        if ($NSObject.DestinationIP -ne $this.DestinationIP) {
                            Write-Verbose -Message "Monitor Destination IP does not match [$($NSObject.DestinationIP) <> $($this.DestinationIP)]"
                            $pass = $false
                        }
                        if ($NSObject.Interval -ne $this.Interval) {
                            Write-Verbose -Message "Monitor Interval does not match [$($NSObject.interval) <> $($this.Interval)]"
                            $pass = $false
                        }
                        if ($NSObject.IntervalType -ne $this.IntervalType) {
                            Write-Verbose -Message "Monitor Interval Type does not match [$($NSObject.IntervalType) <> $($this.IntervalType)]"
                            $pass = $false
                        }
                        if ($NSObject.ResponseTimeout -ne $this.ResponseTimeout) {
                            Write-Verbose -Message "Monitor Response Timeout does not match [$($NSObject.ResponseTimeout) <> $($this.ResponseTimeout)]"
                            $pass = $false
                        }
                        if ($NSObject.ResponseTimeoutType -ne $this.ResponseTimeoutType) {
                            Write-Verbose -Message "Monitor Response Timeout Type does not match [$($NSObject.ResponseTimeoutType) <> $($this.ResponseTimeoutType)]"
                            $pass = $false
                        }
                        if ($NSObject.Downtime -ne $this.Downtime) {
                            Write-Verbose -Message "Monitor Downtime does not match [$($NSObject.Downtime) <> $($this.Downtime)]"
                            $pass = $false
                        }
                        if ($NSObject.DowntimeType -ne $this.DowntimeType) {
                            Write-Verbose -Message "Monitor Downtime Type does not match [$($NSObject.DowntimeType) <> $($this.DowntimeType)]"
                            $pass = $false
                        }
                        if ($NSObject.Retries -ne $this.Retries) {
                            Write-Verbose -Message "Monitor Retries does not match [$($NSObject.Retries) <> $($this.Retries)]"
                            $pass = $false
                        }
                        if ($NSObject.SuccessRetries -ne $this.SuccessRetries) {
                            Write-Verbose -Message "Monitor Success Retries does not match [$($NSObject.SuccessRetries) <> $($this.SuccessRetries)]"
                            $pass = $false
                        }
                        if ($NSObject.TOS -ne $this.TOS) {
                            Write-Verbose -Message "Monitor TOS setting not match [$($NSObject.TOS) <> $($this.TOS)]"
                            $pass = $false
                        }
                        if ($NSObject.State -ne $this.State) {
                            Write-Verbose -Message "Monitor State does not match [$($NSObject.State) <> $($this.State)]"
                            $pass = $false
                        }
                        if ($NSObject.Reverse -ne $this.Reverse) {
                            Write-Verbose -Message "Monitor Reverse setting does not match [$($NSObject.Reverse) <> $($this.Reverse)]"
                            $pass = $false
                        }
                        if ($NSObject.Transparent -ne $this.Transparent) {
                            Write-Verbose -Message "Monitor Transparent setting does not match [$($NSObject.Transparent) <> $($this.Transparent)]"
                            $pass = $false
                        }
                        if ($NSObject.LRTM -ne $this.LRTM) {
                            Write-Verbose -Message "Monitor LRTM setting does not match [$($NSObject.LRTM) <> $($this.LRTM)]"
                            $pass = $false
                        }
                        if ($NSObject.Secure -ne $this.Secure) {
                            Write-Verbose -Message "Monitor Secure setting does not match [$($NSObject.Secure) <> $($this.Secure)]"
                            $pass = $false
                        }
                        if ($NSObject.IPTunnel -ne $this.IPTunnel) {
                            Write-Verbose -Message "Monitor IPTunnel setting does not match [$($NSObject.IPTunnel) <> $($this.IPTunnel)]"
                            $pass = $false
                        }
                        if ($NSObject.FailureRetries -ne $this.FailureRetries) {
                            Write-Verbose -Message "Monitor Failure Retries does not match [$($NSObject.FailureRetries) <> $($this.FailureRetries)]"
                            $pass = $false
                        }
                        if ($NSObject.DestinationPort -ne $this.DestinationPort) {
                            Write-Verbose -Message "Monitor Destination Port does not match [$($NSObject.DestinationPort) <> $($this.DestinationPort)]"
                            $pass = $false
                        }
                        if ($NSObject.ResponseCode -ne $this.ResponseCode) {
                            Write-Verbose -Message "Monitor Response Code does not match [$($NSObject.ResponseCode) <> $($this.ResponseCode)]"
                            $pass = $false
                        }
                        if ($NSObject.HTTPRequest -ne $this.HTTPRequest) {
                            Write-Verbose -Message "Monitor HTTPRequest setting does not match [$($NSObject.HTTPRequest) <> $($this.HTTPRequest)]"
                            $pass = $false
                            }
                    } else {
                        Write-Verbose -Message "Monitor [$($this.Name)] was not found"
                        $pass = $false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBMonitor]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSLBMonitor -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBMonitor]::new()
        $obj.Name = $this.Name
        $obj.Type = $this.Type
        $obj.Interval = $this.Interval
        $obj.IntervalType = $this.IntervalType
        $obj.DestinationIP = $this.DestinationIP
        $obj.ResponseTimeout = $this.ResponseTimeout
        $obj.ResponseTimeoutType = $this.ResponseTimeoutType
        $obj.Downtime = $this.Downtime
        $obj.DowntimeType = $this.DowntimeType
        $obj.Retries = $this.Retries
        $obj.SuccessRetries = $this.SuccessRetries
        $obj.TOS = $this.TOS
        $obj.State = $this.State
        $obj.Reverse = $this.Reverse
        $obj.Transparent = $this.Transparent
        $obj.LRTM = $this.LRTM
        $obj.Secure = $this.Secure
        $obj.IPTunnel = $this.IPTunnel
        $obj.FailureRetries = $this.FailureRetries
        $obj.DestinationPort = $this.DestinationPort
        $obj.HTTPRequest = $this.HTTPRequest
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Name = $s.monitorname
            $obj.Type = $s.type
            $obj.Interval = $s.interval
            $obj.IntervalType = $s.units3
            $obj.DestinationIP = $s.destip
            $obj.ResponseTimeout = $s.resptimeout
            $obj.ResponseTimeoutType = $s.units4
            $obj.Downtime = $s.downtime
            $obj.DowntimeType = $s.units2
            $obj.Retries = $s.retries
            $obj.SuccessRetries = $s.successRetries
            $obj.TOS = $s.tos
            $obj.State = $s.state
            $obj.Reverse = $s.reverse
            $obj.Transparent = $s.transparent
            $obj.LRTM = $s.lrtm
            $obj.Secure = $s.secure
            $obj.IPTunnel = $s.iptunnel
            $obj.FailureRetries = $s.failureretries
            $obj.DestinationPort = $s.destport
            $obj.HTTPRequest = $s.httprequest  
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBServiceGroup {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [ValidateSet('ADNS','ADNS_TCP','ANY','DHCPRA','DIAMETER','DNS','DNS_TCP','DTLS','FTP','HTTP','MSSQL',
    'MYSQL','NNTP','RADIUS','RDP','RPCSVR','RTSP','SIP_UDP','SNMP','SSL','SSL_BRIDGE','SSL_DIAMETER','SSL_TCP','TCP','TFTP','UDP')]
    [Alias('Protocol')]
    [string]$ServiceType = 'HTTP'

    [DscProperty()]
    [ValidateRange(0, 4094)]
    [int]$TrafficDomainId = 0

    [DscProperty()]
    [ValidateSet('SERVER', 'FORWARD', 'TRANSPARENT', 'REVERSE')]
    [string]$CacheType = 'SERVER'

    [DscProperty()]
    [ValidateSet('DISABLED', 'DNS', 'POLICY')]
    [string]$AutoScale = 'DISABLED'

    [DscProperty()]
    [ValidateSet('NO', 'YES')]
    [string]$Cacheable = 'NO'
    
    [DscProperty()]
    [ValidateSet('ENABLED', 'DISABLED')]
    [string]$State = 'ENABLED'

    [DscProperty()]
    [ValidateSet('NO', 'YES')]
    [string]$HealthMonitor = 'YES'

    [DscProperty()]
    [ValidateSet('DISABLED', 'ENABLED')]
    [string]$AppFlowLog = 'ENABLED'

    [DscProperty()]
    [ValidateLength(0, 256)]
    [string]$Comment = [string]::Empty

    [DscProperty()]
    [ValidateSet('ON', 'OFF')]
    [string]$SureConnect = 'OFF'

    [DscProperty()]
    [ValidateSet('ON', 'OFF')]
    [string]$SurgeProtection = 'OFF'

    [DscProperty()]
    [ValidateSet('YES','NO')]
    [string]$UseProxyPort = 'YES'

    [DscProperty()]
    [ValidateSet('ENABLED','DISABLED')]
    [string]$DownStateFlush = 'ENABLED'

    [DscProperty()]
    [ValidateSet('YES','NO')]
    [string]$UseClientIP = "No"

    [DscProperty()]
    [ValidateSet('YES','NO')]
    [string]$ClientKeepAlive = 'NO'

    [DscProperty()]
    [ValidateSet('YES', 'NO')]
    [string]$TCPBuffering = 'NO'

    [DscProperty()]
    [ValidateSet('YES', 'NO')]
    [string]$HTTPCompression = 'YES'

    [DscProperty()]
    [ValidateSet('ENABLED','DISABLED')]
    [string]$ClientIP = 'DISABLED'

    [DscProperty()]
    [string]$ClientIPHeader

    [DscProperty()]
    [ValidateRange(0, 4294967287)]
    [int]$MaxBandwidthKbps

    [DscProperty()]
    [ValidateRange(0, 65535)]
    [int]$MonitorThreshold

    [DscProperty()]
    [ValidateRange(0, 65535)]
    [int]$MaxRequests

    [DscProperty()]
    [ValidateRange(0, 4294967294)]
    [int]$MaxClients

    [DscProperty()]
    [ValidateRange(0, 31536000)]
    [int]$ClientIdleTimeout = 180

    [DscProperty()]
    [ValidateRange(0, 31536000)]
    [int]$ServerIdleTimeout = 360

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }


    [void]Set() {
        $NSObject = $this.Get()
        try {
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Warning -Message "Setting Name cannot be changed to [$($this.Name)], must be recreated"
                        }                        
                        if ($NSObject.ServiceType -ne $this.ServiceType) {
                            Write-Warning -Message "Setting Service Type cannot be changed to [$($this.ServiceType)], must be recreated"
                        }                        
                        if ($NSObject.TrafficDomainId -ne $this.TrafficDomainId) {
                            Write-Warning -Message "Setting Traffic Domain cannot be changed to [$($this.TrafficDomainId)]"
                        }
                        if ($NSObject.CacheType -ne $this.CacheType) {
                            Write-Warning -Message "Setting Cache Type cannot be changed to[$($this.CacheType)]"
                        }
                        if ($NSObject.AutoScale -ne $this.AutoScale) {
                            Write-Verbose -Message "Setting Autoscale [$($this.AutoScale)]"
                            Set-NSLBServiceGroup -Name $this.Name -AutoScale $this.AutoScale -Force -Verbose:$false
                        }
                        if ($NSObject.Cacheable -ne $this.Cacheable) {
                            Write-Verbose -Message "Setting Cacheable [$($this.Cacheable)]"
                            Set-NSLBServiceGroup -Name $this.Name -Cacheable $this.Cacheable -Force -Verbose:$false
                        }
                        if ($NSObject.State -ne $this.State) {
                            Write-Verbose -Message "Setting State [$($this.State)]"
                            Set-NSLBServiceGroup -Name $this.Name -State $this.State -Force -Verbose:$false
                        }
                        if ($NSObject.HealthMonitor -ne $this.HealthMonitor) {
                            Write-Verbose -Message "Setting Health Monitor [$($this.HealthMonitor)]"
                            Set-NSLBServiceGroup -Name $this.Name -HealthMonitor $this.HealthMonitor -Force -Verbose:$false
                        }
                        if ($NSObject.AppFlowLog -ne $this.AppFlowLog) {
                            Write-Verbose -Message "Setting AppFlowLog [$($this.AppFlowLog)]"
                            Set-NSLBServiceGroup -Name $this.Name -AppFlowLog $this.AppFlowLog -Force -Verbose:$false
                        }
                        if ($NSObject.Comment -ne $this.Comment) {
                            Write-Verbose -Message "Setting Comment [$($this.Comment)]"
                            Set-NSLBServiceGroup -Name $this.Name -Comment $this.Comment -Force -Verbose:$false
                        }
                        if ($NSObject.SureConnect -ne $this.SureConnect) {
                            Write-Verbose -Message "Setting SureConnect [$($this.SureConnect)]"
                            Set-NSLBServiceGroup -Name $this.Name -SureConnect $this.SureConnect -Force -Verbose:$false
                        }
                        if ($NSObject.SurgeProtection -ne $this.SurgeProtection) {
                            Write-Verbose -Message "Setting Surge Protection [$($this.SurgeProtection)]"
                            Set-NSLBServiceGroup -Name $this.Name -SurgeProtection $this.SurgeProtection -Force -Verbose:$false
                        }
                        if ($NSObject.UseProxyPort -ne $this.UseProxyPort) {
                            Write-Verbose -Message "Setting Use Proxy Port [$($this.UseProxyPort)]"
                            Set-NSLBServiceGroup -Name $this.Name -UseProxyPort $this.UseProxyPort -Force -Verbose:$false
                        }
                        if ($NSObject.DownStateFlush -ne $this.DownStateFlush) {
                            Write-Verbose -Message "Setting DownState Flush [$($this.DownStateFlush)]"
                            Set-NSLBServiceGroup -Name $this.Name -DownStateFlush $this.DownStateFlush -Force -Verbose:$false
                        }
                        if ($NSObject.UseClientIP -ne $this.UseClientIP) {
                            Write-Verbose -Message "Setting Use Client IP [$($this.UseClientIP)]"
                            Set-NSLBServiceGroup -Name $this.Name -UseClientIP $this.UseClientIP -Force -Verbose:$false
                        }
                        if ($NSObject.ClientKeepAlive -ne $this.ClientKeepAlive) {
                            Write-Verbose -Message "Setting Client Keep Alive [$($this.ClientKeepAlive)]"
                            Set-NSLBServiceGroup -Name $this.Name -ClientKeepAlive $this.ClientKeepAlive -Force -Verbose:$false
                        }
                        if ($NSObject.TCPBuffering -ne $this.TCPBuffering) {
                            Write-Verbose -Message "Setting TCP Buffering [$($this.TCPBuffering)]"
                            Set-NSLBServiceGroup -Name $this.Name -TCPBuffering $this.TCPBuffering -Force -Verbose:$false
                        }
                        if ($NSObject.HTTPCompression -ne $this.HTTPCompression) {
                            Write-Verbose -Message "Setting HTTP Compression [$($this.HTTPCompression)]"
                            Set-NSLBServiceGroup -Name $this.Name -HTTPCompression $this.HTTPCompression -Force -Verbose:$false
                        }
                        if ($NSObject.ClientIP -ne $this.ClientIP) {
                            Write-Verbose -Message "Setting Client IP [$($this.ClientIP)]"
                            Set-NSLBServiceGroup -Name $this.Name -ClientIP $this.ClientIP -Force -Verbose:$false
                        }
                        if ($NSObject.MaxBandwidthKbps -ne $this.MaxBandwidthKbps) {
                            Write-Verbose -Message "Setting Maximum Bandwidth (Kbps) [$($this.MaxBandwidthKbps)]"
                            Set-NSLBServiceGroup -Name $this.Name -MaxBandwidthKbps $this.MaxBandwidthKbps -Force -Verbose:$false
                        }
                        if ($NSObject.MonitorThreshold -ne $this.MonitorThreshold) {
                            Write-Verbose -Message "Setting Monitor Threshold [$($this.MonitorThreshold)]"
                            Set-NSLBServiceGroup -Name $this.Name -MonitorThreshold $this.MonitorThreshold -Force -Verbose:$false
                        }
                        if ($NSObject.MaxRequests -ne $this.MaxRequests) {
                            Write-Verbose -Message "Setting Maximum Client Requests [$($this.MaxRequests)]"
                            Set-NSLBServiceGroup -Name $this.Name -MaxRequests $this.MaxRequests -Force -Verbose:$false
                        }
                        if ($NSObject.MaxClients -ne $this.MaxClients) {
                            Write-Verbose -Message "Setting Maximum Client connections [$($this.MaxClients)]"
                            Set-NSLBServiceGroup -Name $this.Name -MaxClients $this.MaxClients -Force -Verbose:$false
                        }
                        if ($NSObject.ClientIdleTimeout -ne $this.ClientIdleTimeout) {
                            Write-Verbose -Message "Setting Client Idle Timeout [$($this.ClientIdleTimeout)]"
                            Set-NSLBServiceGroup -Name $this.Name -ClientIdleTimeout $this.ClientIdleTimeout -Force -Verbose:$false
                        }
                        if ($NSObject.ServerIdleTimeout -ne $this.ServerIdleTimeout) {
                            Write-Verbose -Message "Setting Server Idle Timeout [$($this.ServerIdleTimeout)]"
                            Set-NSLBServiceGroup -Name $this.Name -ServerIdleTimeout $this.ServerIdleTimeout -Force -Verbose:$false
                        }
                    } else {
                        Write-Verbose -Message "Creating Service Group [$($this.Name)]"
                        $params = @{
                            name = $this.Name
                            servicetype = $this.ServiceType
                            state = $this.State
                            comment = $this.Comment
                        }
                        if ($PSBoundParameters.ContainsKey('TrafficDomainId')) {
                            $params.Add('TrafficDomainId', $this.TrafficDomainId)
                        }
                        if ($PSBoundParameters.ContainsKey('MaxClients')) {
                            $params.Add('MaxClients', $this.MaxClients)
                        }
                        if ($PSBoundParameters.ContainsKey('CacheType')) {
                            $params.Add('CacheType', $this.CacheType)
                        }
                        if ($PSBoundParameters.ContainsKey('AutoScale')) {
                            $params.Add('AutoScale', $this.AutoScale)
                        }
                        if ($PSBoundParameters.ContainsKey('Cacheable')) {
                            $params.Add('Cacheable', $this.Cacheable)
                        }
                        if ($PSBoundParameters.ContainsKey('HealthMonitor')) {
                            $params.Add('HealthMonitor', $this.HealthMonitor)
                        }
                        if ($PSBoundParameters.ContainsKey('AppFlowLog')) {
                            $params.Add('AppFlowLog', $this.AppFlowLog)
                        }
                        if ($PSBoundParameters.ContainsKey('SureConnect')) {
                            $params.Add('SureConnect', $this.SureConnect)
                        }
                        if ($PSBoundParameters.ContainsKey('SurgeProtection')) {
                            $params.Add('SurgeProtection', $this.SurgeProtection)
                        }
                        if ($PSBoundParameters.ContainsKey('UseProxyPort')) {
                            $params.Add('UseProxyPort', $this.UseProxyPort)
                        }
                        if ($PSBoundParameters.ContainsKey('DownStateFlush')) {
                            $params.Add('DownStateFlush', $this.DownStateFlush)
                        }
                        if ($PSBoundParameters.ContainsKey('UseClientIP')) {
                            $params.Add('UseClientIP', $this.UseClientIP)
                        }
                        if ($PSBoundParameters.ContainsKey('ClientKeepAlive')) {
                            $params.Add('ClientKeepAlive', $this.ClientKeepAlive)
                        }
                        if ($PSBoundParameters.ContainsKey('TCPBuffering')) {
                            $params.Add('TCPBuffering', $this.TCPBuffering)
                        }
                        if ($PSBoundParameters.ContainsKey('HTTPCompression')) {
                            $params.Add('HTTPCompression', $this.HTTPCompression)
                        }
                        if ($PSBoundParameters.ContainsKey('ClientIP')) {
                            $params.Add('ClientIP', $this.ClientIP)
                        }
                        if ($PSBoundParameters.ContainsKey('MaxBandwidthKbps')) {
                            $params.Add('MaxBandwidthKbps', $this.MaxBandwidthKbps)
                        }
                        if ($PSBoundParameters.ContainsKey('DownStateFlush')) {
                            $params.Add('DownStateFlush', $this.DownStateFlush)
                        }
                        if ($PSBoundParameters.ContainsKey('MaxRequests')) {
                            $params.Add('MaxRequests', $this.MaxRequests)
                        }
                        if ($PSBoundParameters.ContainsKey('ClientIdleTimeout')) {
                            $params.Add('ClientIdleTimeout', $this.ClientIdleTimeout)
                        }
                        if ($PSBoundParameters.ContainsKey('ServerIdleTimeout')) {
                            $params.Add('ServerIdleTimeout', $this.ServerIdleTimeout)
                        }                         
                        New-NSLBServiceGroup @params -ErrorAction SilentlyContinue
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSLBServiceGroup -Name $NSObject.Name -Confirm:$false -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removing Netscaler monitor: $($this.Name)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

    [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Verbose -Message "Service Group Name doest not match [$($NSObject.Name) <> $($this.Name)]"
                            $pass = $false
                        }
                        if ($NSObject.ServiceType -ne $this.ServiceType) {
                            Write-Verbose -Message "Service Type does not match [$($NSObject.ServiceType) <> $($this.ServiceType)]"
                            $pass = $false
                        }
                        if ($NSObject.TrafficDomainId -ne $this.TrafficDomainId) {
                            Write-Verbose -Message "Traffic Domain does not match [$($NSObject.TrafficDomainId) <> $($this.TrafficDomainId)]"
                            $pass = $false
                        }
                        if ($NSObject.CacheType -ne $this.CacheType) {
                            Write-Verbose -Message "Cache Type does not match [$($NSObject.CacheType) <> $($this.CacheType)]"
                            $pass = $false
                        }
                        if ($NSObject.Cacheable -ne $this.Cacheable) {
                            Write-Verbose -Message "Cacheable setting does not match [$($NSObject.Cacheable) <> $($this.Cacheable)]"
                            $pass = $false
                        }
                        if ($NSObject.State -ne $this.State) {
                            Write-Verbose -Message "State does not match [$($NSObject.State) <> $($this.State)]"
                            $pass = $false
                        }
                        if ($NSObject.HealthMonitor -ne $this.HealthMonitor) {
                            Write-Verbose -Message "Health Monitor does not match [$($NSObject.HealthMonitor) <> $($this.HealthMonitor)]"
                            $pass = $false
                        }
                        if ($NSObject.AppFlowLog -ne $this.AppFlowLog) {
                            Write-Verbose -Message "AppFlowLog does not match [$($NSObject.AppFlowLog) <> $($this.AppFlowLog)]"
                            $pass = $false
                        }
                        if ($NSObject.Comment -ne $this.Comment) {
                            Write-Verbose -Message "Comment does not match [$($NSObject.Comment) <> $($this.Comment)]"
                            $pass = $false
                        }
                        if ($NSObject.SurgeProtection -ne $this.SurgeProtection) {
                            Write-Verbose -Message "Surge Protection does not match [$($NSObject.SurgeProtection) <> $($this.SurgeProtection)]"
                            $pass = $false
                        }
                        if ($NSObject.SureConnect -ne $this.SureConnect) {
                            Write-Verbose -Message "Sure Connect does not match [$($NSObject.SureConnect) <> $($this.SureConnect)]"
                            $pass = $false
                        }                            
                        if ($NSObject.UseProxyPort -ne $this.UseProxyPort) {
                            Write-Verbose -Message "Use Proxy Port does not match [$($NSObject.UseProxyPort) <> $($this.UseProxyPort)]"
                            $pass = $false
                        }
                        if ($NSObject.DownStateFlush -ne $this.DownStateFlush) {
                            Write-Verbose -Message "DownState Flush does not match [$($NSObject.DownStateFlush) <> $($this.DownStateFlush)]"
                            $pass = $false
                        }
                        if ($NSObject.UseClientIP -ne $this.UseClientIP) {
                            Write-Verbose -Message "Use Client IP does not match [$($NSObject.UseClientIP) <> $($this.UseClientIP)]"
                            $pass = $false
                        }
                        if ($NSObject.ClientKeepAlive -ne $this.ClientKeepAlive) {
                            Write-Verbose -Message "Client Keep Alive does not match [$($NSObject.ClientKeepAlive) <> $($this.ClientKeepAlive)]"
                            $pass = $false
                        }
                        if ($NSObject.TCPBuffering -ne $this.TCPBuffering) {
                            Write-Verbose -Message "TCP Buffering does not match [$($NSObject.TCPBuffering) <> $($this.TCPBuffering)]"
                            $pass = $false
                        }
                        if ($NSObject.HTTPCompression -ne $this.HTTPCompression) {
                            Write-Verbose -Message "HTTP Compression does not match [$($NSObject.HTTPCompression) <> $($this.HTTPCompression)]"
                            $pass = $false
                        }
                        if ($NSObject.ClientIP -ne $this.ClientIP) {
                            Write-Verbose -Message "Client IP does not match [$($NSObject.ClientIP) <> $($this.ClientIP)]"
                            $pass = $false
                        }
                        # if ($NSObject.ClientIPHeader -ne $this.ClientIPHeader) {
                        #     Write-Verbose -Message "ClientIP Header does not match [$($this.ClientIPHeader)]"
                        #     $pass = $false
                        # }
                        if ($NSObject.MaxBandwidthKbps -ne $this.MaxBandwidthKbps) {
                            Write-Verbose -Message "Maximum Banddwith (Kbps) does not match [$($NSObject.MaxBandwidthKbps) <> $($this.MaxBandwidthKbps)]"
                            $pass = $false
                        }
                        if ($NSObject.MonitorThreshold -ne $this.MonitorThreshold) {
                            Write-Verbose -Message "Monitor Threshold does not match [$($NSObject.MonitorThreshold) <> $($this.MonitorThreshold)]"
                            $pass = $false
                        }
                        if ($NSObject.MaxRequests -ne $this.MaxRequests) {
                            Write-Verbose -Message "Maximum Client Requests does not match [$($NSObject.MaxRequests) <> $($this.MaxRequests)]"
                            $pass = $false
                        }
                        if ($NSObject.MaxClients -ne $this.MaxClients) {
                            Write-Verbose -Message "Maximum Client connections does not match [$($NSObject.MaxClients) <> $($this.MaxClients)]"
                            $pass = $false
                        }
                        if ($NSObject.ClientIdleTimeout -ne $this.ClientIdleTimeout) {
                            Write-Verbose -Message "Client Idle Timeout does not match [$($NSObject.ClientIdleTimeout) <> $($this.ClientIdleTimeout)]"
                            $pass = $false
                        }
                        if ($NSObject.ServerIdleTimeout -ne $this.ServerIdleTimeout) {
                            Write-Verbose -Message "Server Idle Timeout does not match [$($NSObject.ServerIdleTimeout) <> $($this.ServerIdleTimeout)]"
                            $pass = $false
                        }
                    } else {
                        Write-Verbose -Message "Resource [$($this.Name)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBServiceGroup]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSLBServiceGroup -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBServiceGroup]::new()
        $obj.Name = $this.Name
        $obj.ServiceType = $this.ServiceType
        $obj.TrafficDomainID = $this.TrafficDomainID
        $obj.CacheType = $this.CacheType
        $obj.MaxClients = $this.MaxClients
        $obj.MaxRequests = $this.MaxRequests
        $obj.Cacheable = $this.Cacheable        
        $obj.ClientIP = $this.ClientIP
        $obj.UseClientIP = $this.UseClientIP
        $obj.UseProxyPort = $this.UseProxyPort
        $obj.SureConnect = $this.SureConnect
        $obj.SurgeProtection = $this.SurgeProtection
        $obj.ClientKeepAlive = $this.ClientKeepAlive
        $obj.ClientIdleTimeout = $this.ClientIdleTimeout
        $obj.ServerIdleTimeout = $this.ServerIdleTimeout        
        $obj.TCPBuffering = $this.TCPBuffering
        $obj.HTTPCompression = $this.HTTPCompression
        $obj.MaxBandwidthKbps = $this.MaxBandwidthKbps
        $obj.State = $this.State
        $obj.DownStateFlush = $this.DownStateFlush
        $obj.HealthMonitor = $this.HealthMonitor
        $obj.AppFlowLog = $this.AppFlowLog
        $obj.Comment = $this.Comment
        # $obj.ClientIPHeader = $this.ClientIPHeader
        $obj.MonitorThreshold = $this.MonitorThreshold  
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Name = $s.servicegroupname
            $obj.ServiceType = $s.servicetype
            $obj.TrafficDomainID = $s.td
            $obj.CacheType = $s.cachetype
            $obj.MaxClients = $s.maxclient
            $obj.MaxRequests = $s.maxreq
            $obj.Cacheable = $s.cacheable
            $obj.ClientIP = $s.cip
            $obj.UseClientIP = $s.usip            
            $obj.UseProxyPort = $s.useproxyport
            $obj.SureConnect = $s.sc
            $obj.SurgeProtection = $s.sp
            $obj.ClientKeepAlive = $s.cka            
            $obj.ClientIdleTimeout = $s.clttimeout
            $obj.ServerIdleTimeout = $s.svrtimeout
            $obj.TCPBuffering = $s.tcpb
            $obj.HTTPCompression = $s.cmp
            $obj.MaxBandwidthKbps = $s.maxbandwidth
            $obj.State = $s.state
            $obj.DownStateFlush = $s.downstateflush
            $obj.HealthMonitor = $s.healthmonitor
            $obj.AppFlowLog = $s.appflowlog
            $obj.Comment = $s.comment
            # $obj.ClientIPHeader = $s.cipheader
            $obj.MonitorThreshold = $s.monthreshold
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBNTPServer {
    [DscProperty(Key)]
    [string]$Server

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [int]$MinPollInterval

    [DscProperty()]
    [ValidateRange(0, 4094)]
    [int]$MaxPollInterval

    [DscProperty()]
    [ValidateSet('Yes','No')]
    [string]$PreferredNTPServer = 'Yes'

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        if ($NSObject.Server -ne $this.Server) {
                            Write-Warning -Message "The NTP server name cannot be set to [$($this.Server)], resource can only be removed and recreated"
                        }
                        if ($NSObject.MinPollInterval -ne $this.MinPollInterval) {
                            Write-Verbose -Message "Setting Service Group MinPollInterval [$($this.MinPollInterval)]"
                            Set-NSNTPServer -Server $this.Server -MinPollInterval $this.MinPollInterval -Verbose:$false
                        }
                        if ($NSObject.MaxPollInterval -ne $this.MaxPollInterval) {
                            Write-Verbose -Message "Setting Service Group MaxPollInterval [$($this.MaxPollInterval)]"
                            Set-NSNTPServer -Server $this.Server -MaxPollInterval $this.MaxPollInterval -Verbose:$false
                        }
                        if ($NSObject.PreferredNTPServer -ne $this.PreferredNTPServer) {
                            Write-Warning -Message "The preferred NTP server cannot be set to [$($this.PreferredNTPServer)], setting can only be set manually"
                        }
                    } else {
                        Write-Verbose -Message "Creating resource [$($this.Name)]"
                        $params = @{
                            server = $this.Server
                            minpoll  = $this.MinPollInterval
                            maxpoll  = $this.MaxPollInterval
                            preferredntpserver = $this.PreferredNTPServer
                        }
                        New-NSNTPServer @params -Verbose:$false -ErrorAction SilentlyContinue
                    }        
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSNTPServer -Server $this.Server -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removing resource: $($this.Server)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Server -ne $this.Server) {
                            Write-Verbose -Message "Server does not match [$($NSObject.Server) <> $($this.Server)]"
                            $pass = $false
                        }
                        if ($NSObject.MinPollInterval -ne $this.MinPollInterval) {
                            Write-Verbose -Message "Min Poll Interval does not match [$($NSObject.MinPollInterval) <> $($this.MinPollInterval)]"
                            $pass = $false
                        }
                        if ($NSObject.MaxPollInterval -ne $this.MaxPollInterval) {
                            Write-Verbose -Message "Max Poll Interval does not match [$($NSObject.MaxPollInterval) <> $($this.MaxPollInterval)]"
                            $pass = $false
                        }
                        if ($NSObject.PreferredNTPServer -ne $this.PreferredNTPServer) {
                            Write-Verbose -Message "Preferred NTP Server does not match [$($NSObject.PreferredNTPServer) <> $($this.PreferredNTPServer)]"
                            $pass = $false
                        }
                    } else {
                        Write-Verbose -Message "Resource [$($this.Server)] was not found"
                        $pass = $false
                    }
                } 
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass
    }

    [LBNTPServer]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSNTPServer -Name $this.Server -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBNTPServer]::new()
        $obj.Server = $this.Server
        $obj.MinPollInterval = $this.MinPollInterval
        $obj.MaxPollInterval = $this.MaxPollInterval
        $obj.PreferredNTPServer = $this.PreferredNTPServer
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Server = $s.serverip
            $obj.MinPollInterval = $s.minpoll
            $obj.MaxPollInterval = $s.maxpoll
            $obj.PreferredNTPServer = $s.preferredntpserver
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBResponderPolicy {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [string]$Rule

    [DscProperty()]
    [string]$Comment

    [DscProperty(Mandatory)]
    [string]$Action

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Warning -Message "The Name cannot be changed to [$($this.Name)], resource can only be removed and recreated"
                        }
                        if ($NSObject.Rule -ne $this.Rule) {
                            Write-Verbose -Message "Setting Rule [$($this.Rule)]"
                            Set-NSResponderPolicy -Name $this.Name -Rule $this.Rule -Verbose:$false
                        }
                        if ($NSObject.Action -ne $this.Action) {
                            Write-Verbose -Message "Setting Service Group Name [$($this.MaxPollInterval)]"
                            Set-NSResponderPolicy -Name $this.Name -Action $this.Action -Verbose:$false
                        }
                        if ($NSObject.Comment -ne $this.Comment) {
                            Write-Verbose -Message "Setting monitor's Interval Type [$($this.Comment)]"
                            Set-NSResponderPolicy -Name $this.Name -Comment $this.Comment -Verbose:$false
                        }   
                    } else {
                        Write-Verbose -Message "Creating resource [$($this.Name)]"
                        $params = @{
                            name = $this.Name
                            rule  = $this.Rule
                            action  = $this.Action
                            comment  = $this.Comment
                        }
                        New-NSResponderPolicy @params -ErrorAction SilentlyContinue
                    }        
            } 'Absent' {
                if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSResponderPolicy -Name $NSObject.Name -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removed Responder Policy: $($this.Name)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Verbose -Message "Name does not match [$($NSObject.Name) <> $($this.Name)]"
                            $pass = $false
                        }
                        if ($NSObject.Rule -ne $this.Rule) {
                            Write-Verbose -Message "Rule does not match [$($NSObject.Rule) <> $($this.Rule)]"
                            $pass = $false
                        }
                        if ($NSObject.Action -ne $this.Action) {
                            Write-Verbose -Message "Action does not match [$($NSObject.Action) <> $($this.Action)]"
                            $pass = $false
                        }
                    } else {
                        Write-Verbose -Message "Responder Policy [$($this.Name)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBResponderPolicy]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSResponderPolicy -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBResponderPolicy]::new()
        $obj.Name = $this.Name
        $obj.Rule = $this.Rule
        $obj.Action = $this.Action
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Name = $s.name
            $obj.Rule = $s.rule
            $obj.Action = $s.action.toString()
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBResponderAction {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [ValidateSet('NOOP','Redirect','RespondWith', 'RespondWithSQLOK','RespondWithSQLError','RespondWithHTMLPage')] 
    [string]$Type = 'NOOP'

    [DscProperty()]
    [ValidateLength(0, 8191)]
    [Alias('Expression')]
    [string]$Target = [string]::Empty

    [DscProperty()]
    [ValidateRange(100, 599)]
    [int]$ResponseStatusCode

    [DscProperty()]
    [ValidateLength(0, 8191)]
    [string]$ReasonPhrase = [string]::Empty

    [DscProperty()]
    [ValidateLength(0, 256)]
    [string]$Comment = [string]::Empty


    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Verbose -Message "Warning, resource cannot be changed to [$($this.Name)], resource can only be removed and recreated"
                        }
                        if ($NSObject.Type -ne $this.Type) {
                            Write-Verbose -Message "Setting Responder Action [$($this.Type)]"
                            Set-NSResponderAction -Name $this.Name -Type $this.Type -Verbose:$false
                        }
                        if ($NSObject.Target -ne $this.Target) {
                            Write-Verbose -Message "Setting Responder Action [$($this.Target)]"
                            Set-NSResponderAction -Name $this.Name -Target $this.Target -Verbose:$false
                        }
                        if ($NSObject.Comment -ne $this.Comment) {
                            Write-Verbose -Message "Setting Responder Action [$($this.Comment)]"
                            Set-NSResponderAction -Name $this.Name -Comment $this.Comment -Verbose:$false
                        }   
                } else {
                        Write-Verbose -Message "Creating resource [$($this.Name)]"
                        $params = @{
                            name = $this.Name
                            type  = $this.Type
                            target  = $this.Target
                            comment  = $this.Comment
                        }
                        New-NSResponderAction @params -ErrorAction SilentlyContinue
                    }        
            } 'Absent' {
                if ($this.Ensure -ne $NSObject.Ensure) {                
                    Remove-NSResponderAction -Name $NSObject.Name -ErrorAction SilentlyContinue
                    Write-Verbose -Message "Removed Responder Action: $($this.Name)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Verbose -Message "Name does not match [$($NSObject.Name) <> $($this.Name)]"
                            $pass = $false
                        }
                        if ($NSObject.Type -ne $this.Type) {
                            Write-Verbose -Message "Type does not match [$($NSObject.Type) <> $($this.Type)]"
                            $pass = $false
                        }
                        if ($NSObject.Target -ne $this.Target) {
                            Write-Verbose -Message "Target does not match [$($NSObject.Target) <> $($this.Target)]"
                            $pass = $false
                        }
                    } else {
                        Write-Verbose -Message "Responder Action [$($this.Name)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBResponderAction]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSResponderAction -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBResponderAction]::new()
        $obj.Name = $this.Name
        $obj.Type = $this.Type
        $obj.Target = $this.Target
        $obj.Comment = $this.Comment
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Name = $s.name
            $obj.Type = $s.type
            $obj.Target = $s.target
            $obj.Comment = $s.comment
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBRewritePolicy {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [string]$ActionName

    [DscProperty()]
    [string]$LogActionName

    [DscProperty()]
    [ValidateLength(0, 8191)]
    [Alias('Expression')]
    [string]$Rule

    [DscProperty()]
    [string]$Comment

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.name -ne $this.Name) {
                            Write-Verbose -Message "Warning, resource cannot be changed to [$($this.Name)], resource can only be removed and recreated"
                        }
                        if ($NSObject.rule -ne $this.Rule) {
                            Write-Verbose -Message "Setting Rule [$($this.Rule)]"
                            Set-NSRewritePolicy -Name $this.Name -Rule $this.Rule -Verbose:$false
                        }
                        if ($NSObject.actionname -ne $this.ActionName) {
                            Write-Verbose -Message "Setting Action Name [$($this.ActionName)]"
                            Set-NSRewritePolicy -Name $this.Name -ActionName $this.ActionName -LogActionName $this.LogActionName -Rule $this.Rule -Verbose:$false
                        }                    
                        if ($NSObject.logActionname -ne "Use Global") {
                            if ($NSObject.logactionname -ne $this.LogActionName) {                                
                                Write-Verbose -Message "Setting LogActionName [$($this.LogActionName)]"
                                Set-NSRewritePolicy -Name $this.Name -LogActionName $this.LogActionName -Verbose:$false
                            }
                        }
                        if ($NSObject.Comment -ne $this.Comment) {
                            Write-Verbose -Message "Setting Comment [$($this.Comment)]"
                            Set-NSRewritePolicy -Name $this.Name -Comment $this.Comment -Verbose:$false
                        }
                } else {
                        Write-Verbose -Message "Creating resource [$($this.Name)]"
                        $params = @{
                            name = $this.Name
                            rule  = $this.Rule
                            actionname  = $this.ActionName
                            comment  = $this.Comment
                        }
                        if ($PSBoundParameters.ContainsKey('LogActionName')) {
                            $params.Add('LogActionName', $this.LogActionName)
                        }                        
                        New-NSRewritePolicy @params -ErrorAction SilentlyContinue
                    }        
            } 'Absent' {
                if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSRewritePolicy -Name $NSObject.Name -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removed Rewrite Policy: $($this.Name)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Verbose -Message "Name does not match [$($NSObject.Name) <> $($this.Name)]"
                            $pass = $false
                        }
                        if ($NSObject.Rule -ne $this.Rule) {
                            Write-Verbose -Message "Rule does not match [$($NSObject.Rule) <> $($this.Rule)]"
                            $pass = $false
                        }
                        if ($NSObject.ActionName -ne $this.ActionName) {
                            Write-Verbose -Message "Action Name does not match [$($NSObject.ActionName) <> $($this.ActionName)]"
                            $pass = $false
                        }
                        if ($NSObject.LogActionName -ne "Use Global") {
                            if ($NSObject.LogActionName -ne $this.LogActionName) {
                                Write-Verbose -Message "Log Action Name does not match [$($NSObject.LogActionName) <> $($this.LogActionName)]"
                                $pass = $false
                            }
                        }
                        if ($NSObject.Comment -ne $this.Comment) {
                            Write-Verbose -Message "Comment does not match [$($NSObject.Comment) <> $($this.Comment)]"
                            $pass = $false
                        }                                              
                    } else {
                        Write-Verbose -Message "Responder Policy [$($this.Name)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBRewritePolicy]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSRewritePolicy -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBRewritePolicy]::new()
        $obj.Name = $this.Name
        $obj.Rule = $this.Rule
        $obj.ActionName = $this.ActionName
        $obj.LogActionName = $this.LogActionName
        $obj.Comment = $this.Comment
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Name = $s.name
            $obj.Rule = $s.rule
            $obj.ActionName = $s.action
            $obj.LogActionName = $s.logaction
            $obj.Comment = $s.comment
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBRewriteAction {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [string]$Type

    [DscProperty(Mandatory)]
    [ValidateLength(0, 8191)]
    [string]$Target

    [DscProperty(Mandatory)]
    [ValidateLength(0, 8191)]
    [string]$Expression

    [DscProperty()]
    [string]$Comment

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne $this.Name) {
                            Write-Verbose -Message "Warning, resource cannot be changed to [$($this.Name)], resource can only be removed and recreated"
                        }
                        if ($NSObject.Type -ne $this.Type) {
                            Write-Verbose -Message "Setting Rule [$($this.Type)]"
                            Set-NSRewriteAction -Name $this.Name -Type $this.Type -Target $this.Target -Expression $this.Expression -Comment $this.Comment -Verbose:$false
                        }
                        if ($NSObject.Target -ne $this.Target) {
                            Write-Verbose -Message "Setting Action Name [$($this.Target)]"
                            Set-NSRewriteAction -Name $this.Name -Target $this.Target -Verbose:$false
                        }                    
                        if ($NSObject.Expression -ne $this.Expression) {
                            Write-Verbose -Message "Setting LogActionName [$($this.Expression)]"
                            Set-NSRewriteAction -Name $this.Name -Expression $this.Expression -Verbose:$false
                        }
                        if ($NSObject.Comment -ne $this.Comment) {
                            Write-Verbose -Message "Setting Comment [$($this.Comment)]"
                            Set-NSRewriteAction -Name $this.Name -Comment $this.Comment -Verbose:$false
                        }
                } else {
                        Write-Verbose -Message "Creating resource [$($this.Name)]"
                        $params = @{
                            name = $this.Name
                            Type  = $this.Type.toLower()
                            Target  = $this.Target
                            Expression = $this.Expression
                            Comment  = $this.Comment
                        }
                        New-NSRewriteAction @params -ErrorAction SilentlyContinue
                    }        
            } 'Absent' {
                if ($this.Ensure -ne $NSObject.Ensure) {                
                    Remove-NSRewriteAction -Name $NSObject.Name -ErrorAction SilentlyContinue
                    Write-Verbose -Message "Removed Rewrite Action: $($this.Name)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.name -ne $this.Name) {
                            Write-Verbose -Message "Name does not match [$($NSObject.Name) <> $($this.Name)]"
                            $pass = $false
                        }
                        if ($NSObject.type -ne $this.Type) {
                            Write-Verbose -Message "Type does not match [$($NSObject.Type) <> $($this.Type)]"
                            $pass = $false
                        }
                        if ($NSObject.target -ne $this.Target) {
                            Write-Verbose -Message "Target does not match [$($NSObject.Target) <> $($this.Target)]"
                            $pass = $false
                        }
                        if ($NSObject.Expression -ne $this.Expression) {
                            Write-Verbose -Message "Expression does not match [$($NSObject.Expression) <> $($this.Expression)]"
                            $pass = $false
                        }
                        if ($NSObject.comment -ne $this.Comment) {
                            Write-Verbose -Message "Comment does not match [$($NSObject.Comment) <> $($this.Comment)]"
                            $pass = $false
                        }                                              
                    } else {
                        Write-Verbose -Message "Responder Action [$($this.Name)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBRewriteAction]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSRewriteAction -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBRewriteAction]::new()
        $obj.Name = $this.Name
        $obj.Type = $this.Type
        $obj.Target = $this.Target
        $obj.Expression = $this.Expression
        $obj.Comment = $this.Comment
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.Name = $s.name
            $obj.Type = $s.type
            $obj.Target = $s.target
            $obj.Expression = $s.stringbuilderexpr
            $obj.Comment = $s.comment
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBDNSServer {
    [DscProperty(Key)]
    [string]$IPAddress

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [ValidateLength(0, 8191)]
    [string]$Local = $false

    [DscProperty()]
    [ValidateSet('ENABLED','DISABLED')]
    [string]$State = 'ENABLED'

    [DscProperty()]
    [ValidateSet('UDP', 'TCP', 'UDP_TCP')]
    [string]$Type = 'UDP'


    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if (($NSObject.ip -ne $this.IPAddress) -OR ($NSObject.state -ne $this.State) -OR ($NSObject.type -ne $this.Type))   {
                            Write-Verbose -Message "Warning, resource cannot be changed to [$($this.Name)], resource can only be removed and recreated. Resource deleted and re-added"
                            Remove-NSDnsNameServer -IPAddress $this.IPAddress -Verbose:$false -ErrorAction SilentlyContinue
                            Add-NSDnsNameServer -IPAddress $this.IPAddress -State $this.State -Type $this.Type -Verbose:$false -ErrorAction SilentlyContinue
                        }
                    } else {
                        Write-Verbose -Message "Creating resource [$($this.IPAddress)]"
                        $params = @{
                            ip = $this.IPAddress
                            type  = $this.Type
                            state  = $this.State
                        }
                        Add-NSDnsNameServer @params -Verbose:$false -ErrorAction SilentlyContinue
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSDnsNameServer -IPAddress $this.IPAddress -Verbose:$false -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removed DNS Server: $($this.IPAddress)"                        
                    }
                }

            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

  [bool]Test() {
        $pass = $true
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            if ($NSObject.IPAddress -ne $this.IPAddress) {
                                Write-Verbose -Message "IP Address does not match [$($NSObject.IPAddress) <> $($this.IPAddress)]"
                                $pass = $false
                            }
                            if ($NSObject.Local -ne $this.Local) {
                                Write-Verbose -Message "Local does not match [$($NSObject.Local) <> $($this.Local)]"
                                $pass = $false
                            }
                            if ($NSObject.State -ne $this.State) {
                                Write-Verbose -Message "State does not match [$($NSObject.State) <> $($this.State)]"
                                $pass = $false
                            }
                            if ($NSObject.Type -ne $this.Type) {
                                Write-Verbose -Message "Type does not match [$($NSObject.Type) <> $($this.Type)]"
                                $pass = $false
                            }
                    } else {
                        Write-Verbose -Message "DNS server [$($this.IPAddress)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }

            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBDNSServer]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSDnsNameServer | where {$_.ip -eq $this.IPAddress} -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBDNSServer]::new()
        $obj.IPAddress = $this.IPAddress
        $obj.Local = $this.Local
        $obj.State = $this.State
        $obj.Type = $this.Type
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.IPAddress = $s.ip
            $obj.Local = $s.local
            $obj.State = $s.state
            $obj.Type = $s.type
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBNSMode {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne "True") {
                            Write-Verbose -Message "Mode enabled, [$($this.Name)]"
                            Enable-NSMode -name $this.name -Confirm:$false
                        }
                    } else {
                        Write-Verbose -Message "Mode enabled, [$($this.Name)]"
                        Enable-NSMode -name $this.name -Confirm:$false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Disable-NSMode -Name $this.Name -Confirm:$false
                        Write-Verbose -Message "Mode disabled: $($this.Name)"
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }


 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne "True") {
                            Write-Verbose -Message "Mode is not set [$($NSObject.Name) <> $($this.Name)]"
                            $pass = $false
                        }
                    } else {
                        $pass = $false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    } else {
                        if ($NSObject.Name -eq "True") {
                            $pass = $false
                        }
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBNSMode]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSMode -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBNSMode]::new()
            $obj.Name = $this.Name
        if ($s) {
                $obj.Ensure = [ensure]::Present
                $obj.Name = $s
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBNSFeature {
    [DscProperty(Key)]
    [string]$Name

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne "True") {
                            Write-Verbose -Message "Feature enabled, [$($this.Name)]"
                            Enable-NSFeature -name $this.name -Confirm:$false
                        }
                    } else {
                        Write-Verbose -Message "Feature enabled, [$($this.Name)]"
                        Enable-NSFeature -name $this.name -Confirm:$false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Disable-NSFeature -Name $this.Name -Confirm:$false
                        Write-Verbose -Message "Feature disabled: $($this.Name)"
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }


 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.Name -ne "True") {
                            Write-Verbose -Message "Feature is not set [$($NSObject.Name) <> $($this.Name)]"
                            $pass = $false
                        }
                    } else {
                        $pass = $false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    } else {
                        if ($NSObject.Name -eq "True") {
                            $pass = $false
                        }
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBNSFeature]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSFeature -Name $this.Name -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBNSFeature]::new()
            $obj.Name = $this.Name
        if ($s) {
                $obj.Ensure = [ensure]::Present
                $obj.Name = $s.name
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBSSLCertificate {
    [DscProperty(Key)]
    [string]$CertKeyName

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [string]$CertPath

    [DscProperty()]
    [string]$KeyPath

    [DscProperty()]
    [ValidateSet('PEM','DER','PFX')]
    [string]$CertKeyFormat = 'PEM'

    [DscProperty()]
    [securestring]$Password


    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if (($NSObject.CertKeyName -ne $this.CertKeyName) -OR ($NSObject.CertPath -ne $this.CertPath) -OR ($NSObject.KeyPath -ne $this.KeyPath) -OR ($NSObject.CertKeyFormat -ne $this.CertKeyFormat)) {
                            Write-Verbose -Message "Warning, resource cannot be changed to [$($this.CertKeyName)], resource can only be removed and recreated"
                            Remove-NSCertKeyPair -CertKeyName $this.CertKeyName
                        }                 
                } else {
                        Write-Verbose -Message "Creating resource [$($this.CertKeyName)]"
                        $params = @{
                            CertKeyName = $this.CertKeyName
                            CertPath  = $this.CertPath
                            KeyPath  = $this.KeyPath
                            CertKeyFormat = $this.CertKeyFormat
                        }
                        Add-NSCertKeyPair @params -ErrorAction SilentlyContinue
                    }
                }       
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSResponderAction -Name $NSObject.CertKeyName -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removed Certificate: $($this.Name)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                            if ($NSObject.certkeyname -ne $this.CertKeyName) {
                                Write-Verbose -Message "Certificate Key Name does not match [$($NSObject.certkeyname) <> $($this.CertKeyName)]"
                                $pass = $false
                            }
                            if ($NSObject.certpath -ne $this.CertPath) {
                                Write-Verbose -Message "Certificate Path does not match [$($NSObject.certpath) <> $($this.CertPath)]"
                                $pass = $false
                            }
                            if ($this.KeyPath) {
                                if ($NSObject.keypath -ne $this.KeyPath) {
                                    Write-Verbose -Message "Key Path does not match [$($NSObject.keypath) <> $($this.KeyPath)]"
                                    $pass = $false
                                }
                            }
                    } else {
                        Write-Verbose -Message "Certificate[$($this.CertKeyName)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBSSLCertificate]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSCertKeyPair -CertKeyName $this.CertKeyName -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }
        $obj = [LBSSLCertificate]::new()
        $obj.CertKeyName = $this.CertKeyName
        $obj.CertPath = $this.CertPath        
        $obj.CertKeyFormat = $this.CertKeyFormat
        $obj.KeyPath = $this.KeyPath        
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.CertKeyName = $s.certkey
            $obj.CertPath = $s.cert
            $obj.CertKeyFormat = $s.inform
            if ($s.key) {
                $obj.KeyPath = $s.key
            }
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBNSIP {
    [DscProperty(Key)]
    [string]$IPAddress

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [string]$SubnetMask

    [DscProperty()]
    [string]$Type = 'SNIP'

    [DscProperty(Mandatory)]
    [bool]$VServer = $false

    [DscProperty(Mandatory)]
    [bool]$Telnet = $false

    [DscProperty(Mandatory)]
    [bool]$FTP = $false

    [DscProperty(Mandatory)]
    [bool]$GUI = $false

    [DscProperty(Mandatory)]
    [bool]$SSH = $false

    [DscProperty(Mandatory)]
    [bool]$SNMP = $false

    [DscProperty(Mandatory)]
    [bool]$MgmtAccess = $false

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.IPAddressName -ne $this.IPAddress) {
                            Write-Verbose -Message "Warning, the resource cannot be set to [$($this.IPAddress)]"
                        }
                        if ($NSObject.SubnetMask -ne $this.SubnetMask) {
                            Write-Verbose -Message "Resource name does not match [$($this.SubnetMask)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask
                        } 
                        if ($NSObject.Type -ne $this.Type) {
                            Write-Verbose -Message "Warning, the resource cannot be set to [$($this.Type)]"
                        }
                        if ($NSObject.VServer -ne $this.VServer) {
                            Write-Verbose -Message "Setting vServer [$($this.VServer)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask -VServer
                        }
                        if ($NSObject.Telnet -ne $this.Telnet) {
                            Write-Verbose -Message "Setting Telnet [$($this.Telnet)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask -Telnet
                        }                                                                                     
                        if ($NSObject.FTP -ne $this.FTP) {
                            Write-Verbose -Message "Setting FTP [$($this.FTP)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask -FTP
                        }
                        if ($NSObject.GUI -ne $this.GUI) {
                            Write-Verbose -Message "Setting GUI [$($this.GUI)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask -GUI
                        }
                        if ($NSObject.SSH -ne $this.SSH) {
                            Write-Verbose -Message "Setting GUI [$($this.SSH)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask -SSH
                        }
                        if ($NSObject.SNMP -ne $this.SNMP) {
                            Write-Verbose -Message "Setting SNMP [$($this.SNMP)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask -SNMP
                        }
                        if ($NSObject.MgmtAccess -ne $this.MgmtAccess) {
                            Write-Verbose -Message "Setting Management Access [$($this.MgmtAccess)]"
                            Set-NSIPResource -IPAddress $this.IPAddress -SubnetMask $this.SubnetMask -MgmtAccess
                        }
                    } else {
                        Write-Verbose -Message "Feature enabled, [$($this.IPAddress)]"
                        $params = @{
                            ipaddress = $this.IPAddress
                            netmask = $this.SubnetMask
                            type = $this.Type
                        }                         
                       Add-NSIPResource @params -Confirm:$false
                    #    $switches {
                    #         ipaddress = $this.IPAddress
                    #         netmask = $this.SubnetMask
                    #         type = $this.Type
                    #         vserver = $this.VServer
                    #         telnet = $this.Telnet
                    #         ftp = $this.FTP
                    #         gui = $this.GUI
                    #         ssh = $this.SSH
                    #         snmp = $this.SNMP        
                    #         mgmtaccess = $this.mgmtaccess
                    #    }
                    #    Invoke-DscResource -Method set -ModuleName poshorigin_netscaler -Name LBNSIP -Property $switches
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Disable-NSFeature -Name $this.Name -Confirm:$false
                        Write-Verbose -Message "Feature disabled: $($this.Name)"
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }


 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {                                                                        
                        # # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.ipaddress -ne $this.IPAddress) {
                            Write-Verbose -Message "IPAddress does not match [$($NSObject.ipaddress) <> $($this.IPAddress)]"
                            $pass = $false
                        }
                        if ($NSObject.subnetmask -ne $this.SubnetMask) {
                            Write-Verbose -Message "SubnetMask does not match [$($NSObject.subnetmask) <> $($this.SubnetMask)]"
                            $pass = $false
                        }
                        if ($NSObject.type -ne $this.Type) {
                            Write-Verbose -Message "Type does not match [$($NSObject.type) <> $($this.Type)]"
                            $pass = $false
                        }
                        if ($NSObject.vserver -ne $this.VServer) {
                            Write-Verbose -Message "VServer does not match [$($NSObject.vserver) <> $($this.VServer)]"
                            $pass = $false
                        }
                        if ($NSObject.telnet -ne $this.Telnet) {
                            Write-Verbose -Message "Telnet does not match [$($NSObject.telnet) <> $($this.Telnet)]"
                            $pass = $false
                        }
                        if ($NSObject.ftp -ne $this.FTP) {
                            Write-Verbose -Message "FTP does not match [$($NSObject.ftp) <> $($this.FTP)]"
                            $pass = $false
                        }
                        if ($NSObject.gui -ne $this.GUI) {
                            Write-Verbose -Message "GUI does not match [$($NSObject.gui) <> $($this.GUI)]"
                            $pass = $false
                        }
                        if ($NSObject.ssh -ne $this.SSH) {
                            Write-Verbose -Message "SSH does not match [$($NSObject.ssh) <> $($this.SSH)]"
                            $pass = $false
                        }
                        if ($NSObject.snmp -ne $this.SNMP) {
                            Write-Verbose -Message "SNMP does not match [$($NSObject.snmp) <> $($this.SNMP)]"
                            $pass = $false
                        }
                        if ($NSObject.mgmtaccess -ne $this.MgmtAccess) {
                            Write-Verbose -Message "MgmtAccess does not match [$($NSObject.mgmtaccess) <> $($this.MgmtAccess)]"
                            $pass = $false
                        }                             
                    } else {
                        $pass = $false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    } else {
                        if ($NSObject.Name -eq "True") {
                            $pass = $false
                        }
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBNSIP]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSIPResource -IPAddress $this.IPAddress -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBNSIP]::new()
            $obj.IPAddress = $this.IPAddress
            $obj.SubnetMask = $this.SubnetMask
            $obj.Type = $this.Type
            $obj.VServer = $this.VServer
            $obj.Telnet = $this.Telnet
            $obj.FTP = $this.FTP
            $obj.GUI = $this.GUI
            $obj.SSH = $this.SSH
            $obj.SNMP = $this.SNMP
            $obj.MgmtAccess = $this.MgmtAccess
        if ($s) {
                $obj.Ensure = [ensure]::Present
                $obj.IPAddress = $s.ipaddress
                $obj.SubnetMask = $s.netmask
                $obj.Type = $s.type
                $obj.VServer = $this.TestEnabledFeatures($s.VServer)
                $obj.Telnet = $this.TestEnabledFeatures($s.Telnet)
                $obj.FTP = $this.TestEnabledFeatures($s.FTP)
                $obj.GUI = $this.TestEnabledFeatures($s.GUI)
                $obj.SSH = $this.TestEnabledFeatures($s.SSH)
                $obj.SNMP = $this.TestEnabledFeatures($s.SNMP)
                $obj.MgmtAccess = $this.TestEnabledFeatures($s.MgmtAccess)
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }

    <#
        Helper method to test switch/boolean options 
    #>
    [bool] TestEnabledFeatures([string] $Existing){
        # $present = $true
        if ($Existing -eq "ENABLED") {
            $present = $true
        } else {
            $present = $false
        }
        return $present
    }
}


[DscResource()]
class LBNSVirtualServerBinding {
    [DscProperty(Key)]
    [string]$VirtualServerName

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [string]$ServiceGroupName

    [DscProperty()]
    [string]$ServiceName

    [DscProperty()]
    [int]$Weight = 1

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($this.ServiceGroupName -eq $NSObject.ServiceGroupName) {
                                Write-Verbose -Message "Service Group Name bound, [$($this.VirtualServerName)]"
                                Add-NSLBVirtualServerBinding -VirtualServerName $this.VirtualServerName -ServiceGroupName $this.ServiceGroupName -Weight $this.Weight -Confirm:$false
                        } else {
                            if (($this.ServiceName -ne $null) -OR ($NSObject.NetScalerFQDN -ne $null)) {
                                Write-Verbose -Message "Service Name bound, [$($this.ServiceName)]"
                                Add-NSLBVirtualServerBinding -VirtualServerName $this.VirtualServerName -ServiceName $this.ServiceName -Weight $this.Weight -Confirm:$false
                            }
                        }
                    } 
                } 'Absent' {
                    if ($this.ServiceGroupName) {
                        if ($this.Ensure -ne $NSObject.Ensure) {
                            Remove-NSLBVirtualServerBinding -name $this.VirtualServerName -ServiceGroupName $this.ServiceGroupName -Confirm:$false
                            Write-Verbose -Message "Virtual Server Binding removed for $($this.VirtualServerName)"
                        }
                    } else {
                            Remove-NSLBVirtualServerBinding -name $this.VirtualServerName -ServiceName $this.ServiceName -Confirm:$false
                            Write-Verbose -Message "Virtual Server Binding removed for $($this.VirtualServerName)"
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($this.servicegroupname -eq $NSObject.ServiceGroupName) {                        
                            if ($NSObject.virtualservername -ne $this.VirtualServerName) {
                                Write-Verbose -Message "VirtualServerName does not match [$($NSObject.virtualservername) <> $($this.VirtualServerName)]"
                                $pass = $false
                            }
                            if ($NSObject.servicegroupname -ne $this.ServiceGroupName) {
                                Write-Verbose -Message "ServiceGroupName does not match [$($NSObject.servicegroupname) <> $($this.ServiceGroupName)]"
                                $pass = $false
                            }
                        } else {
                            if ($NSObject.virtualservername -ne $this.VirtualServerName) {
                                Write-Verbose -Message "VirtualServerName does not match [$($NSObject.virtualservername) <> $($this.VirtualServerName)]"
                                $pass = $false
                            }                            
                            if ($NSObject.servicename -ne $this.ServiceName) {
                                Write-Verbose -Message "ServiceName does not match [$($NSObject.servicename) <> $($this.ServiceName)]"
                                $pass = $false
                            }
                        }  
                    } else {
                        $pass = $false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    } else {
                        if ($NSObject.Name -eq "True") {
                            $pass = $false
                        }
                    }
                 }
              }   
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBNSVirtualServerBinding]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSLBVirtualServerBinding -Name $this.VirtualServerName -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }

        $obj = [LBNSVirtualServerBinding]::new()
            $obj.VirtualServerName = $this.VirtualServerName
            $obj.ServiceGroupName = $this.ServiceGroupName
            $obj.ServiceName = $this.ServiceName
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.VirtualServerName = $s.name
            $obj.ServiceGroupName = $s.ServiceGroupName
            $obj.ServiceName = $s.ServiceName
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}


[DscResource()]
class LBSystemFile {
    [DscProperty(Key)]
    [string]$FileName

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [string]$FileLocation

    [DscProperty(Mandatory)]
    [string]$Path


    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($NSObject.Ensure -ne $this.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if (!$NSObject.FileName) {
                            Write-Verbose -Message "Warning, resource cannot be changed to [$($this.FileName)], resource can only be removed and recreated"
                            Add-NSSystemFile -Path $this.Path -FileLocation $this.FileLocation -FileName $this.FileName -Force
                        }                 
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSSystemFile -Name $this.FileName -FileLocation $this.FileLocation -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removed File: $($this.Name)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                            if ($NSObject.filename -ne $this.FileName) {
                                Write-Verbose -Message "File Name does not match [$($NSObject.filename) <> $($this.FileName)]"
                                $pass = $false
                            }
                            if ($NSObject.filelocation -ne $this.FileLocation) {
                                Write-Verbose -Message "File Location does not match [$($NSObject.filelocation) <> $($this.FileLocation)]"
                                $pass = $false
                            }
                    } else {
                        Write-Verbose -Message "File[$($this.FileName)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBSystemFile]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSSystemFile -FileName $this.FileName -FileLocation $this.FileLocation -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }
        
        $obj = [LBSystemFile]::new()
        $obj.FileName
        $obj.FileLocation
        $obj.Path
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.FileName = $s.filename
            $obj.FileLocation = $s.filelocation
            if ($s.Path) {
                $obj.Path = $s.path
            }
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}

[DscResource()]
class LBVLAN {
    [DscProperty(Key)]
    [int]$VLANID

    [DscProperty()]
    [Ensure]$Ensure = [Ensure]::Present

    [DscProperty(Mandatory)]
    [string]$NetScalerFQDN    
    
    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [string]$AliasName

    [DscProperty()]
    [ValidateSet('ENABLED','DISABLED')] 
    [string]$IPV6DynamicRouting = 'DISABLED'

    [DscProperty(Mandatory)]
    [int]$MTU

    [DscProperty()]
    [string]$Interface

    [DscProperty()]
    [bool]$Tagged = $false

    Init() {
        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }
    }

    [void]Set() {
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()

        try {
            Import-Module -Name Netscaler -Verbose:$false -Debug:$false
            Connect-NetScaler -Hostname $this.NetScalerFQDN -Credential $this.Credential -Verbose:$false
        } catch {
            throw "Unable to establish a Netscaler session with $($this.NetScalerFQDN)"
        }

        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                        # Run tests and set any needed attributes to match desired configuration
                        if ($NSObject.vlanid -ne $this.VLANID) {
                            Write-Warning -Message "Setting VLANID cannot be changed to [$($this.VLANID)], resource can only be removed and recreated"
                        }
                        if ($NSObject.aliasname -ne $this.AliasName) {
                            Write-Verbose -Message "Setting AliasName [$($this.AliasName)]"
                            Set-NSVLAN -VLANID $this.VLANID -AliasName $this.AliasName
                        }
                        if ($NSObject.mtu -ne $this.AliasName) {
                            Write-Verbose -Message "Setting AliasName [$($this.AliasName)]"
                            Set-NSVLAN -VLANID $this.VLANID -AliasName $this.AliasName
                        }    
                        if ($NSObject.ipv6dynamicrouting -ne $this.IPV6DynamicRouting) {
                            Write-Verbose -Message "Setting AliasName [$($this.IPV6DynamicRouting)]"
                            Set-NSVLAN -VLANID $this.VLANID -IPV6DynamicRouting $this.IPV6DynamicRouting
                        }         
                        if ($NSObject.mtu -ne $this.MTU) {
                            Write-Verbose -Message "Setting AliasName [$($this.MTU)]"
                            Set-NSVLAN -VLANID $this.VLANID -MTU $this.MTU
                        }
                        if ($NSObject.interface -ne $this.Interface) {
                            Write-Verbose -Message "Setting Interface [$($this.Interface)]"
                            Set-NSVLANInterfaceBinding -VLANID $this.VLANID -Interface $this.Interface
                        }
                   } else {
                        Write-Verbose -Message "Feature enabled, [$($this.IPAddress)]"
                        $params = @{
                            vlanid = $this.VLANID
                            aliasname = $this.AliasName
                            ipv6dynamicrouting = $this.ipv6dynamicrouting
                            mtu = $this.MTU
                            interface = $this.Interface
                        }                         
                       Add-NSVLAN @params -Confirm:$false
                    }
                } 'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        Remove-NSVLAN -VLANID $this.VLANID -ErrorAction SilentlyContinue
                        Write-Verbose -Message "Removed VLANID: $($this.VLANID)"
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem setting the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
    }

 [bool]Test() {
        $pass = $true
        $t = $null
        $t = $this.Init()
        $NSObject = $this.Get()
        try {
            switch ($this.Ensure) {
                'Present' {
                    if ($this.Ensure -eq $NSObject.Ensure) {
                            # Run tests and set any needed attributes to match desired configuration
                            if ($NSObject.vlanid -ne $this.VLANID) {
                                Write-Verbose -Message "VLANID does not match [$($NSObject.vlanid) <> $($this.VLANID)]"
                                $pass = $false
                            }
                            if ($NSObject.aliasname -ne $this.AliasName) {
                                Write-Verbose -Message "Aliasname does not match [$($NSObject.aliasname) <> $($this.AliasName)]"
                                $pass = $false
                            }
                            if ($NSObject.ipv6dynamicrouting -ne $this.IPV6DynamicRouting) {
                                Write-Verbose -Message "IPV6 Dynamic Routing does not match [$($NSObject.ipv6dynamicrouting) <> $($this.IPV6DynamicRouting)]"
                                $pass = $false
                            }
                            if ($NSObject.mtu -ne $this.MTU) {
                                Write-Verbose -Message "MTU does not match [$($NSObject.mtu) <> $($this.MTU)]"
                                $pass = $false
                            }
                            if ($NSObject.interface -ne $this.Interface) {
                                Write-Verbose -Message "Interface does not match [$($NSObject.interface) <> $($this.Interface)]"
                                $pass = $false
                            }
                            if ($NSObject.tagged -ne $this.Tagged) {
                                Write-Verbose -Message "Tagged does not match [$($NSObject.Tagged) <> $($this.Tagged)]"
                                $pass = $false
                            }      
                    } else {
                        Write-Verbose -Message "File[$($this.VLANID)] was not found"
                        $pass = $false
                    }
                }
                'Absent' {
                    if ($this.Ensure -ne $NSObject.Ensure) {
                        $pass = $false
                    }
                }
            }
        } catch {
            Write-Error 'There was a problem testing the resource'
            Write-Error "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
            Write-Error $_
        }
        try {
            Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            # Do nothing
        }
        return $pass        
    }

    [LBVLAN]Get() {
        $t = $null
        $t = $this.Init()

        try {
            $s = Get-NSVLAN -VLANID $this.VLANID -Verbose:$false -ErrorAction SilentlyContinue
        } catch {
            $s = $null
        }
        
        $obj = [LBVLAN]::new()
        $obj.VLANID = $this.VLANID
        $obj.AliasName = $this.AliasName
        $obj.IPV6DynamicRouting = $this.IPV6DynamicRouting
        $obj.MTU = $this.MTU
        $obj.Interface = $this.Interface
        $obj.Tagged = $this.Tagged
        if ($s) {
            $obj.Ensure = [ensure]::Present
            $obj.VLANID = $s.id
            if ($s.AliasName) { $obj.AliasName = $s.aliasname }
            $obj.IPV6DynamicRouting = $s.ipv6dynamicrouting
            if ($s.mtu) { $obj.MTU = $s.mtu }
            $obj.Interface = $s.ifaces.ToString()
            $obj.Tagged = $s.tagged
        } else {
            $obj.Ensure = [ensure]::Absent
        }
        Disconnect-NetScaler -Verbose:$false -ErrorAction SilentlyContinue
        return $obj
    }
}