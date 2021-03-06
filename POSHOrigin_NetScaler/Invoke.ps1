<#
    This script expects to be passed a psobject with all the needed properties
    in order to invoke 'NetScaler' DSC resources.
#>
[cmdletbinding()]
param(
    [parameter(mandatory)]
    [psobject]$Options,

    [bool]$Direct = $false
)

# Ensure we have a valid 'ensure' property
if ($null -eq $Options.options.Ensure) {
    $Options.Options | Add-Member -MemberType NoteProperty -Name Ensure -Value 'Present' -Force
}

# Get the resource type
$type = $Options.Resource.split(':')[1]

$hash = @{
    Name = $Options.Name
    Ensure = $Options.options.Ensure
    Credential = $Options.Options.Adminuser.Credential
    NetScalerFQDN = $Options.Options.NetScalerFQDN
}

$export = $false
if ($Options.options.ParameterExport) {
    $export = [bool]$Options.options.ParameterExport
}

switch ($type) {
    'LBServer' {
        if ($Direct) {
            $hash.IPAddress = $Options.Options.IPAddress
            $hash.Comments = $Options.Options.Description
            $hash.TrafficDomainId = $Options.Options.TrafficDomainId
            $hash.State = $Options.Options.State
            $hash.ParameterExport = $export
            return $hash
        } else {
            $confName = "$type" + '_' + $Options.Name
            Write-Verbose -Message "Returning configuration function for resource: $confName"
            Configuration $confName {
                Param (
                    [psobject]$ResourceOptions
                )

                Import-DscResource -Name LBServer -ModuleName POSHOrigin_NetScaler

                # Credentials may be specified in line. Test for that
                if ($ResourceOptions.Options.Credential -is [pscredential]) {
                    $cred = $ResourceOptions.Options.Credential
                }

                # Credentials may be listed under secrets. Test for that
                if ($ResourceOptions.options.secrets.Credential) {
                    $cred = $ResourceOptions.options.secrets.Credential.credential
                }

                if (-Not $ResourceOptions.options.State) {
                    $ResourceOptions.options | Add-Member -MemberType NoteProperty -Name State -Value 'ENABLED'
                }

                LBServer $ResourceOptions.Name {
                    Ensure = $ResourceOptions.options.Ensure
                    Name = $ResourceOptions.Name
                    NetScalerFQDN = $ResourceOptions.options.netscalerfqdn
                    Credential = $cred
                    IPAddress = $ResourceOptions.options.IPAddress
                    TrafficDomainId = $ResourceOptions.options.TrafficDomainId
                    Comments = $ResourceOptions.options.comments
                    State = $ResourceOptions.options.State
                    ParameterExport = $export
                }
            }
        }
    }
    'LBVirtualServer' {
        if ($Direct) {
            $hash.IPAddress = $Options.Options.IPAddress
            $hash.Port = $Options.Options.Port
            $hash.LBMethod = $Options.Options.LBMethod
            $hash.Comments = $Options.Options.Description
            $hash.ServiceGroup = $Options.Options.ServiceGroup
            $hash.Service = $Options.Options.Service
            $hash.State = $Options.Options.State
            $hash.ParameterExport = $export
            return $hash
        } else {
            $confName = "$type" + '_' + $Options.Name
            Write-Verbose -Message "Returning configuration function for resource: $confName"
            Configuration $confName {
                Param (
                    [psobject]$ResourceOptions
                )

                Import-DscResource -Name LBVirtualServer -ModuleName POSHOrigin_NetScaler

                # Credentials may be specified in line. Test for that
                if ($ResourceOptions.Options.Credential -is [pscredential]) {
                    $cred = $ResourceOptions.Options.Credential
                }

                # Credentials may be listed under secrets. Test for that
                if ($ResourceOptions.options.secrets.Credential) {
                    $cred = $ResourceOptions.options.secrets.Credential.credential
                }

                if (-Not $ResourceOptions.options.State) {
                    $ResourceOptions.options | Add-Member -MemberType NoteProperty -Name State -Value 'ENABLED'
                }

                LBVirtualServer $ResourceOptions.Name {
                    Ensure = $ResourceOptions.options.Ensure
                    Name = $ResourceOptions.Name
                    NetScalerFQDN = $ResourceOptions.options.netscalerfqdn
                    Credential = $cred
                    IPAddress = $ResourceOptions.options.IPAddress
                    Port = $ResourceOptions.options.Port
                    ServiceType = $ResourceOptions.options.servicetype
                    LBMethod = $ResourceOptions.options.lbmethod
                    ServiceGroup = $ResourceOptions.options.servicegroup
                    Service = $ResourceOptions.options.service
                    Comments = $ResourceOptions.options.comments
                    State = $ResourceOptions.options.State
                    ParameterExport = $export
                }
            }
        }
    }
}