$script:LogPath = "$env:SystemDrive\adforest_install.log"
$script:TranscriptPath = "$env:SystemDrive\transcript.log"

[System.Environment]::SetEnvironmentVariable("LogPath", $script:LogPath, [System.EnvironmentVariableTarget]::Machine)

$script:FinishSecureADForestTask = "FinishSecureADForest"
$script:InstallSecureADForestTask = "InstallSecureADForest"

$script:RemoteForestPasswordFilePath = "$env:ALLUSERSPROFILE\Microsoft\RFPassword.txt" 
$script:LocalForestPasswordFilePath = "$env:ALLUSERSPROFILE\Microsoft\LFPassword.txt"
$script:SafeModeAdminPasswordFilePath = "$env:ALLUSERSPROFILE\Microsoft\ADPassword.txt"

$script:ConfigFilePath = "$PSScriptRoot\config.json"
$script:MSSFilePath = "$PSScriptRoot\sceregvl.inf"

$script:BaseGPOBundle = "$PSScriptRoot\BaseGPOBundle.zip"
$script:ForestGPLinks = "$PSScriptRoot\Forest_GPLinks.json"
$script:OUStructure = "$PSScriptRoot\Forest_OU.json"
$script:AdditionalGPOs = "$PSScriptRoot\Forest_AdditionalGPOBundle.zip"
$script:AdditionalGPLinks = "$PSScriptRoot\Forest_AdditionalGPLinks.json"
$script:ForestLocalGroups = "$PSScriptRoot\Forest_LocalGroups.json"
$script:BaseAdmxBundle = "$PSScriptRoot\BaseAdmxBundle.zip"
$script:AddOnAdmxBundle = "$PSScriptRoot\AddOnAdmxBundle.zip"
$script:SysvolFiles = [System.IO.Path]::Combine($PSScriptRoot, "SysvolFiles.zip")

$script:ESAEOUConfigFilePath = "$PSScriptRoot\ESAE_OU.json"
$script:ESAELocalGroups = "$PSScriptRoot\ESAE_LocalGroups.json" #Not really needed, the script will use the default groups and name them appropriately
$script:ESAERemoteGroups = "$PSScriptRoot\ESAE_RemoteManagementGroups.json"
$script:ESAEGPLinks = "$PSScriptRoot\ESAE_GPLinks.json"

#region Base Commands

Function New-SecureADForest {
		<#
		.SYNOPSIS	
			The cmdlet builds a new AD forest with a single domain on a single server, creates standard user groups and OUs, imports pre-configured GPOs with the DISA STIGs, and runs AD and DNS STIGs.

		.DESCRIPTION
			The cmdlet renames the computer, if desired, sets the local administrator password, and then installs Active Directory with a new forest and domain. It sets up an AD site, and then sets up some AD
			infrastructure from configuration files or uses a default setup to include an OU structure, security groups, and user accounts. DISA STIG GPOs are imported and linked to OUs based on a configuration
			file. If this forest is designated as an Enhanced Security Administrative Environment (ESAE), it sets up conditional forwarders on the DC and the remote forest if specified, and then builds a one way
			forest trust. The AD recycle bin is enabled, the Group Policy Central Store is setup, and the MSS GPO settings are imported to be available to use.

			This cmdlet takes the parameter input and creates a config file that is used by later steps that are enacted through scheduled tasks. All passwords are temporarily stored on the file system encrypted
			with SYSTEM credentials and deleted. 

			This cmdlet specifically creates the config file from the parameter and saves it, renames the computer, sets the administrator password, and saves the encrypted passwords that are used later. Then, 
			if a reboot is required due to renaming the computer, it creates a scheduled task to run Install-SecureADForest, otherwise the next cmdlet is run directly without a reboot. 

		.PARAMETER ForestRootDomainName
			The name of the forest and root domain.

		.PARAMETER ComputerName
			The new name the domain controller should have.

		.PARAMETER AdminPassword
			The new password for the local administrator account.

		.PARAMETER BaseNTDSPath
			The root location to place the NTDS.dit, SYSVOL, and logs file folders. Useful if the Active Directory files contents are being placed on a separate drive from the OS. This defaults to c:\NTDS.

		.PARAMETER FunctionalLevel
			The functional level of the forest and root domain. This defaults to 6.

			-- Windows Server 2003    : 2 
            -- Windows Server 2008    : 3 
            -- Windows Server 2008 R2 : 4 
            -- Windows Server 2012    : 5 
            -- Windows Server 2012 R2 : 6 
			-- Windows Server 2016    : 7

		.PARAMETER SiteName
			The name of the AD site the new domain controller will be a part of. The defaults to Default-First-Site-Name.

		.PARAMETER SiteSubnets
			The subnet blocks that will be added to the site. These should be in the format of X.X.X.X/CIDR.

		.PARAMETER SafeModePassword
			The DSRM password. This will default to the AdminPassword if it is specified, or will prompt for input if it is not.

		.PARAMETER LogPath
			The path progress logs are written to. This defaults to $env:SystemDrive\adforest_install.log.

		.PARAMETER OUConfigFilePath
			The file containing the OU setup configuration. If no file is specified, a default OU structure is implemented.

		.PARAMETER ForestGroupsConfigFilePath
			The file containing the security group configuration for the groups that are used to manage the forest. If no file is specified, a default set of administrative groups are deployed. The groups are added
			to existing built in groups, like Domain Admins, so that well-known SID groups are not utilized for the membership of user accounts.

			If a custom OU structure is specified, this configuration must be specified so that the groups are created in OUs that actually exist.

		.PARAMETER IsESAEForest
			Specify that this forest will be an ESAE forest. This option prompts additional available dynamic parameters needed to configure the ESAE forest and forest trust.

		.PARAMETER GPOBundleFilePath
			The path to the default set of GPOs that include the DISA STIGs. This defaults to $PSScriptRoot\BaseGPOBundle.zip. The default bundle of GPOs utilize WMI filters that are also imported.

		.PARAMETER GPLinksFilePath
			The path to the configuration file that maps the imported base GPOs specified in GPOBundleFilePath to OUs. This will default to "$PSScriptRoot\Forest_GPLinks.json" for a standalone forest install and
			default to "$PSScriptRoot\ESAE_GPLinks.json" for an ESAE installation.
	
		.PARAMETER AdditonalGPOsFilePath
			The path to a zip file containing any additional GPOs that should be imported. This is useful so that the base GPO bundle can contain just the STIG GPOs, and this can contain environment specific
			GPOs. If no file is specified, no additional GPOs are imported.
	
		.PARAMETER AdditionalGPLinksFilePath
			The path to the configuration file that maps the imported additional GPOs specified in AdditionalGPOsFilePath to OUs.

		.PARAMETER BaseAdmxBundleFilePath
			The path to the zip file with the ADMX and ADML files that will be added to the central policy store. This defaults to "$PSScriptRoot\BaseAdmxBundle.zip". To use the local PolicyDefinitions folder, set this parameter as an empty string.
	
		.PARAMETER AddOnAdmxBundleFilePath
			The path to the zip file with additional ADMX and ADML files. This is useful so that the base bundle can remain unchanged and the add-on can be environment specific.

		.PARAMETER SysvolFilesPath
			The path to the zip containing files and folders that will be extracted to the SYSVOL into a folder named "files". This defaults to "$PSScriptRoot\Sysvolfiles.zip".

		.PARAMETER UsersFilePath
			The path to the configuration file that specifies users to be created and their group membership. This defaults to none.
	
		.PARAMETER AdditionalSitesConfigFilePath
			The path to the configuration file that specifies additional AD sites and subnets to be created.

		.PARAMETER RemoteForestCredential
			The credentials to use to connect to the remote forest during an ESAE installation to create the conditional forwarder pointing to the ESAE forest and setup the forest trust.

		.PARAMETER RemoteForest
			The DNS name of the remote forest during an ESAE installation.

		.PARAMETER LocalForest
			The DNS name of the local forest being setup for ESAE. This is only required if the forest being setup is different than the local forest the cmdlet is running on. Typically this is not required.

		.PARAMETER LocalForestCredential
			Specifies the credentials to use on the local forest to set up the forest trust for an ESAE forest. This is only needed if the specific credentials are needed in the local forest, typically not required.
	
		.PARAMETER ConfigFilePath
			The path to the configuration file containing all of the required parameters to execute the cmdlet. This can be used to help programatically execute the cmdlet repeatedly, but this cmdlet will still
			need to have the AdminPassword, SafeModePassword, or both specified directly. They can be stored as secure strings in the config file, but that is not really secure. 

		.PARAMETER CreateRemoteConditionalForwarder
			Specify that a conditional forwarder to the new ESAE forest should be created in the remote forest. Requires RemoteForestCredential is specified.

		.PARAMETER CreateLocalConditionalForwarder
			Specify that a conditional forwarder to the remote forest should be created in the new ESAE forest. This needs to be specified unless an external DNS solution is utilized to resolve the remote forest.

		.PARAMETER RemoteForestMasterServers
			The remote DNS servers that will be used to create the local conditional forwarder in the new ESAE forest.

		.PARAMETER ManagementGroupsConfigFilePath
			The path to the configuration file that specifies groups to be created that will be used to manage remote forests and domains from the new ESAE forest.

		.INPUTS
			System.String
			This represents the configuration file path.

		.OUTPUTS
			None

		.EXAMPLE
			New-SecureADForest -ForestRootDomainName "admin.local" `
								-ComputerName "AdminDC" `
								-BaseNTDSPath "n:\NTDS" `
								-SiteName "Site1" `
								-SiteSubnets @("192.168.1.0/24") `
								-GPOBundleFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\BaseGPOBundle.zip" `
								-GPLinksFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_GPLinks.json" `
								-OUConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_OU.json" `
								-ManagementGroupsConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_RemoteManagementGroups.json" `
								-ForestGroupsConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_LocalGroups.json" `
								-UsersFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\users.json" `
								-SysvolFilesPath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_Sysvolfiles.zip" `
								-IsESAEForest `
								-RemoteForest "contoso.com" `
								-RemoteForestMasterServers @("192.168.2.1") `
								-CreateLocalConditionalForwarder `
								-RemoteForestCredential (Get-Credential) `
								-CreateRemoteConditionalForwarder `
								-AdditionalGPOsFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_AdditionalGPOBundle.zip" `
								-AdditionalGPLinksFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_AdditionalGPLinks.json" `
								-BaseAdmxBundleFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\BaseAdmxBundle.zip" `
								-AddOnAdmxBundleFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\AddOnAdmxBundle.zip"

			Builds a new ESAE forest including the defined OU structure, remote forest management groups, specified users, and DNS settings to administer the contoso.com forest from the new admin.local forest.

			The default security groups for managing the ESAE forest are used. The OU.json file uses an OU structure compatible with the specified security group creation locations.

		.EXAMPLE
			New-SecureADForest -ForestRootDomainName "admin.local" `
								-ComputerName "AdminDC" `
								-BaseNTDSPath "n:\NTDS" `
								-SiteName "Site1" `
								-SiteSubnets @("192.168.1.0/24") `
								-ManagementGroupsConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_RemoteManagementGroups.json" `
								-UsersFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\users.json" `
								-IsESAEForest `
								-RemoteForest "contoso.com" `
								-RemoteForestMasterServers @("192.168.2.1") `
								-CreateLocalConditionalForwarder `
								-RemoteForestCredential (Get-Credential) `
								-CreateRemoteConditionalForwarder `
								-AdditionalGPOsFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_AdditionalGPOBundle.zip" `
								-AdditionalGPLinksFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_AdditionalGPLinks.json" `
								-AddOnAdmxBundleFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\AddOnAdmxBundle.zip"

			Builds a new ESAE forest including the defined OU structure, remote forest management groups, specified users, and DNS settings to administer the contoso.com forest from the new admin.local forest.

			The default security groups for managing the ESAE forest are used, as well as the default OU structure. The defaults for the base GPO Bundle, the base Admx Bundle, and the GP Links are used as well.

		.EXAMPLE
			New-SecureADForest -ForestRootDomainName "admin.local" `
								-ComputerName "AdminDC" `
								-BaseNTDSPath "n:\NTDS" `
								-SiteName "Site1" `
								-SiteSubnets @("192.168.1.0/24") `
								-OUConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\Forest_OU.json" `
								-ForestGroupsConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\Forest_LocalGroups.json" `
								-UsersFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\users.json" `
								-AdditionalGPOsFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\Forest_AdditionalGPOBundle.zip" `
								-AdditionalGPLinksFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\Forest_AdditionalGPLinks.json" 

			Builds a new standalone secure forest including the defined OU structure, and specified users.

		.EXAMPLE
			New-SecureADForest -ForestRootDomainName "admin.local"

			This represents the minimum configuration to deploy a new forest called admin.local. All of the default OU and group settings are used. No users are created and no additional GPOs or ADMX files are imported. The default Sysvol files
			are extracted. No AD Site information is updated. The base GPO bundle and associated links are used. 

		.NOTES
			The remote forest credentials should have Enterprise Admin permissions in the remote forest.
	#>
    [CmdletBinding(DefaultParameterSetName="File")]
	Param(
        [Parameter(Mandatory=$true, ParameterSetName="Parameters")]
        [System.String]$ForestRootDomainName,

        [Parameter(ParameterSetName="Parameters")]
        [System.String]$ComputerName,

        [Parameter()]
        [SecureString]$AdminPassword,

        [Parameter(ParameterSetName="Parameters")]
        [System.String]$BaseNTDSPath = "c:\NTDS",

		[Parameter(ParameterSetName="Parameters")]
		[ValidateRange(2,7)]
		[int]$FunctionalLevel = 6,

        [Parameter(ParameterSetName="Parameters")]
        [System.String]$SiteName = "Default-First-Site-Name",

        [Parameter(ParameterSetName="Parameters")]
        [System.String[]]$SiteSubnets = @(),

        [Parameter()]
        [SecureString]$SafeModePassword,

        [Parameter(ParameterSetName="Parameters")]
        [System.String]$LogPath = $script:LogPath,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$OUConfigFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$ForestGroupsConfigFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$IsESAEForest,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$GPOBundleFilePath = $script:BaseGPOBundle,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]	
		[System.String]$GPLinksFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]	
		[System.String]$AdditionalGPOsFilePath,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]		
		[System.String]$AdditionalGPLinksFilePath,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$BaseAdmxBundleFilePath = $script:BaseAdmxBundle,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$AddOnAdmxBundleFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$UsersFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$AdditionalSitesConfigFilePath = [System.String]::Empty,
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$SysvolFilesPath = $script:SysvolFiles,

		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="File")]
		[ValidateScript({Test-Path -Path $_})]	
		[System.String]$ConfigFilePath = $script:ConfigFilePath
    )
	DynamicParam
    {
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

		$ValidateScript = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute([System.Management.Automation.ScriptBlock]::Create("if (![System.String]::IsNullOrEmpty(`$_)) { Test-Path -Path `$_ } else { return `$true }"))

        if ($IsESAEForest) {

            [System.Management.Automation.ParameterAttribute]$Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $Attributes.ParameterSetName = "Parameters"
            
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $AttributeCollection.Add($Attributes)

            #region RemoteForestCredential
			
			$Temp = $AttributeCollection.Remove($Attributes)
			$Attributes.Mandatory = $true
			$AttributeCollection.Add($Attributes)

            [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("RemoteForestCredential", [PSCredential], $AttributeCollection)
            $ParamDictionary.Add("RemoteForestCredential", $DynParam)
			
			$Temp = $AttributeCollection.Remove($Attributes) 
			$Attributes.Mandatory = $false
			$AttributeCollection.Add($Attributes)

            #endregion

            #region RemoteForest

            [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("RemoteForest", [System.String], $AttributeCollection)
            $ParamDictionary.Add("RemoteForest", $DynParam)

            #endregion

            #region RemoteForest

            [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("LocalForest", [System.String], $AttributeCollection)
            $ParamDictionary.Add("LocalForest", $DynParam)

            #endregion

            #region LocalForestCredential
     
            [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("LocalForestCredential", [PSCredential], $AttributeCollection)
            $ParamDictionary.Add("LocalForestCredential", $DynParam)

            #endregion

            #region ESAE Stub Zones

            [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("CreateRemoteConditionalForwarder", [switch], $AttributeCollection)
            $ParamDictionary.Add("CreateRemoteConditionalForwarder", $DynParam)

            [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("CreateLocalConditionalForwarder", [switch], $AttributeCollection)
            $ParamDictionary.Add("CreateLocalConditionalForwarder", $DynParam)

			[System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("RemoteForestMasterServers", [System.String[]], $AttributeCollection)
            $ParamDictionary.Add("RemoteForestMasterServers", $DynParam)

            #endregion

			#region Remote Forest Management Groups
			
			$AttributeCollection.Add($ValidateScript)
            
			[System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("ManagementGroupsConfigFilePath", [System.String], $AttributeCollection)
            $ParamDictionary.Add("ManagementGroupsConfigFilePath", $DynParam)
			
			$Temp = $AttributeCollection.Remove($ValidateScript)

            #endregion
        }

        return $ParamDictionary  
    }

    Begin {
		Enable-TaskSchedulerHistory 	
    }

    Process {
		$PsBoundParameters.GetEnumerator() | ForEach-Object { 
            New-Variable -Name $_.Key -Value $_.Value -ErrorAction SilentlyContinue
        }
		
		switch ($PSCmdlet.ParameterSetName) {
			"Parameters" {

				if ([System.String]::IsNullOrEmpty($LogPath)) {
					$LogPath = $script:LogPath
				}

				$ParametersNotToSave = @("AdminPassword","SafeModePassword","ConfigFilePath","RemoteForestCredential","LocalForestCredential")
				$CommandName = $PSCmdlet.MyInvocation.InvocationName
				$ParameterList = @{}
         
				(Get-Command -Name $CommandName).Parameters.GetEnumerator() | Select-Object -ExpandProperty Key | Where-Object {$_ -notin $ParametersNotToSave} | ForEach-Object {
					$Temp = Get-Variable -Name $_ -ErrorAction SilentlyContinue 

					if ($Temp -ne $null -and $Temp.Name -ne $null) {

						if ($Temp.Value.GetType() -eq [System.Management.Automation.SwitchParameter]) {
							$ParameterList.Add($Temp.Name, [System.Boolean]::Parse($Temp.Value.ToString()))
						}
						else {
							$ParameterList.Add($Temp.Name,$Temp.Value)
						}
					}
				}

				$PsBoundParameters.GetEnumerator() | Where-Object {$_.Key -notin $ParametersNotToSave } | ForEach-Object {
					if ($_ -ne $null -and $_.Key -ne $null) {
						if (!@($ParameterList.Keys).Contains($_.Key)) {
							if ($_.Value.GetType() -eq [System.Management.Automation.SwitchParameter]) {
								$ParameterList.Add($_.Key, [System.Boolean]::Parse($_.Value.ToString()))
							}
							else {
								$ParameterList.Add($_.Key, $_.Value)	
							}					
						}
					}
				}

				if ($IsESAEForest) {
					$RemoteForestCredential = $PSBoundParameters.RemoteForestCredential
					$LocalForestCredential = $PSBoundParameters.LocalForestCredential

					$ParameterList.Add("RemoteForestUserName", $RemoteForestCredential.UserName)
					$ParameterList.Add("RemoteForestPasswordFilePath", $script:RemoteForestPasswordFilePath)

					if ($LocalForestCredential -ne $null -and $LocalForestCredential -ne [PSCredential]::Empty) {
						$ParameterList.Add("LocalForestUserName", $LocalForestCredential.UserName)
						$ParameterList.Add("LocalForestPasswordFilePath", $script:LocalForestPasswordFilePath)
					}
					else {
						$ParameterList.Add("LocalForestPasswordFilePath", "")
						$ParameterList.Add("LocalForestUserName", "")
					}
				}

				$Config = New-ConfigurationFile -ParameterList $ParameterList
				$Parameters = ConvertFrom-Json -InputObject $Config.Content
				
				break
			}
			"File" {
				$Config = New-ConfigurationFile -SourceFilePath $ConfigFilePath
				$Parameters = ConvertFrom-Json -InputObject $Config.Content

				if ([System.String]::IsNullOrEmpty($Parameters.ForestRootDomainName)) {
					throw "Configuration file missing required parameter ForestRootDomainName."
				}

				if ([System.String]::IsNullOrEmpty($Parameters.LogPath)) {
					$Parameters.LogPath = $script:LogPath
				}

				if ([System.String]::IsNullOrEmpty($Parameters.FunctionalLevel)) {
					$Parameters.FunctionalLevel = 6
				}

				if ([System.String]::IsNullOrEmpty($Parameters.BaseAdmxBundleFilePath)) {
					$Parameters.BaseAdmxBundleFilePath = $script:BaseAdmxBundle
				}

				break
			}
			default {
				throw "Could not determine the parameter set for New-SecureADForest"
			}
		}

		[System.Environment]::SetEnvironmentVariable("NewADForestLogPath", $Parameters.LogPath, [System.EnvironmentVariableTarget]::Machine)
	
        [bool]$Success = $true

		if ($SafeModePassword -eq $null -and $AdminPassword -eq $null) {
			$VerifyPassword = $null
			while(($SafeModePassword -eq $null -or $VerifyPassword -eq $null) -or ($SafeModePassword -ne $VerifyPassword)) {
				$SafeModePassword = Read-Host -AsSecureString -Prompt "Enter the DSRM safe mode password"
				$VerifyPassword = Read-Host -AsSecureString -Prompt "Verify the DSRM safe mode password"
			}
		}

		if ($SafeModePassword -eq $null -and $AdminPassword -ne $null) {
			$SafeModePassword = $AdminPassword
		}

		if (![System.String]::IsNullOrEmpty($Parameters.UsersFilePath)) {
			if (!(Test-Path -Path $Parameters.UsersFilePath)) {
				Write-Warning "The file specified for the user import, $($Parameters.UsersFilePath), could not be found."
				Write-Log "The file specified for the user import, $($Parameters.UsersFilePath), could not be found." 
				throw [System.IO.FileNotFoundException]("The file specified for the user import, $($Parameters.UsersFilePath), could not be found." )
			}
		}

		if (![System.String]::IsNullOrEmpty($Parameters.ForestGroupsConfigFilePath)) {
			if (!(Test-Path -Path $Parameters.ForestGroupsConfigFilePath)) {
				Write-Warning "The file specified for the forest groups, $($Parameters.ForestGroupsConfigFilePath), could not be found."
				Write-Log "The file specified for the forest groups, $($Parameters.ForestGroupsConfigFilePath), could not be found."
				throw [System.IO.FileNotFoundException]("The file specified for the forest groups, $($Parameters.ForestGroupsConfigFilePath), could not be found.")
			}
		}

		if (![System.String]::IsNullOrEmpty($Parameters.OUConfigFilePath)) {
			if(!(Test-Path -Path $Parameters.OUConfigFilePath)) {
				Write-Warning "The file specified for the OU configuration, $($Parameters.OUConfigFilePath), could not be found."
				Write-Log "The file specified for the OU configuration, $($Parameters.OUConfigFilePath), could not be found."
				throw [System.IO.FileNotFoundException]("The file specified for the OU configuration, $($Parameters.OUConfigFilePath), could not be found.")
			}
		}

        try
        {
            Write-Log "Adding ADDS windows feature."
            Add-ADDSWindowsFeature -IncludeManagementTools

            try
            {
				if ($AdminPassword -ne $null) {
					Write-Log "Setting local admin password and enabling the account if disabled."
					Set-LocalAdminPassword -AdminPassword $AdminPassword -EnableAccount
				}
				else {
					Write-Log "No new password specified, skipping."
				}
                
                try 
                {
					$RebootRequired = $false

					if (![System.String]::IsNullOrEmpty($Parameters.ComputerName)) {
						Write-Log "Renaming computer to $($Parameters.ComputerName)."
						Rename-LocalComputer -ComputerName $Parameters.ComputerName -ErrorAction SilentlyContinue
						$RebootRequired = $true
					}
					else {
						Write-Log "No computer name provided, not renaming."
					}

					if ($Parameters.IsESAEForest) {
						Write-Log "This is an ESAE Forest installation."
						try
						{
							Write-Log "Saving encrypted remote forest password."
							$Temp = New-SaveEncryptedPasswordTask -Password ($RemoteForestCredential.Password) -FilePath $script:RemoteForestPasswordFilePath
							Write-Log "Remote forest password saved at $Temp."
						}
						catch [Exception] {
							Write-Log $_
							$Success = $false
						}
						
						if ($LocalForestCredential -ne $null -and $LocalForestCredential -ne [PSCredential]::Empty) {
							try
							{
								Write-Log "Saving encrypted local forest password."
								$Temp = New-SaveEncryptedPasswordTask -Password ($LocalForestCredential.Password) -FilePath $script:LocalForestPasswordFilePath
								Write-Log "Local forest password saved at $Temp."
							}
							catch [Exception] {
								Write-Log $_
								$Success = $false
							}
						}
					}

					if ($RebootRequired) {
						try
						{
							Write-Log "Saving encrypted admin password."
							$Temp = New-SaveEncryptedPasswordTask -Password $SafeModePassword -FilePath $script:SafeModeAdminPasswordFilePath
							Write-Log "Safe mode password saved at $Temp."

							try
							{
								Write-Log "Preparing Install Forest scheduled task."
								New-InstallSecureADForestScheduledTask -ConfigFilePath ($Config.FilePath) -PasswordFilePath $script:SafeModeAdminPasswordFilePath
								Write-Log "Completed building scheduled task."
							}
							catch [Exception] {
								Write-Log $_
								$Success = $false
							}
						}
						catch [Exception] {
							Write-Log $_
							$Success = $false
						}
					}
					else {
						Write-Log "No reboot required, moving to installing the forest."
						Install-SecureADForest -ConfigFilePath $Config.FilePath -SafeModePassword $SafeModePassword
					}            
                }
                catch [Exception] {
					Write-Log $_
					$Success = $false
                }
            }
            catch [Exception] {
				Write-Log $_
				$Success = $false
            }
        }
        catch [Exception] {
			Write-Log $_
			$Success = $false
        } 

		if ($Success -and $RebootRequired) {
            Write-Log "Restarting computer."
            Restart-Computer -Force
        }

        if (!$Success) {
			Write-Log "One of the steps in New-SecureADForest failed."
			$CommandText = Get-CommandText -Command ($PSCmdlet.MyInvocation.MyCommand.Name) -Parameters $PSBoundParameters
			Write-Log "Rerun this command: $CommandText"
        }
    }

    End {        
    }
}

Function Install-SecureADForest {
	<#
		.SYNOPSIS
			This cmdlet launches the installation of a new, secure AD forest.

		.DESCRIPTION
			Active Directory is installed through this cmdlet at a 2012 R2 functional level. 
	
			After the installation is complete, if a configuration file was used to initiate the command, a scheduled task is created that will call Set-ADForestSecurityConfiguration after a reboot. If the restart
			parameter is not specified, the server must manually be rebooted to start the next steps. The New-SecureADForest cmdlet specifies that the server should be rebooted when calling this step.

			If the cmdlet is not launched from the configuration file input, the cmdlet will optionally reboot the machine based in the inputted parameter.

		.PARAMETER ConfigFilePath
			The path to the configuration file with the parameters used to run this cmdlet. This defaults to "$PSScriptRoot\config.json".

		.PARAMETER SafeModePassword
			The password to use with DSRM.

		.PARAMETER BaseNTDSPath
			The root folder to put the appropriate Active Directory database, log, and sysvol folders and files. This is useful when those files are stored on a drive different than the OS.

		.PARAMETER ForestRootDomainName
			The DNS name of the new forest.

		.PARAMETER Restart
			Specify whether to automatically restart the server after Active Directory is installed.

		.PARAMETER FunctionalLevel
			The functional level of the forest and root domain. This defaults to 6.

			-- Windows Server 2003    : 2 
            -- Windows Server 2008    : 3 
            -- Windows Server 2008 R2 : 4 
            -- Windows Server 2012    : 5 
            -- Windows Server 2012 R2 : 6 

		.INPUTS
			None
		
		.OUTPUTS
			None

		.EXAMPLE
			Install-SecureADForest -ConfigFilePath "$PSScriptRoot\config.json" -Restart

			Installs Active Directory based on the config file path and automatically reboots the server after the installation. A scheduled task is created to run the follow on security hardening and configuration
			steps after the reboot is complete.

		.EXAMPLE
			Install-SecureADForest -BaseNTDSPath "n:\NTDS" -ForestRootDomainName "admin.local" -Restart -FunctionalLevel 6 -SafeModePassword (ConvertTo-SecureString -String "P@$$w0rd" -AsPlainText -Force)

			Installs Active Directory to n:\NTDS in a forest named admin.local with a Server 2012 R2 functional level. The server is automatically rebooted after installation.
		
		.NOTES
			None
	#>
	[CmdletBinding(DefaultParameterSetName="File")]
    Param (
        [Parameter(ParameterSetName="File")]
		[ValidateScript({Test-Path -Path $_})]	
        [System.String]$ConfigFilePath = $script:ConfigFilePath,

		[Parameter(Mandatory=$true)]
		[SecureString]$SafeModePassword,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$BaseNTDSPath = "c:\NTDS",

		[Parameter(Mandatory=$true, ParameterSetName="Parameters")]
		[System.String]$ForestRootDomainName,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$Restart = $false,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateRange(2,7)]
		[int]$FunctionalLevel = 6
    )

    Begin {		
    }

    Process {
		switch ($PSCmdlet.ParameterSetName) {
			"File" {
				Write-Log "Getting configuration file information."
				$Parameters = ConvertFrom-Json -InputObject (Get-Content -Path $ConfigFilePath -Raw)

				if (!([System.String]::IsNullOrEmpty($Parameters.ForestRootDomainName))) {
					$ForestRootDomainName = $Parameters.ForestRootDomainName
				}
				else {
					Write-Log "Forest root domain name is null or empty."
					throw [System.ArgumentNullException]("Forest root domain name is null or empty")
				}
				
				if (![System.String]::IsNullOrEmpty($Parameters.BaseNTDSPath)) {
					$BaseNTDSPath = $Parameters.BaseNTDSPath
				}

				if(![System.String]::IsNullOrEmpty($Parameters.FunctionalLevel)) {
					$FunctionalLevel = $Parameters.FunctionalLevel
				}

				break
			}
			"Parameters" {

				break
			}
		}

        [bool]$Success = $false

        Write-Log "Checking for Install AD Forest Scheduled Task."

        if ((Get-ScheduledTask -TaskName $script:InstallSecureADForestTask -ErrorAction SilentlyContinue) -ne $null) {
			Write-Log "Removing Install AD Forest Scheduled Task."
            Unregister-ScheduledTask -TaskName $script:InstallSecureADForestTask -Confirm:$false
        }

		$Netbios = $ForestRootDomainName.Substring(0,[System.Math]::Min($ForestRootDomainName.IndexOf("."), 15))

        <#
            -- Windows Server 2003    : 2 or Win2003
            -- Windows Server 2008    : 3 or Win2008
            -- Windows Server 2008 R2 : 4 or Win2008R2
            -- Windows Server 2012    : 5 or Win2012
            -- Windows Server 2012 R2 : 6 or Win2012R2
			-- Windows Server 2016	  : 7 or Win2016
        #>

        try
        {
            Write-Log "Installing AD Forest."

            Install-ADDSForest `
                -CreateDnsDelegation:$false `
                -DatabasePath "$BaseNTDSPath\Database" `
                -DomainMode 6 `
                -DomainName $ForestRootDomainName `
                -DomainNetbiosName $Netbios `
                -ForestMode 6 `
                -InstallDns:$true `
                -LogPath "$BaseNTDSPath\Logs" `
                -NoRebootOnCompletion:$true `
                -SysvolPath "$BaseNTDSPath\SYSVOL" `
                -Force:$true `
                -SafeModeAdministratorPassword $SafeModePassword


			if ($PSCmdlet.ParameterSetName -eq "File") {
				Write-Log "Preparing finish AD Forest installation scheduled task."
				New-FinishSecureADForestInstallationScheduledTask -ConfigFilePath $ConfigFilePath
				Write-Log "Completed building the scheduled task."
			}

            $Success = $true
        }
        catch [Exception] 
        {
            Write-Log $_
        }

		if ($Success) {
			Write-Log "Installation completed successfully."
			if (($PSCmdlet.ParameterSetName -eq "Parameters" -and $Restart) -or ($PSCmdlet.ParameterSetName -eq "File")) {
				Write-Log "Restarting computer."
				Restart-Computer -Force
			}
			else {
				Write-Log "Restart automatically not selected. The server needs to be rebooted to finish the installation."
			}
        }
        else {
            Write-Log "One of the steps in Install-SecureADForest failed."
			$CommandText = Get-CommandText -Command ($PSCmdlet.MyInvocation.MyCommand.Name) -Parameters $PSBoundParameters
			Write-Log "Rerun this command: $CommandText"
        }
    }   

    End {        
    }
}

Function Set-ADForestSecurityConfiguration {
	<#
		.SYNOPSIS
			This cmdlet completes the installation of Active Directory and sets default configurations and implements security hardening.

		.DESCRIPTION
			This cmdlet renames the default site to the specified name, adds the specified subnets to the site, creates any additional specified sites, installs the KDS root key with an immediate effective time,
			enables the AD recycle bin, adds the MSS GPO settings, creates the specified OU structure, and creates groups to manage the new forest.

			If this is an ESAE forest, additional groups are also created for managing remote forests, if specified.

			Then the central policy store is created and the ADMX bundle zip is imported to it, the Active Directory STIG items that cannot be applied through GPOs are run (requires the ActiveDirectoryStig module),
			the DNS STIG items are applied (requires the DnsStig module), extracts and config files used for STIG implementation like Java or Mozilla or other config files like custom lockscreen backgrounds to the sysvol,
			creates a standard set of WMI filters for GPOs (requires the ActiveDirectoryTools module), imports the base GPO bundle, links those GPOs to the OUs specified in the GP Links configuration file, imports
			any additional GPOs specified and links those, then finally creates Fine Grained Password policies that comply with the DISA STIG requirements (one is set as the default and another is created with the
			same settings called FGP_STIG and is applied to Domain Users.
			
		.PARAMETER ConfigFilePath
			The path to the configuration file with the parameters used to run this cmdlet. This defaults to "$PSScriptRoot\config.json".
	
		.PARAMETER SiteName
			The new name of the Default First Site.

		.PARAMETER SiteSubnets
			The subnets to add to the default site.

		.PARAMETERS OUConfigFilePath
			The path to the configuration file for the OU structure to be deployed in the new forest root domain. This defaults to a standard OU structure depending on whether the deployment is for an ESAE environment or not.

		.PARAMETER ForestGroupsConfigFilePath
			The path to the configuration file for the security groups to be created that will be utilized to manage the new forest. The defaults to a standard set of groups.

		.PARAMETER GPOBundleFilePath
			The path to the zip file containing the base GPOs. This defaults to "$PSScriptRoot\BaseGPOBundle.zip".

		.PARAMETER GPLinksFilePath
			The path to the configuration file that maps the imported base GPOs specified in GPOBundleFilePath to OUs. This will default to "$PSScriptRoot\Forest_GPLinks.json" for a standalone forest install and
			default to "$PSScriptRoot\ESAE_GPLinks.json" for an ESAE installation.

		.PARAMETER AdditonalGPOsFilePath
			The path to a zip file containing any additional GPOs that should be imported. This is useful so that the base GPO bundle can contain just the STIG GPOs, and this can contain environment specific
			GPOs. If no file is specified, no additional GPOs are imported.
	
		.PARAMETER AdditionalGPLinksFilePath
			The path to the configuration file that maps the imported additional GPOs specified in AdditionalGPOsFilePath to OUs.

		.PARAMETER BaseAdmxBundleFilePath
			The path to the zip file with the ADMX and ADML files that will be added to the central policy store. This defaults to "$PSScriptRoot\BaseAdmxBundle.zip". To use the local PolicyDefinitions folder, set this parameter as an empty string.
	
		.PARAMETER AddOnAdmxBundleFilePath
			The path to the zip file with additional ADMX and ADML files. This is useful so that the base bundle can remain unchanged and the add-on can be environment specific.

		.PARAMETER IsESAEForest
			Specify that this forest will be an ESAE forest. This option prompts additional available dynamic parameters needed to configure the ESAE forest and forest trust.

		.PARAMETER UsersFilePath
			The path to the configuration file that specifies users to be created and their group membership. This defaults to none.

		.PARAMETER AdditionalSitesConfigFilePath
			The path to the configuration file that specifies additional AD sites and subnets to be created.

		.PARAMETER ManagementGroupsConfigFilePath
			The path to the configuration file that specifies groups to be created that will be used to manage remote forests and domains from the new ESAE forest.

		.PARAMETER SysvolFilesPath
			The path to the zip containing files and folders that will be extracted to the SYSVOL into a folder named "files". This defaults to "$PSScriptRoot\Sysvolfiles.zip".
		
		.INPUTS
			None
		
		.OUTPUTS
			None

		.EXAMPLE
			Set-ADForestSecurityConfiguration -SiteName "Site1" `
											-SiteSubnets @("192.168.1.0/24") `
											-OUConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_OU.json" `
											-UsersFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\users.json" `
											-IsESAEForest `
											-AdditionalGPOsFilePath "$env:SystemRoot\windowspowershell\v1.0\modules\ESAE\ESAE_AdditionalGPOBundle.zip" `
											-AdditionalGPLinksFilePath "$env:SystemRoot\windowspowershell\v1.0\ESAE\modules\ESAE_AdditionalGPLinks.json" ` 
											-ManagementGroupsConfigFilePath "$env:SystemRoot\windowspowershell\v1.0\ESAE\modules\ESAE_RemoteManagementGroups.json" `

			Runs the security configuration with the specified parameters. This uses the default for the groups used to manage the ESAE forest.

		.NOTES
			None
	#>
	[CmdletBinding(DefaultParameterSetName="File")]
    Param (
		[Parameter(ParameterSetName="File")]
		[ValidateScript({Test-Path -Path $_})]	
		[System.String]$ConfigFilePath = $script:ConfigFilePath,

        [Parameter(ParameterSetName="Parameters")]
        [System.String]$SiteName = "Default-First-Site-Name",

        [Parameter(ParameterSetName="Parameters")]
        [System.String[]]$SiteSubnets = @(),

		[Parameter(ParameterSetName="Parameters")]	
		[System.String]$OUConfigFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$ForestGroupsConfigFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]		
		[System.String]$GPOBundleFilePath = $script:BaseGPOBundle,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]		
		[System.String]$GPLinksFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]	
		[System.String]$AdditionalGPLinksFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$AdditionalGPOsFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$BaseAdmxBundleFilePath = $script:BaseAdmxBundle,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$AddOnAdmxBundleFilePath = [System.String]::Empty,

		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$SysvolFilesPath = $script:SysvolFiles,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$IsESAEForest,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateScript({
			if (![System.String]::IsNullOrEmpty($_)) {
				Test-Path -Path $_
			}
			else {
				return $true
			}
		})]
		[System.String]$AdditionalSitesConfigFilePath = [System.String]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[System.String]$UsersFilePath = [System.String]::Empty
    )
	DynamicParam
    {
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        if ($IsESAEForest) {

            [System.Management.Automation.ParameterAttribute]$Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $Attributes.ParameterSetName = "Parameters"

            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $AttributeCollection.Add($Attributes)

            [System.Management.Automation.RuntimeDefinedParameter]$DynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter("ManagementGroupsConfigFilePath", [System.String], $AttributeCollection)
            $ParamDictionary.Add("ManagementGroupsConfigFilePath", $DynParam)
        }

        return $ParamDictionary  
    }

    Begin {
    }

	Process 
    {
		switch ($PSCmdlet.ParameterSetName) {
			"File" {
				Write-Log "Getting configuration file."
				$Parameters = ConvertFrom-Json -InputObject (Get-Content -Path $ConfigFilePath -Raw)
				Write-Log "Successfully retrieved configuration file."

				$IsESAEForest = $Parameters.IsESAEForest
				$ForestRootDomainName = $Parameters.ForestRootDomainName

				if (![System.String]::IsNullOrEmpty($Parameters.SiteName)) {
					$SiteName = $Parameters.SiteName
				}
				else {
					$SiteName = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.AdditionalSitesConfigFilePath)) {
					$AdditionalSitesConfigFilePath = $Parameters.AdditionalSitesConfigFilePath
				}
				else {
					$AdditionalSitesConfigFilePath = [System.String]::Empty
				}
				
				if (![System.String]::IsNullOrEmpty($Parameters.GPOBundleFilePath) -and (Test-Path -Path $Parameters.GPOBundleFilePath)) {
					$GPOBundleFilePath = $Parameters.GPOBundleFilePath
				}
				else {
					$GPOBundleFilePath = $script:BaseGPOBundle
				}

				if (![System.String]::IsNullOrEmpty($Parameters.GPLinksFilePath) -and (Test-Path -Path $Parameters.GPLinksFilePath)) {
					$GPLinksFilePath = $Parameters.GPLinksFilePath				
				}
				else {
					if ($IsESAEForest) {
						$GPLinksFilePath = $script:ESAEGPLinks
					}
					else {
						$GPLinksFilePath = $script:ForestGPLinks
					}
				}
				
				if ($Parameters.SiteSubnets -ne $null -and $Parameters.SiteSubnets.Length -gt 0) {
					$SiteSubnets = $Parameters.SiteSubnets
				}
				else {
					$SiteSubnets = @()
				}

				if (![System.String]::IsNullOrEmpty($Parameters.SysvolFilesPath) -and (Test-Path -Path $Parameters.SysvolFilesPath)) {
					$SysvolFilesPath = $Parameters.SysvolFilesPath
				}
				else {
					if (Test-Path -Path $script:SysvolFiles) {
						$SyvolFilesPath = $script:SysvolFiles
					}
					else {
						$SysvolFilesPath = [System.String]::Empty
					}
				}

				if (![System.String]::IsNullOrEmpty($Parameters.UsersFilePath) -and (Test-Path -Path $Parameters.UsersFilePath)) {
					$UsersFilePath = $Parameters.UsersFilePath

				}
				else {
					$UsersFilePath = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.AdditionalGPOsFilePath)) {
					$AdditionalGPOsFilePath = $Parameters.AdditionalGPOsFilePath
				}
				else {
					$AdditionalGPOsFilePath = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.AdditionalGPLinksFilePath)) {
					$AdditionalGPLinksFilePath = $Parameters.AdditionalGPLinksFilePath
				}
				else {
					$AdditionalGPLinksFilePath = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.OUConfigFilePath)) {
					$OUConfigFilePath = $Parameters.OUConfigFilePath
				}
				else {
					$OUConfigFilePath = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.ForestGroupsConfigFilePath)) {
					$ForestGroupsConfigFilePath = $Parameters.ForestGroupsConfigFilePath
				}
				else {
					$ForestGroupsConfigFilePath = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.ManagementGroupsConfigFilePath)) {
					$ManagementGroupsConfigFilePath = $Parameters.ManagementGroupsConfigFilePath
				}
				else {
					$ManagementGroupsConfigFilePath = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.BaseAdmxBundleFilePath) -and (Test-Path -Path $Parameters.BaseAdmxBundleFilePath)) {
					$BaseAdmxBundleFilePath = $Parameters.BaseAdmxBundleFilePath
				}
				else {
					$BaseAdmxBundleFilePath = [System.String]::Empty
				}

				if (![System.String]::IsNullOrEmpty($Parameters.AddOnAdmxBundleFilePath) -and (Test-Path -Path $Parameters.AddOnAdmxBundleFilePath)) {
					$AddOnAdmxBundleFilePath = $Parameters.AddOnAdmxBundleFilePath
				}
				else {
					$AddOnAdmxBundleFilePath = [System.String]::Empty
				}

				break
			}
			"Parameters" {
				$Counter = 0
				$ForestRootDomainName = ""
				$TimeoutLimit = 10
				while ([System.String]::IsNullOrEmpty($ForestRootDomainName) -and $Counter -lt $TimeoutLimit) {
					Start-Sleep -Seconds 10
					try {
						$ForestRootDomainName = Get-ADForest -Current LocalComputer -Server $env:COMPUTERNAME | Select-Object -ExpandProperty Name
					}
					catch [Exception] {
						Write-Log -Message "Could not call Get-ADForest with error: $($_.Exception.Message)."
						$Counter++			
					}

					if ($Counter -eq $TimeoutLimit) {
						Write-Log -Message "Timeout waiting to successfully call Get-ADForest, using computer domain."
						$ForestRootDomainName = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Domain
					}
				}
				break
			}
		}

		if ([System.String]::IsNullOrEmpty($GPOBundleFilePath)) {
			$GPOBundleFilePath = $script:BaseGPOBundle
		}

		if (![System.String]::IsNullOrEmpty($GPLinksFilePath)) {
			if ($IsESAEForest) {
				$GPLinksFilePath = $script:ESAEGPLinks
			}
			else {
				$GPLinksFilePath = $script:ForestGPLinks
			}		
		}

		if (![System.String]::IsNullOrEmpty($ForestGroupsConfigFilePath) -and !(Test-Path -Path $ForestGroupsConfigFilePath)) {
			Write-Warning "The file specified for the forest groups, $ForestGroupsConfigFilePath, could not be found."
			Write-Log "The file specified for the forest groups, $ForestGroupsConfigFilePath, could not be found."
			throw [System.IO.FileNotFoundException]("The file specified for the forest groups, $ForestGroupsConfigFilePath, could not be found.")
		}

		if (![System.String]::IsNullOrEmpty($UsersFilePath) -and !(Test-Path -Path $UsersFilePath)) {
			Write-Warning "The file specified for the users import, $UsersFilePath, could not be found."
			Write-Log "The file specified for the users import, $UsersFilePath, could not be found."
			throw [System.IO.FileNotFoundException]("The file specified for the users import, $UsersFilePath, could not be found.")
		}

		if (![System.String]::IsNullOrEmpty($AdditionalGPOsFilePath) -and !(Test-Path -Path $AdditionalGPOsFilePath)) {
			Write-Warning "The file specified for the additional gpo import, $AdditionalGPOsFilePath, could not be found."
			Write-Log "The file specified for the additional gpo import, $AdditionalGPOsFilePath, could not be found."
			throw [System.IO.FileNotFoundException]("The file specified for the additional gpo import, $AdditionalGPOsFilePath, could not be found.")
		}

		if (![System.String]::IsNullOrEmpty($AdditionalGPLinksFilePath) -and !(Test-Path -Path $AdditionalGPLinksFilePath)) {
			Write-Warning "The file specified for the additional gpo links, $AdditionalGPLinksFilePath, could not be found."
			Write-Log "The file specified for the additional gpo links, $AdditionalGPLinksFilePath, could not be found."
			throw [System.IO.FileNotFoundException]("The file specified for the additional gpo links, $AdditionalGPLinksFilePath, could not be found.")
		}

		if (![System.String]::IsNullOrEmpty($OUConfigFilePath) -and !(Test-Path -Path $OUConfigFilePath)) {
			Write-Warning "The file specified, $OUConfigFilePath, for the OU configuration could not be found."
			Write-Log "The file specified, $OUConfigFilePath, for the OU configuration could not be found."
			throw [System.IO.FileNotFoundException]("The file specified, $OUConfigFilePath, for the OU configuration could not be found.")
		}

		if ($IsESAEForest -and ![System.String]::IsNullOrEmpty($ManagementGroupsConfigFilePath) -and !(Test-Path -Path $ManagementGroupsConfigFilePath)) {
			Write-Warning "The file specified for the managemement groups, $ManagementGroupsConfigFilePath, could not be found."
			Write-Log "The file specified for the management groups, $ManagementGroupsConfigFilePath, could not be found."
			throw [System.IO.FileNotFoundException]("The file specified for the management groups, $ManagementGroupsConfigFilePath, could not be found.")
		}
		
        [bool]$Success = $true

        $Counter = 0
        $NTDS = Get-Service -Name NTDS

        while ($NTDS.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Start-Sleep -Seconds 1
            $Counter++
            $NTDS = Get-Service -Name NTDS

            if ($Counter -gt 600) {
                throw "Timeout waiting for Active Directory Domain Services to start."
            }
        }

        $Counter = 0
        $ADWS = Get-Service -Name ADWS

        while ($ADWS.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Start-Sleep -Seconds 1
            $Counter++
            $ADWS = Get-Service -Name ADWS

            if ($Counter -gt 600) {
                throw "Timeout waiting for Active Directory Web Services to start."
            }
        }

		$DomainSID = Get-ADDomain -Identity $ForestRootDomainName -Server $env:COMPUTERNAME | Select-Object -ExpandProperty DomainSID
		$DomainUsersSID = (New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)).Value.ToString()
		
        $SYSVOL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty SysVol

		#region AD Sites
		if (![System.String]::IsNullOrEmpty($SiteName)) {
			try 
			{
				Write-Log "Renaming site."
				Rename-ADSite -NewName $SiteName
			}
			catch [Exception] 
			{
				Write-Log $_
				$Success = $false
			}
		}

		if ($SiteSubnets -ne $null -and $SiteSubnets.Count -gt 0) {	
			foreach ($Subnet in $SiteSubnets) {
				try
				{
					Write-Log "Adding subnet $Subnet."
					Add-ADSiteSubnet -SiteSubnet $Subnet -SiteName $SiteName
				}
				catch [Exception] 
				{
					Write-Log $_
					$Success = $false
				}
			
			}    		
		}

		if (![System.String]::IsNullOrEmpty($AdditionalSitesConfigFilePath)) {
			Write-Log "Additional site information provided, converting from Json to object."
			try {
				$AdditionalSitesJson = Get-Content -Path $AdditionalSitesConfigFilePath -Raw
				$AdditionalSites = ConvertFrom-Json -InputObject $AdditionalSitesJson

				foreach ($Site in $AdditionalSites) {
					Write-Log "Adding site $($Site.Name)."

					 try{
						$NewSite = Get-ADReplicationSite -Identity $Site.Name
						 Write-Log "Site $($NewSite.Name) already exists, continuing."
					}
					catch [Exception] {
						try {
							$NewSite = New-ADReplicationSite -Name $Site.Name -PassThru -ProtectedFromAccidentalDeletion $true
							Write-Log "Successfully created new site."
						}
						catch [Exception] {
							Write-Log $_
						}
					}

					if ($NewSite -ne $null) {
						foreach ($Subnet in $Site.Subnets) {
							Write-Log "Adding $Subnet to site $($NewSite.Name)."
							Add-ADSiteSubnet -SiteName $NewSite.Name -SiteSubnet $Subnet
						}
					}
					else {
						Write-Log "New site object was null, not adding subnets."
					}
				}
			}
			catch [Exception] {
				Write-Log $_
			}
		}

		#endregion

		try {
			Write-Log "Installing KDS Root Key, effective immediately."
			Add-KdsRootKey -EffectiveImmediately
			Write-Log "Installed KDS Root Key."
		}
		catch [Exception] {
			Write-Log $_
		}

		try 
        {
			Write-Log "Enabling Recycle Bin."
			Enable-ADRecycleBin -ForestRootDomainName $ForestRootDomainName
		}
		catch [Exception] 
		{
            Write-Log $_
		}

		try
		{
			Write-Log "Adding sceregvl.inf to add MSS settings."
			New-MSSGPOSettings -Wait
			Write-Log "Completed adding sceregvl.inf file."
		}
		catch [Exception]
		{
			Write-Log $_
		}
		
		#region OU and Group Structure

		try
		{
			Write-Log "Creating Forest OU Structure."
			if ([System.String]::IsNullOrEmpty($OUConfigFilePath)) {
				if ($IsESAEForest) {
					Write-Log "Config file was null or empty, but this is an ESAE forest installation, using the ESAE_OU.json file for the configuration."
					Set-OUStructure -FilePath $script:ESAEOUConfigFilePath
				}
				else {
					Set-OUStructure -OUStructureJson ([System.String]::Empty)
				}
			}
			else {
				Set-OUStructure -FilePath $OUConfigFilePath
			}

			Write-Log "Completed creating OU structure."

			try
			{
				Write-Log "Creating local forest management groups."

				if ([System.String]::IsNullOrEmpty($ForestGroupsConfigFilePath)) {
					if ($IsESAEForest) {
						Write-Log -Message "Creating groups for an ESAE forest."
						$GroupPrefix = "UG-ESAE"
						$ResourceOUName = "ESAE Privileged Resources"
					}
					else {
						Write-Log -Message "Creating groups for a standalone forest."
						$GroupPrefix = "UG"
						$ResourceOUName = "Privileged Resources"
					}

					New-StandardForestGroups -GroupNamePrefix $GroupPrefix -ResourceOUName $ResourceOUName
				}
				else {
					Write-Log -Message "Using configuration file to create groups: $ForestGroupsConfigFilePath."
					New-StandardForestGroups -FilePath $ForestGroupsConfigFilePath
				}
		
				Write-Log "Completed creating local forest management groups."
			}
			catch [Exception] 
			{
				Write-Log $_
				$Success = $false
			}

			if ($IsESAEForest) {
				try
				{
					Write-Log "Creating remote forest management groups."
			
					if ([System.String]::IsNullOrEmpty($ManagementGroupsConfigFilePath)) {
						if ([System.String]::IsNullOrEmpty($OUConfigFilePath)) {
							New-ManagementGroups
						}
						else {
							Write-Log "No management group config file path specified, but a custom OU structure was specified. Cannot create default groups with a custom OU structure."
						}
					}
					else {
						New-ManagementGroups -FilePath $ManagementGroupsConfigFilePath
					}

					Write-Log "Completed creating remote forest management groups."
				}
				catch [Exception] 
				{
					Write-Log $_
					$Success = $false
				}
			}
		}
		catch [Exception] 
		{
			Write-Log $_
			$Success = $false
		}

		#endregion

		try 
		{
			Write-Log "Building central policy store."
			New-CentralPolicyStore -FilePath $BaseAdmxBundleFilePath -SysVolPath $SYSVOL -ForestRootDomainName $ForestRootDomainName

			if (![System.String]::IsNullOrEmpty($AddOnAdmxBundleFilePath)) {
				try
				{
					Write-Log "Importing Add-On ADMX files."
					Add-AdmxBundleToCentralPolicyStore -FilePath $AddOnAdmxBundleFilePath -SysVolPath $SYSVOL -ForestRootDomainName $ForestRootDomainName
				}
				catch [Exception] 
				{
					Write-Log $_
					$Success = $false
				}
			}
		}
		catch [Exception] 
		{
			Write-Log $_
			$Success = $false
		}

		try {
			Write-Log "Setting Active Directory non GPO STIG items."
			Start-Transcript -Path $script:TranscriptPath -Append
			Import-Module ActiveDirectoryStig
			Set-ActiveDirectoryStigItems
			Stop-Transcript
			Write-Log "Completed Active Directory STIG."
		}
		catch [Exception] {
			Write-Log $_
			$Success = $false
		}

		try {
			Write-Log "Setting DNS Server STIG."
			Start-Transcript -Path $script:TranscriptPath -Append
			Import-Module DnsStig
			Set-DnsServerStig -Forest $ForestRootDomainName
			Stop-Transcript
			Write-Log "Completed DNS Server STIG."
		}
		catch [Exception] {
			Write-Log $_
			$Success = $false
		}

		#region GPO Operations

		if (![System.String]::IsNullOrEmpty($SysvolFilesPath)) {
			try {
				Write-Log "Extracting config files for GPO use to the SYSVOL."
				Add-SysvolFiles
				Write-Log "Finished extracting config files."
			}
			catch [Exception] {
				Write-Log $_
				$Success = $false
			}
		}
		else {
			Write-Log -Message "No Sysvol files zip specified."
		}

		try
		{
			Write-Log "Creating WMI Filters."
			Start-Transcript -Path $script:TranscriptPath -Append

			Import-Module ActiveDirectoryTools
			New-StandardGPOWmiFilters

			Stop-Transcript
			Write-Log "Finished creating standard WMI filters."
		}
		catch [Exception] {
			Write-Log $_
			$Success = $false
		}

		try
		{
			Write-Log "Importing baseline GPOs."
			$Destination = [System.IO.Path]::Combine($PSScriptRoot,"GPOs")
			Write-Log "Extracting GPO bundle from $GPOBundleFilePath."

			Start-Transcript -Path $script:TranscriptPath -Append

			Extract-ZipFile -Source $GPOBundleFilePath -Destination $Destination

			Write-Log "Creating Migration Table."
			$MigrationTablePath = New-GPOMigrationTable -BackupRootDirectory $Destination

			Write-Log "Setting preference values."
			Set-GPPMigrationValues -BackupRootDirectory $Destination

			Write-Log "Importing GPOs to domain from $Destination for domain $ForestRootDomainName using migration table at $MigrationTablePath."
			Import-FullGPOBackups -Path $Destination -Domain $ForestRootDomainName -MigrationTable $MigrationTablePath
			
			Stop-Transcript

			Write-Log "Deleting temp GPO folder."
			Remove-Item -Path $Destination -Force -Recurse -Confirm:$false
			Remove-Item -Path $MigrationTablePath -Force -Recurse -Confirm:$false
			Write-Log "Completed importing GPOs."

			try {
				Write-Log "Linking GPOs."

				Start-Transcript -Path $script:TranscriptPath -Append

				New-GPOLinks -LinksFilePath $GPLinksFilePath
				try {
					Write-Log "Removing default domain controllers policy."
					$TopLevelDomain = Get-ADDomain -Identity $ForestRootDomainName | Select-Object -ExpandProperty DistinguishedName
					Remove-GPLink -Name "Default Domain Controllers Policy" -Target "OU=Domain Controllers,$TopLevelDomain" -ErrorAction Stop
					Write-Log "Successfully removed default domain controllers policy."
				}
				catch [Exception] {
					Write-Log $_
				}

				Stop-Transcript

				Write-Log "Completed linking GPOs."
			}
			catch [Exception] {
				Write-Log $_
				$Success = $false
			}
		}
		catch [Exception] {
			Write-Log -ErrorRecord $_
			$Success = $false
		}

		if (![System.String]::IsNullOrEmpty($AdditionalGPOsFilePath)) {
			try {
				Write-Log "Importing additional GPOs from $AdditionalGPOsFilePath."
				$Destination = [System.IO.Path]::Combine($PSScriptRoot,"AdditionalGPOs")

				Start-Transcript -Path $script:TranscriptPath -Append

				Extract-ZipFile -Source $AdditionalGPOsFilePath -Destination $Destination

				Write-Log "Creating Migration Table"
				$MigrationTablePath = New-GPOMigrationTable -BackupRootDirectory $Destination
				
				Write-Log "Setting preference values."
				Set-GPPMigrationValues -BackupRootDirectory $Destination
				
				Write-Log "Importing GPOs to domain from $Destination for domain $ForestRootDomainName using migration table at $MigrationTablePath."
				Import-FullGPOBackups -Path $Destination -Domain $ForestRootDomainName -MigrationTable $MigrationTablePath
				
				Write-Log "Deleting temp GPO folder."
				Remove-Item -Path $Destination -Force -Recurse -Confirm:$false
				Remove-Item -Path $MigrationTablePath -Force -Recurse -Confirm:$false
				
				Write-Log -Message "Completed importing GPOs."

				if (![System.String]::IsNullOrEmpty($AdditionalGPLinksFilePath) -and (Test-Path -Path $AdditionalGPLinksFilePath)) {
					try {
						Write-Log -Message "Linking Additional GPOs."
						New-GPOLinks -LinksFilePath $AdditionalGPLinksFilePath
						Write-Log -Message "Completed linking additional GPOs."
					}
					catch [Exception] {
						Write-Log -ErrorRecord $_
						$Success = $false
					}
				}

				Stop-Transcript
			}
			catch [Exception] {
				Write-Log -ErrorRecord $_
				$Success = $false
			}
		}

		#endregion

		try {
			Write-Log "Creating fine grained password policies."
			Write-Log "Setting default domain password policy settings objects."

			Set-ADDefaultDomainPasswordPolicy   -Identity $ForestRootDomainName `
												-ComplexityEnabled $true `
												-LockoutDuration ([System.Timespan]::MinValue) `
												-LockoutObservationWindow ([System.Timespan]::FromMinutes(60)) `
												-LockoutThreshold 3 `
												-MinPasswordLength 14 `
												-MaxPasswordAge ([System.Timespan]::FromDays(60)) `
												-MinPasswordAge ([System.Timespan]::FromDays(1)) `
												-ReversibleEncryptionEnabled $false `
												-PasswordHistoryCount 24 `
												-Server $env:COMPUTERNAME `
			
			Write-Log "Creating STIG password settings object."
			
			$PSO = New-ADFineGrainedPasswordPolicy  -Name "FGP_STIG" `
													-ComplexityEnabled $true `
													-DisplayName "FGP_STIG" `
													-LockoutDuration ([System.Timespan]::MinValue) `
													-LockoutObservationWindow ([System.Timespan]::FromMinutes(60)) `
													-LockoutThreshold 3 `
													-MinPasswordLength 14 `
													-MaxPasswordAge ([System.Timespan]::FromDays(60)) `
													-MinPasswordAge ([System.Timespan]::FromDays(1)) `
													-ProtectedFromAccidentalDeletion $true `
													-ReversibleEncryptionEnabled $false `
													-PasswordHistoryCount 24 `
													-Precedence ([System.Int32]::MaxValue) `
													-Server $env:COMPUTERNAME `
													-PassThru

			Add-ADFineGrainedPasswordPolicySubject -Identity $PSO -Subjects $DomainUsersSID -Server $env:COMPUTERNAME

			Write-Log "Created default and domain Password Settings Objects."
		}
		catch [Exception] {
			Write-Log $_
			$Success = $false
		}

		if (![System.String]::IsNullOrEmpty($UsersFilePath)) {
			try {
			
				Write-Log "Importing users."
				Import-ADUsers -FilePath $UsersFilePath -EnableLogging
				Write-Log "Completed user import."
			}
			catch [Exception] {
				Write-Log $_
				$Success = $false
			}
		}

		Write-Log "Checking for Finish AD Forest Scheduled Task."

        if ((Get-ScheduledTask -TaskName $script:FinishSecureADForestTask -ErrorAction SilentlyContinue) -ne $null) {
            Write-Log "Removing Finish AD Forest Scheduled Task."
            Unregister-ScheduledTask -TaskName $script:FinishSecureADForestTask -Confirm:$false
        }

        if ($Success) {
            Write-Log "Completed forest install."

			if ($IsESAEForest) {
				Write-Log "Starting ESAE Configuration function."
				Set-ESAEForestConfiguration -ConfigFilePath $ConfigFilePath
			}
        }
        else {
            Write-Log "One of the steps in Set-ADForestSecurityConfiguration failed."
			$CommandText = Get-CommandText -Command ($PSCmdlet.MyInvocation.MyCommand.Name) -Parameters $PSBoundParameters
			Write-Log "Rerun this command: $CommandText"
        }
	}

    End {		
    }
}

Function Set-ESAEForestConfiguration {
	<#
		.SYNOPSIS
			This cmdlet conducts the steps to set up the forest trust and DNS settings to enable the ESAE management forest.

		.DESCRIPTION
			The cmdlet builds the conditional forwarders in the two forests, if specified, and then sets up the one-way forest trust from the remote forest to the new ESAE forest.

		.PARAMETER ConfigFilePath
			The path to the configuration file with the parameters used to run this cmdlet. This defaults to "$PSScriptRoot\config.json".

		.PARAMETER RemoteForestCredential
			The credentials to use to connect to the remote forest during an ESAE installation to create the conditional forwarder pointing to the ESAE forest and setup the forest trust.

		.PARAMETER RemoteForest
			The DNS name of the remote forest during an ESAE installation.

		.PARAMETER LocalForest
			The DNS name of the local forest being setup for ESAE. This is only required if the forest being setup is different than the local forest the cmdlet is running on. Typically this is not required.

		.PARAMETER LocalForestCredential
			Specifies the credentials to use on the local forest to set up the forest trust for an ESAE forest. This is only needed if the specific credentials are needed in the local forest, typically not required.

		.PARAMETER CreateRemoteConditionalForwarder
			Specify that a conditional forwarder to the new ESAE forest should be created in the remote forest. Requires RemoteForestCredential is specified.

		.PARAMETER CreateLocalConditionalForwarder
			Specify that a conditional forwarder to the remote forest should be created in the new ESAE forest. This needs to be specified unless an external DNS solution is utilized to resolve the remote forest.

		.PARAMETER RemoteForestMasterServers
			The remote DNS servers that will be used to create the local conditional forwarder in the new ESAE forest.

		.INPUTS
			None

		.OUTPUTS
			None

		.EXAMPLE
			Set-ESAEForestConfiguration -RemoteForest "contoso.com" `
								-RemoteForestMasterServers @("192.168.2.1") `
								-CreateLocalConditionalForwarder `
								-RemoteForestCredential (Get-Credential) `
								-CreateRemoteConditionalForwarder `

		.NOTES
			The remote forest credential should have Enterprise Admin rights to build the conditional forwarder and establish the forest trust.
	#>
	[CmdletBinding(DefaultParameterSetName="File")]
	Param (
		[Parameter(ParameterSetName="File")]
		[ValidateScript({Test-Path -Path $_})]	
		[System.String]$ConfigFilePath = $script:ConfigFilePath,

		[Parameter(ParameterSetName="Parameters",Mandatory=$true)]
		[System.String]$RemoteForest,

		[Parameter(ParameterSetName="Parameters",Mandatory=$true)]
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$RemoteForestCredential,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$LocalForestCredential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$CreateLocalConditionalForwarder,

		[Parameter(ParameterSetName="Parameters")]
		[switch]$CreateRemoteConditionalForwarder,

		[Parameter(ParameterSetName="Parameters")]
		[ValidateNotNull()]
		[System.String[]]$RemoteForestMasterServers = @()
    )

	Begin {		
	}

	Process {
		Write-Log "Starting ESAE Forest Configuration."

		switch ($PSCmdlet.ParameterSetName) {
			"File" {
				Write-Log "Getting config file from $ConfigFilePath."
				$Parameters = ConvertFrom-Json -InputObject (Get-Content -Path $ConfigFilePath -Raw)

				Write-Log "Remote forest password file $($Parameters.RemoteForestPasswordFilePath)."

				$RemoteForest = $Parameters.RemoteForest
				$RemoteForestCredentialPassword = Get-EncryptedPassword -FilePath $Parameters.RemoteForestPasswordFilePath
				$RemoteForestCredential = New-Object -TypeName System.Management.Automation.PSCredential($Parameters.RemoteForestUserName, $RemoteForestCredentialPassword)

				try {
					Write-Log "Removing remote forest password file."
					Remove-Item -Path $Parameters.RemoteForestPasswordFilePath
					Write-Log "Removed password file."
				}
				catch [Exception] {
					Write-Log $_
				}

				try {
					if (![System.String]::IsNullOrEmpty($Parameters.LocalForestPasswordFilePath) -and (Test-Path -Path $Parameters.LocalForestPasswordFilePath) -and ![System.String]::IsNullOrEmpty($Parameters.LocalForestUserName)) {
						Write-Log "Local forest credentials specified."
						$LocalForestCredentialPassword = Get-EncryptedPassword -FilePath $Parameters.LocalForestPasswordFilePath
						$LocalForestCredential = New-Object -TypeName System.Management.Automation.PSCredential($Parameters.LocalForestUserName, $LocalForestCredentialPassword)

						Write-Log "Removing local forest password file."
						Remove-Item -Path $Parameters.RemoteForestPasswordFilePath
						Write-Log "Removed password file."

					} else {
						$LocalForestCredential = [PSCredential]::Empty
					}
				}
				catch [Exception] {
					Write-Log $_
				}

				if ($Parameters.CreateLocalConditionalForwarder -ne $null) {
					$CreateLocalConditionalForwarder = $Parameters.CreateLocalConditionalForwarder
				}
				else {
					$CreateLocalConditionalForwarder = $false
				}
				
				if ($CreateLocalConditionalForwarder) {
					if ($Parameters.RemoteForestMasterServers -ne $null -and $Parameters.RemoteForestMasterServers.Count -gt 0) {
						$RemoteForestMasterServers = $Parameters.RemoteForestMasterServers
					}
					else {
						Write-Log "Create local stub zone was specified, but the remote forest master servers array was null or empty."
						throw "Create local stub zone was specified, but the remote forest master servers array was null or empty."
					}
				}

				if ($Parameters.CreateRemoteConditionalForwarder -ne $null) {
					$CreateRemoteConditionalForwarder = $Parameters.CreateRemoteConditionalForwarder
				}
				else {
					$CreateRemoteConditionalForwarder = $false
				}
			
				break
			}
			"Parameters" {

				break
			}
		}

		[bool]$Success = $false
        $ForestRootDomainName = Get-ADForest -Current LocalComputer -Server $env:COMPUTERNAME | Select-Object -ExpandProperty Name	

		try {
			Write-Log "Creating forest trust with $RemoteForest."

			New-ADForestTrust -RemoteForest $RemoteForest `
								-RemoteForestCredential $RemoteForestCredential `
								-LocalForestCredential $LocalForestCredential `
								-CreateLocalConditionalForwarder:$CreateLocalConditionalForwarder `
								-CreateRemoteConditionalForwarder:$CreateRemoteConditionalForwarder `
								-RemoteForestMasterServers $RemoteForestMasterServers `
								-EnableSelectiveAuthentication $true `
								-SidFilteringEnabled $true `
								-TrustDirection Inbound `
								-EnableLogging `
								-TrustingDomainSupportsKerberosAESEncryption $true `
								-WaitForRpcSs
		}
		catch [Exception] {
			Write-Log $_
		}

		Write-Log "Completed ESAE Forest Configuration."
	}

	End {		
	}
}

#endregion

#region AD Forest Prerequisites

Function Add-ADDSWindowsFeature {
	<#
		.SYNOPSIS
			Installs the Active Directory feature.

		.DESCRIPTION
			Installs the Active Directory feature and optionally installs the management tools.

		.PARAMETER IncludeManagementTools
			Specify whether the management tools should be installed, this defaults to false.

		.INPUTS
			None
		
		.OUTPUTS
			Microsoft.Windows.ServerManager.Commands.FeatureOperationResult

		.EXAMPLE
			Add-ADDSWindowsFeature -IncludeManagementTools
			
			Installs the Active Directory feature with the management tools.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[switch]$IncludeManagementTools = $false
	)
    Begin {}

    Process {
        $Feature = Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools:$IncludeManagementTools
		Write-Output -InputObject $Feature
    }

    End {       
    }
}

Function Set-LocalAdminPassword {
	<#
		.SYNOPSIS
			Sets the local administrator password.

		.DESCRIPTION
			Sets the local administrator password and optionally enables the account if it is disabled.

		.PARAMETER AdminPassword
			The new password for the local administrator account.

		.PARAMETER EnableAccount
			Specify to enable the local administrator account if it is disabled.

		.INPUTS
			System.Boolean
		
		.OUTPUTS
			Microsoft.Windows.ServerManager.Commands.FeatureOperationResult

		.EXAMPLE 
			Set-LocalAdminPassword -EnableAccount

			The cmdlet will prompt the user to enter the new password.

		.NOTES
			None
	#>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0 , ValueFromPipeline=$true)]
        [SecureString]$AdminPassword,

		[Parameter()]
		[switch]$EnableAccount
    )
    Begin {       
    }
    
    Process {
		$HostName = $env:COMPUTERNAME 
        $Computer = [ADSI]"WinNT://$HostName,Computer" 

		while($AdminPassword -eq $null) {
			$AdminPassword = Read-Host -AsSecureString -Prompt "Enter the new administrator password"
		}

        foreach ($Child in $Computer.Children | Where {$_.Class -eq "User"} ) { 

            $Sid = New-Object System.Security.Principal.SecurityIdentifier($Child.objectSid[0],0) 
    
            if ($Sid.Value -match "S-1-5-21-.*-500") {
    
                $User = [ADSI]"WinNT://$HostName/$($Child.Name),User"
                $Password = Convert-SecureStringToString -SecureString $AdminPassword
                
                $User.SetPassword($Password)
                
				if ($EnableAccount) {
					#The 0x0002 flag specifies that the account is diabled
					#The binary AND operator will test the value to see if the bit is set, if it is, the account is disabled.
					#Doing a binary OR would add the value to the flags, since it would not be present, the OR would add it
					if ($User.UserFlags.Value -band "0x0002") {
						#The binary XOR will remove the flag, which enables the account, the XOR means that if both values have the bit set, the result does not
						#If only 1 value has the bit set, then it will remain set, so we need to ensure that the bit is actually set with the -band above for the XOR to actually
						#remove the disabled value
						$User.UserFlags = $User.UserFlags -bxor "0x0002"
						$User.SetInfo()
					}
				}

                break
            }
        }

		Write-Output -InputObject $true
    }
    
    End {        
    }       
}

Function Rename-LocalComputer {
	<#
		.SYNOPSIS
			Renames the computer.

		.DESCRIPTION
			Renames the computer.

		.PARAMETER NewName
			The new name for the computer, must be 15 characters or less.

		.INPUTS
			System.String
		
		.OUTPUTS
			System.String

		.EXAMPLE
			Rename-LocalComputer -ComputerName "AdminDC"

			Renames the local computer to AdminDC.

		.NOTES
			None
	#>
	[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
		[ValidateScript({$_.Length -le 15})]
        [System.String]$ComputerName
    )
    Begin {}

    Process {
        $NewName = Rename-Computer -NewName $ComputerName -PassThru
		Write-Output -InputObject $NewName
    }

    End {        
    }
}

#endregion

#region Finish AD Forest Installation

Function Rename-ADSite {
	<#
		.SYNOPSIS
			Renames the specified Active Directory Site.

		.DESCRIPTION
			Renames the specified Active Directory Site

		.PARAMETER Name
			The current identity of the Active Directory site, this defaults to "Default-First-Site-Name".

		.PARAMETER NewName
			The new name of the Active Directory site.

		.INPUTS
			None
		
		.OUTPUTS
			Microsoft.ActiveDirectory.Management.ADReplicationSite

		.EXAMPLE
			Rename-ADSite -NewName "Headquarters"

			Renames the Default-First-Site-Name site to Headquarters.

		.NOTES
			None
	#>
	[CmdletBinding()]
    Param (
		[Parameter(Position=1)]
		[System.String]$Name = "Default-First-Site-Name",

        [Parameter(Position=0, Mandatory=$true)]
        [System.String]$NewName
    )

    Begin {}

    Process {
        $Site = Get-ADReplicationSite -Server $env:COMPUTERNAME -Identity $Name | Rename-ADObject -NewName $NewName -Server $env:COMPUTERNAME -PassThru
		Write-Output -InputObject $Site
    }

    End {    
    }
}

Function Add-ADSiteSubnet {
	<#
		.SYNOPSIS
			Adds a single subnet to an Active Directory site.

		.DESCRIPTION
			Adds a single subnet to an Active Directory site. If the subnet already exists as a replication subnet, it is assigned to the specified Site, which will remove it from any pre-existing association. If it does not exist, it is added and assigned to the site.

		.PARAMETER SiteSubnet
			The subnet to add to the site, should be in the form of X.X.X.X/CIDR.

		.PARAMETER SiteName
			The site the subnet will be added to. This defaults to the current site of the computer the cmdlet is being run on.

		.INPUTS
			None
		
		.OUTPUTS
			Microsoft.ActiveDirectory.Management.ADReplicationSubnet

		.EXAMPLE 
			Add-ADSiteSubnet -SiteSubnet "192.168.1.0/24" -SiteName "Headquarters"

			The 192.168.1.0/24 subnet is added to the Headquarters site.

		.NOTES
			None
	#>
	[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [System.String]$SiteSubnet,

        [Parameter(Position=1)]
        [System.String]$SiteName = [System.String]::Empty
    )

    Begin {       
    }

    Process {
		if ([System.String]::IsNullOrEmpty($SiteName)) 
		{
            $SiteName = Get-ADReplicationSite -Server $env:COMPUTERNAME  | Select-Object -First 1 -ExpandProperty Name
        }

		try 
		{
			$ExistingSubnet = Get-ADReplicationSubnet -Identity $SiteSubnet -ErrorAction SilentlyContinue

			if ($ExistingSubnet -eq $null) 
			{
				$Subnet = New-ADReplicationSubnet -Name $SiteSubnet -Site $SiteName
			}
			else 
			{
				$Subnet = Set-ADReplicationSubnet -Identity $ExistingSubnet -Site $SiteName -PassThru
			}
		}
		catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] 
		{
			$Subnet = New-ADReplicationSubnet -Name $SiteSubnet -Site $SiteName
		}

		Write-Output -InputObject $Subnet
    }

    End {      
    }
}

Function Enable-ADRecycleBin {
	<#
		.SYNOPSIS
			Enables the AD recycle bin.

		.DESCRIPTION
			Enables the AD recycle bin in the specified forest.

		.PARAMETER ForestRootDomainName
			The name of the forest root domain. This defaults to the forest of the computer the cmdlet is being run on.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Enable-ADRecycleBin -ForestRootDomainName "admin.local"

			Enables the AD recycle bin in the admin.local forest.

		.NOTES
			None
	#>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [System.String]$ForestRootDomainName = [System.String]::Empty
    )

    Begin {        
    }

    Process {
		if ([System.String]::IsNullOrEmpty($ForestRootDomainName)) 
		{
            $ForestRootDomainName = Get-ADForest -Current LocalComputer | Select-Object -ExpandProperty Name
        }

        Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $ForestRootDomainName -Confirm:$false

		Write-Host "AD Recycle Bin successfully enabled" -ForegroundColor Green
    }

    End {		
    }
}

Function New-CentralPolicyStore {
	<#
		.SYNOPSIS
			Creates the Central Policy Store for GPOs.

		.DESCRIPTION
			Creates the Central Policy Store in the SYSVOL. Then, the cmdlet extracts the ADMX and English ADML files in the specified zip, or uses the local ADMX and English ADML files in the PolicyDefinitions folder, and 
			moves those to the Central Policy Store. The default included zip file contains the ADMX definitions from Windows 10 1511.

		.PARAMETER FilePath
			The path to the zip containing the ADMX and ADML files. This defaults to "$PSScriptRoot\BaseAdmxBundle.zip". Set this option to an empty string to use the local PolicyDefinitions folder instead.

		.PARAMETER SysVolPath
			The location of the SYSVOL. This parameter defaults to finding the SYSVOL from "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" SysVol property. This property only exists on domain controllers, so if the
			cmdlet is being run remotely, the path should be explicitly specified.

		.PARAMETER ForestRootDomainName
			The name of the forest root domain to be used with the SYSVOL path. This defaults to the current forest of the local computer.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			New-CentralPolicyStore

			Creates the Central Policy Store using the default ADMX zip bundle for the current forest of the local domain controller the cmdlet is run on.

		.NOTES
			None
	#>
	[CmdletBinding()]
    Param (
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[System.String]$FilePath = "$PSScriptRoot\BaseAdmxBundle.zip",

        [Parameter(Position=1)]		
        [System.String]$SysVolPath = [System.String]::Empty,

        [Parameter(Position=2)]
        [System.String]$ForestRootDomainName = [System.String]::Empty
    )

    Begin {       
    }

    Process {
		if ([System.String]::IsNullOrEmpty($SysVolPath)) {
            $SYSVOL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty SysVol
        }
        else {
            $SYSVOL = $SysVolPath
        }

        if ([System.String]::IsNullOrEmpty($ForestRootDomainName)) {
            $ForestRootDomainName = Get-ADForest -Current LocalComputer | Select-Object -ExpandProperty Name
        }   

		if ($FilePath -eq $null -or $FilePath -eq [System.String]::Empty -or !(Test-Path -Path $FilePath))  {
			$SourceAdmx = "$env:SYSTEMROOT\PolicyDefinitions\*.admx"
			$SourceAdml = "$env:SYSTEMROOT\PolicyDefinitions\en-us\*.adml"

			$CentralStoreAdmx = "$SYSVOL\$ForestRootDomainName\Policies\PolicyDefinitions"
			$CentralStoreAdml = "$SYSVOL\$ForestRootDomainName\Policies\PolicyDefinitions\en-us"

			New-Item -ItemType Directory -Path $CentralStoreAdmx
			New-Item -ItemType Directory -Path $CentralStoreAdml

			Copy-Item -Path $SourceAdmx -Destination $CentralStoreAdmx
			Copy-Item -Path $SourceAdml -Destination $CentralStoreAdml
		}
		else {
			Extract-ZipFile -Source $FilePath -Destination "$SYSVOL\$ForestRootDomainName\Policies\PolicyDefinitions"
		}

		Write-Host "Central Policy Store successfullly created." -ForegroundColor Green
    }

    End {		
    }
}

Function Add-AdmxBundleToCentralPolicyStore {
	<#
		.SYNOPSIS
			Adds the contents of zip file to the Central Policy Store

		.DESCRIPTION
			Adds the contents of a zip file to the Central Policy Store.

		.PARAMETER FilePath
			The path to the zip containing the ADMX and ADML files.

		.PARAMETER SysVolPath
			The location of the SYSVOL. This parameter defaults to finding the SYSVOL from "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" SysVol property. This property only exists on domain controllers, so if the
			cmdlet is being run remotely, the path should be explicitly specified.

		.PARAMETER ForestRootDomainName
			The name of the forest root domain to be used with the SYSVOL path. This defaults to the current forest of the local computer.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Add-AdmxBundletoCentralPolicyStore -FilePath "$PSScriptRoot\AddOnAdmxBundle.zip"

			Adds the contents of the zip file to the central policy store.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Position=0, ValueFromPipeline=$true, Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$FilePath,

        [Parameter(Position=1)]		
        [System.String]$SysVolPath = [System.String]::Empty,

        [Parameter(Position=2)]
        [System.String]$ForestRootDomainName = [System.String]::Empty
    )

    Begin {		
    }

    Process {
		if ([System.String]::IsNullOrEmpty($FilePath) -or !(Test-Path -Path $FilePath))  
		{
			throw [System.IO.FileNotFoundException]("The source zip file could not be found.")
		}

        if ([System.String]::IsNullOrEmpty($SysVolPath)) 
		{
            $SYSVOL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty SysVol
        }
        else 
		{
            $SYSVOL = $SysVolPath
        }

        if ([System.String]::IsNullOrEmpty($ForestRootDomainName)) 
		{
            $ForestRootDomainName = Get-ADForest -Current LocalComputer | Select-Object -ExpandProperty Name
        }

		if (Test-Path -Path "$SYSVOL\$ForestRootDomainName\Policies\PolicyDefinitions") 
		{
			Extract-ZipFile -Source $FilePath -Destination "$SYSVOL\$ForestRootDomainName\Policies\PolicyDefinitions"
			Write-Host "Add-on ADMX files successfullly extracted." -ForegroundColor Green
		}
		else 
		{
			Write-Warning -Message "The Policy Definitions folder in the Central Policy Store could not be found."
		}
    }

    End {		
    }
}

Function New-MSSGPOSettings {
	<#
		.SYNOPSIS
			Adds the new sceregvl.inf file to enable the MSS settings in Group Policy Management.

		.DESCRIPTION
			Adds the new sceregvl.inf file to enable the MSS settings in Group Policy Management. The original file is renamed to .old.

		.PARAMETER FilePath
			The path to the new sceregvl.inf file. This defaults to "$PSScriptRoot\sceregvl.inf" and shouldn't need to be changed.

		.PARAMETER Wait
			The function executes a scheduled task that runs as SYSTEM. This parameter waits for the schedule task to complete before completing.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			New-MSSGPOSettings

			Adds the new sceregvl.inf file and enables the management of MSS settings in GPMC.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0, ValueFromPipeline=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$FilePath = $script:MSSFilePath,

		[Parameter(Position=1)]
		[switch]$Wait
	)

	Begin{		
	}

	Process{
		$TargetFilePath = "$env:SYSTEMROOT\inf\sceregvl.inf"
		$NewName = "$env:SYSTEMROOT\inf\sceregvl.old"

        $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

        $SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

		<#$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\takeown.exe" -ArgumentList @("/f $TargetFilePath") -NoNewWindow

		#$Acl = Get-Acl -Path $TargetFilePath
		#$Acl.AddAccessRule($SystemAce)
		#Set-Acl -Path $TargetFilePath -AclObject $Acl

		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\icacls.exe" -ArgumentList @("$TargetFilePath", "/grant SYSTEM:f")

		Rename-Item -Path $TargetFilePath -NewName $NewName
		Copy-Item -Path $FilePath -Destination $TargetFilePath -Force

		$Process = Start-Process -FilePath "$env:SYSTEMROOT\System32\regsvr32.exe" -ArgumentList @("scecli.dll") -NoNewWindow#>

		$TaskName = "takeown"

		$Command = @"
		try {
			Import-Module -Name ESAE
			[System.Diagnostics.Process]`$Process = New-Object System.Diagnostics.Process
			`$Process.StartInfo.Filename = "`$env:SYSTEMROOT\System32\takeown.exe"
			`$Process.StartInfo.Arguments = "/f ```"$TargetFilePath```""
			`$Process.StartInfo.RedirectStandardOutput = `$true
			`$Process.StartInfo.UseShellExecute = `$false
			`$Process.StartInfo.CreateNoWindow = `$true
			`$Process.StartInfo.RedirectStandardError = `$true
			`$Process.Start() | Out-Null
			`$Process.WaitForExit()

			if (`$Process.ExitCode -ne 0) {
				Write-Log -Message "takeown.exe exited with code `$Process.ExitCode."
				[System.String]`$Out = `$Process.StandardError.ReadToEnd()
				Write-Log -Message "Error running takeown.exe `$Out"
			}
			else {
				[System.String]`$Out = `$Process.StandardOutput.ReadToEnd()
				Write-Log -Message "Successfully ran takeown - `$Out"		
			
				[System.Diagnostics.Process]`$Process = New-Object System.Diagnostics.Process
				`$Process.StartInfo.Filename = "`$env:SYSTEMROOT\System32\icacls.exe"
				`$Process.StartInfo.Arguments = "```"$TargetFilePath```" /grant SYSTEM:f"
				`$Process.StartInfo.RedirectStandardOutput = `$true
				`$Process.StartInfo.UseShellExecute = `$false
				`$Process.StartInfo.CreateNoWindow = `$true
				`$Process.StartInfo.RedirectStandardError = `$true
				`$Process.Start() | Out-Null
				`$Process.WaitForExit()

				if (`$Process.ExitCode -ne 0) {
					Write-Log -Message "icacls.exe exited with code `$Process.ExitCode."
					[System.String]`$Out = `$Process.StandardError.ReadToEnd()
					Write-Log -Message "Error running icacls.exe `$Out"
				}
				else {
					[System.String]`$Out = `$Process.StandardOutput.ReadToEnd()
					Write-Log -Message "Successfully ran icacls - `$Out"	
				
					try {
						Write-Log -Message "Renaming $TargetFilePath to $NewName."	
						Rename-Item -Path "$TargetFilePath" -NewName "$NewName"
						Write-Log -Message "Copying new file from $FilePath to $TargetFilePath."
						Copy-Item -Path "$FilePath" -Destination "$TargetFilePath" -Force
						Start-Process -FilePath "`$env:SYSTEMROOT\System32\regsvr32.exe" -ArgumentList @("scecli.dll") -NoNewWindow	
						Write-Log -Message "Successfully registered new sceregvl.inf file."	
						
						Write-Log -Message "Removing scheduled task, $TaskName."
						Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false
						Write-Log -Message "Successfully unregistered scheduled task."
					}
					catch [Exception] {
						Write-Log `$_
					}
				}				
			}
		}
		catch [Exception] {
			Write-Log `$_
		}
"@

<#		$Command = @"
		Start-Process -FilePath "`$env:SYSTEMROOT\System32\takeown.exe" -ArgumentList @("/f ```"$TargetFilePath```"") -NoNewWindow
		Start-Process -FilePath "`$env:SYSTEMROOT\System32\icacls.exe" -ArgumentList @("$TargetFilePath", "/grant SYSTEM:f") -NoNewWindow
		Rename-Item -Path "$TargetFilePath" -NewName "$NewName"
		Copy-Item -Path "$FilePath" -Destination "$TargetFilePath" -Force
		Start-Process -FilePath "`$env:SYSTEMROOT\System32\regsvr32.exe" -ArgumentList @("scecli.dll") -NoNewWindow
"@#>

		$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
		$EncodedCommand = [Convert]::ToBase64String($Bytes)

		$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
		$STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
		$STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
		$STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
		$STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew 
                          
		$ScheduledTask = Register-ScheduledTask -TaskName $TaskName -Action $STAction -Principal $STPrincipal -Settings $STSettings -ErrorAction Stop 

		Start-ScheduledTask -TaskName $TaskName

		if ($Wait) {
			$Task = $ScheduledTask

			$Counter = 0
			while ($Task -ne $null -and $Counter -lt 600) {
				$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
				Start-Sleep -Seconds 1
				$Counter++

				if ($Counter -eq 600) {
					throw "Timeout waiting for scheduled task to replace sceregvl.inf to complete."
				}
			}
		}		
	}

	End{
	}
}

Function New-StandardForestGroups {
	<#
		.SYNOPSIS
			Creates the standard set of groups in the forest to manage the environment.

		.DESCRIPTION
			This cmdlet creates "pseudo" groups for the builtin administrative groups in Active Directory. This allows users to be added to these new groups and the builtin groups with well-known SIDs can be statically set
			so that any changes to those can undone or trigger an alert through monitoring tools.

		.PARAMETER GroupsJson
			A JSON string that defines the new groups and their membership. This defaults to empty and a standard set of groups is created based on the default OU configuration provided by the Set-OUStructure cmdlet.

		.PARAMETER FilePath
			The path to the JSON file that defines the new groups and their membership. This defaults to empty and a standard set of groups is created based on the default OU configuration provided by the Set-OUStructure cmdlet.

		.PARAMETER GroupNamePrefix
			The prefix of each group name if the default groups are used. This defaults to UG.

		.PARAMETER ResourceOUName
			The name of the OU under the top level domain that the User Resources OU is nested in. This is used with the default set of groups and is ignored if the filepath or json options are used. This option defaults to "Privileged Resources".

		.INPUTS
			System.String
		
		.OUTPUTS
			Microsoft.ActiveDirectory.Management.ADGroup[]

		.EXAMPLE 
			New-StandardForestGroups -GroupNamePrefix "UG-ESAE" -ResourceOUName "ESAE Privileged Resources"

			Uses the default group definition and creates each group with the UG-ESAE prefix under the User Resources OU in the ESAE Privileged Resources OU at the top level of the domain.

			The results in groups like UG-ESAE-Domain-Admins.

		.EXAMPLE
			New-StandardForestGroups

			Uses the default group definition and creates each group with the UG prefix under the User Resources OU in the Privileged Resources OU at the top level of the domain.

			The results in groups like UG-Domain-Admins.

		.NOTES
			Refer to the Forest_LocalGroups.json file for appropriate syntax. The domain level should not be specified as part of the path for the group, it is derived programmatically.
	#>
	[CmdletBinding(DefaultParameterSetName="Default")]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="Json",Mandatory=$true)]
		[System.String]$GroupsJson = [System.String]::Empty,

		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="File",Mandatory=$true)]		
		[System.String]$FilePath,

		[Parameter(Position=1,ParameterSetName="Default")]
		[System.String]$GroupNamePrefix = "UG",

		[Parameter(Position=2,ParameterSetName="Default")]
		[System.String]$ResourceOUName = "Privileged Resources"
	)

	Begin {		
	}

	Process {
		$TopLevelDomain = Get-ADDomain -Current LocalComputer | Select-Object -ExpandProperty DistinguishedName

		switch ($PSCmdlet.ParameterSetName)
		{
			"Default" {
				$GroupsJson = @"
[
	{
		"Name" : "$GroupNamePrefix-Domain-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"Domain Admins"
		],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name": "$GroupNamePrefix-GPO-Admins",
		"Scope": "Global",
		"Category": "Security",
		"MemberOf": [
		  "Group Policy Creator Owners"
		],
		"Path": "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
    },
    {
		"Name" : "$GroupNamePrefix-DNS-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"DnsAdmins"
		],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Enterprise-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"Enterprise Admins"
		],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Schema-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"Schema Admins"
		],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Server-AD-LocalAdmins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"Server Operators"
		],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Server-LocalAdmins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"Server Operators"
		],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Workstation-LocalAdmins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Workstation-AD-LocalAdmins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Builtin-Administrators",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"Administrators"
		],
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Account-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"MemberOf" : [
			"Account Operators"
		],
		"Path" :"OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	}
]
"@

				break
			}
			"File" {
				$GroupsJson = Get-Content -Path $FilePath -Raw
				break
			}
			"Json" {
				break
			}
			default {
				throw "Could not determine parameter set for New-StandardForestGroups."
			}
		}
		
		$Groups = ConvertFrom-Json -InputObject $GroupsJson
		$NewGroups = @()

		foreach ($Group in $Groups) {
			try
			{				
				#Test if group exists first
				$Temp = "CN=$($Group.Name),$($Group.Path),$TopLevelDomain"
				Write-Log -Message "Creating group $Temp."

				$NewGroup = Get-ADGroup -Filter {DistinguishedName -eq $Temp}

				if ($NewGroup -eq $null -or $NewGroup.Count -eq 0) {
					$NewGroup = New-ADGroup -Name $Group.Name -DisplayName $Group.Name -Path "$($Group.Path),$TopLevelDomain" -SamAccountName $Group.Name -GroupCategory $Group.Category -GroupScope $Group.Scope -PassThru
					if ($Group.MemberOf -ne $null -and $Group.MemberOf.Length -gt 0) {
						foreach($Member in $Group.MemberOf) {
							try {
								Add-ADGroupMember -Identity $Member -Members $NewGroup
							}
							catch [Exception] {
								Write-Warning ("Error adding $($NewGroup.Name) to $Member : " + $_.Exception.Message)
								Write-Log ("Error adding $($NewGroup.Name) to $Member : " + $_.Exception.Message)
							}
						}
					}
				}
				
				$NewGroups += $NewGroup
			}
			catch [Exception]
			{
				Write-Warning ("Error creating group : " + $_.Exception.Message)
				Write-Log ("Error creating group : " + $_.Exception.Message)
			}
		}

		Write-Log "Finished creating standard forest groups."
		Write-Output -InputObject $NewGroups
	}

	End {		
	}
}

Function New-ManagementGroups {
	<#
		.SYNOPSIS
			Creates the standard set of groups for an ESAE deployment to manage remote forests.

		.DESCRIPTION
			This cmdlet creates "pseudo" groups for the builtin administrative groups in Active Directory for remote forests. These groups can then be added to domain local groups in the remote forest to enable remote
			administration from the ESAE forest.

		.PARAMETER GroupsJson
			A JSON string that defines the new groups. This defaults to empty and a standard set of groups is created based on the default OU configuration provided by the Set-OUStructure cmdlet.

		.PARAMETER FilePath
			The path to the JSON file that defines the new groups. This defaults to empty and a standard set of groups is created based on the default OU configuration provided by the Set-OUStructure cmdlet.

		.PARAMETER GroupNamePrefix
			The prefix of each group name if the default groups are used. This defaults to UG, but should be set to something like UG-DomainName to specify the domain the group is intended to manage.

		.PARAMETER ResourceOUName
			The name of the OU under the top level domain that the User Resources OU is nested in. This is used with the default set of groups and is ignored if the filepath or json options are used. This option defaults to "Privileged Resources".

		.INPUTS
			System.String
		
		.OUTPUTS
			Microsoft.ActiveDirectory.Management.ADGroup[]

		.EXAMPLE 
			New-ManagementGroups -GroupNamePrefix "UG-Constoso"

			Uses the default group definition and creates each group with the UG-Contoso prefix under the User Resources OU in the Privileged Resources OU at the top level of the domain.

			The results in groups like UG-Contoso-Domain-Admins.

		.NOTES
			Refer to the ESAE_RemoteManagementGroups.json file for appropriate syntax. The domain level should not be specified as part of the path for the group, it is derived programmatically.
	#>
	[CmdletBinding(DefaultParameterSetName="Json")]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="Json")]
		[System.String]$GroupsJson,

		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="File",Mandatory=$true)]		
		[System.String]$FilePath,

		[Parameter(Position=1, ParameterSetName="Default")]
		[System.String]$GroupNamePrefix = "UG",

		[Parameter(Position=2, ParameterSetName="Default")]
		[System.String]$ResourceOUName = "Privileged Resources"
	)

	Begin {		
	}

	Process {
		$TopLevelDomain = Get-ADDomain -Current LocalComputer | Select-Object -ExpandProperty DistinguishedName

		switch ($PSCmdlet.ParameterSetName)
		{
			"Json" {
				if ($GroupsJson -eq $null -or $GroupsJson -eq [System.String]::Empty)
				{
					$GroupsJson = @"
[
	{
		"Name" : "$GroupNamePrefix-Domain-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Enterprise-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Schema-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Server-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Administrators",
		"Scope" : "Global",
		"Category" : "Security",
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Workstation-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	},
	{
		"Name" : "$GroupNamePrefix-Account-Admins",
		"Scope" : "Global",
		"Category" : "Security",
		"Path" : "OU=User Groups,OU=User Resources,OU=$ResourceOUName"
	}
]
"@
				}

				break
			}
			"File" {
				$GroupsJson = Get-Content -Path $FilePath
				break
			}
			default {
				throw "Could not determine parameter set for New-ManagementGroups."
			}
		}

		$Groups = ConvertFrom-Json -InputObject $GroupsJson
		$NewGroups = @()

		foreach ($Group in $Groups) {
			try
			{
				if (!$Group.Path.EndsWith($TopLevelDomain)) {
					$Path = ($Group.Path + "," + $TopLevelDomain)
				}
				else {
					$Path = $Group.Path
				}

				#TEST if group exits first
				$Temp = "CN=$($Group.Name),$Path"
				$NewGroup = Get-ADGroup -Filter {DistinguishedName -eq $Temp}

				if ($NewGroup -eq $null) {
					$NewGroup = New-ADGroup -Name $Group.Name -DisplayName $Group.Name -Path $Path -SamAccountName $Group.Name -GroupCategory $Group.Category -GroupScope $Group.Scope -PassThru
				}
				
				$NewGroups += $NewGroup
			}
			catch [Exception]
			{
				Write-Warning ("Error creating group $($Group.Name) " + $_.Exception.Message)
				Write-Log ("Error creating group $($Group.Name) " + $_.Exception.Message)
			}
		}

		Write-Log "Finished creating Management groups."
		Write-Output -InputObject $NewGroups
	}

	End {		
	}
}

#endregion

#region Build AD Structure

Function Set-OUStructure {
	<#
		.SYNOPSIS
			Creates an OU structure in the Active Directory forest.

		.DESCRIPTION
			Creates an OU structure in the Active Directory forest. This uses a default configuration if not JSON or file is specified. The structure is separated into two top level OUs, Privileged Resources that contain
			all of the users, groups, workstations and servers that are used to run the forest, and an Operations OU that contains all of the users, groups, workstations, and servers that are hosted in the Forest. The Operations
			OU is intended for non-privileged users, groups, etc that are tenants or consumers of services in AD, or for an ESAE deployment, only have administrative permissions in remote forests, but not the ESAE forest. 

			The OU structure is created in the current domain of the computer that the cmdlet is being run on.

		.PARAMETER OUStructureJson
			A JSON string that defines the OU structure to be created. This defaults to empty and uses the default OU structure.

		.PARAMETER FilePath
			The path to the JSON file that defines the OU structure to be created.

		.INPUTS
			System.String
		
		.OUTPUTS
			Microsoft.ActiveDirectory.Management.ADOrganizationalUnit[]

		.EXAMPLE 
			Set-OUStructure

			Creates an OU structure in the current domain of the computer using the default setup.

		.NOTES
			The user needs Domain Admin permissions to create OUs in the domain.

			Refer to Forest_OU.json for the correct syntax of the JSON structure.
	#>
	[CmdletBinding(DefaultParameterSetName="Json")]
	Param (
		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="Json")]
		[System.String]$OUStructureJson = [System.String]::Empty,

		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="File",Mandatory=$true)]	
		[ValidateScript({Test-Path -Path $_})]	
		[System.String]$FilePath
	)

	Begin {		
	}

	Process {
		$TopLevelDomain = Get-ADDomain -Current LocalComputer | Select-Object -ExpandProperty DistinguishedName

		switch($PSCmdlet.ParameterSetName) {
			"Json" {
				if ([System.String]::IsNullOrEmpty($OUStructureJson)) {
					$OUStructureJson = @"
[
	{
		"Label" : "Privileged Resources",
		"Children" : [
			{
				"Label" : "User Resources",
				"Children" : [
					{
						"Label" : "Users",
						"Children" : []
					},
					{
						"Label" : "User Groups",
						"Children" : []
					},
					{
						"Label" : "Workstations",
						"Children" : []
					},
					{
						"Label" : "Resource Groups",
						"Children" : []
					},
					{
						"Label" : "Service Accounts",
						"Children" : []
					}
				]
			},
			{
				"Label" : "Server Resources",
				"Children" : [
					{
						"Label" : "Windows Servers",
						"Children" : []
					},
					{
						"Label" : "Linux Servers",
						"Children" : []
					},
					{
						"Label" : "Non-Windows Computer Objects",
						"Children" : []
					},
					{
						"Label" : "Resource Groups",
						"Children" : []
					}			
				]
			}
		]
	},
	{
		"Label" : "Operations",
		"Children" : [
			{
				"Label" : "User Resources",
				"Children" : [
					{
						"Label" : "Users",
						"Children" : []
					},
					{
						"Label" : "User Groups",
						"Children" : []
					},
					{
						"Label" : "Workstations",
						"Children" : []
					},
					{
						"Label" : "Resource Groups",
						"Children" : []
					},
					{
						"Label" : "Service Accounts",
						"Children" : []
					}
				]
			},
			{
				"Label" : "Server Resources",
				"Children" : [
					{
						"Label" : "Windows Servers",
						"Children" : []
					},
					{
						"Label" : "Linux Servers",
						"Children" : []
					},
					{
						"Label" : "Non-Windows Computer Objects",
						"Children" : []
					},
					{
						"Label" : "Resource Groups",
						"Children" : []
					}			
				]
			}
		]
	}
]
"@
				}

				break
			}
			"File" {
				$OUStructureJson = Get-Content -Path $FilePath -Raw
				break
			}
			default {
				throw "Could not determine parameter set for New-OUStructure"
			}
		}

		try
		{
			$OUStructure = ConvertFrom-Json -InputObject $OUStructureJson
		}
		catch [Exception] 
		{
			throw $_.Exception
		}

		$NewOUs = @()

		foreach ($OU in $OUStructure) 
		{
			$NewOUs += New-RecursiveOUStructure -Name $OU.Label -Path $TopLevelDomain -Children $OU.Children
		}

		Write-Output -InputObject $NewOUs
	}

	End {		
	}
}

Function New-RecursiveOUStructure {
	<#
		.SYNOPSIS
			Creates an OU structure recursively.

		.DESCRIPTION
			The cmdlet takes a name of a new OU, the path where it should be created, and any child OUs it should have. It creates the OU, and then calls itself for each defined child OU. All of the created OUs are returned
			in an array. If the OU happens to already exist, the existing OU is added to the array and the children continue to be processed.

		.PARAMETER Name
			The name of the new OU to create.

		.PARAMETER Path
			The parent path of where the new OU should be created. This is a Distinguished Name.

		.PARAMETER Children
			An array of OU objects to be created under this OU. Each Child object requires a Label property as its name and can have a Children property for additional nested OUs.

		.INPUTS
			System.String
		
		.OUTPUTS
			Microsoft.ActiveDirectory.Management.ADOrganizationalUnit[]

		.EXAMPLE 
			New-RecursiveOUStructure -Name "Privileged Resources" -Path "DC=admin,DC=local" -Children @(@{Label = "User Resources"; Children = @(@{Label = "Users"; Children = @()})})

			Creates an OU structure in the current domain of the computer. The Privileged Resources OU is created under admin.local. Then the User Resources OU is created under Privileged Resources, and the Users OU is created
			under the User Resources OU.

		.NOTES
			The user needs Domain Admin permissions to create OUs in the domain.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
		[System.String]$Name,

		[Parameter(Position=1,Mandatory=$true)]
		[System.String]$Path,

		[Parameter(Position=2)]
		[Object[]]$Children
	)

	Begin {		
	}

	Process {
		$NewOUs = @()

		if (![ADSI]::Exists("LDAP://OU=$Name,$Path")) {
			$NewOU = New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true -PassThru
			$NewOUs += $NewOU
		}
		else {
			$NewOU = Get-ADOrganizationalUnit -Identity ("OU=$Name,$Path") -Properties DistinguishedName
		}

		if ($Children -ne $null -and $Children.Length -gt 0)
		{
			foreach ($Child in $Children) {
				$NewOUs +=	(New-RecursiveOUStructure -Name $Child.Label -Path $NewOU.DistinguishedName -Children $Child.Children)
			}
		}

		Write-Output -InputObject $NewOUs
	}

	End {		
	}
}

Function Import-ADUsers {
	<#
		.SYNOPSIS
			Imports new Active Directory users from a JSON file.

		.DESCRIPTION
			The cmdlet reads the contents of the JSON file, and creates users based on objects in the file. Any valid user class property can be defined. The path property defaults to the default Users container. If it is
			defined, it should not include the top level domain name, this is appended programmatically from the current domain of the computer running the cmdlet. Additionally, group memberships can be specified using the
			Membership property. 

		.PARAMETER FilePath
			The path to the JSON file containing the users definition.

		.PARAMETER Json
			The JSON string defining the users to be created.

		.PARAMETER DefaultPassword
			Specifies the default password to assign to all the created users that must be changed on first logon. If no password is specified, a strong random password is generated which will need to be manually reset by
			an administrator before the user can logon.

		.PARAMETER EnableLogging
			Specifies if the logging function should be used when running the function.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Import-ADUsers -FilePath "$PSScriptRoot\users.json"

			Creates the users contained in the specified json file with a randomly generated password for each user.

		.NOTES
			Refer to the included Users.json file for syntax.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="File",Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$FilePath,

		[Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName="Json",Mandatory=$true)]
		[System.String]$Json,

		[Parameter(Position=1)]
		[SecureString]$DefaultPassword = $null,

		[Parameter()]
		[switch]$EnableLogging
	)

	Begin {		
	}

	Process {
		if ($PSCmdlet.ParameterSetName -eq "File") {
			$Json = Get-Content -Path $FilePath -Raw
		}

		$Users = ConvertFrom-Json -InputObject $Json

		$Domain = Get-ADDomain -Current LoggedOnUser | Select-Object -Property *
		$TopLevel = $Domain.DistinguishedName
		$UsersContainer = $Domain.UsersContainer
		$Suffix = $Domain.DnsRoot

		[System.String[]]$UserClassProperties = @()

		[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]$Schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()
		[System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]$UserClass = $Schema.FindClass("User")
		$UserClassProperties += $UserClass.MandatoryProperties | Select-Object -ExpandProperty Name
		$UserClassProperties += $UserClass.OptionalProperties | Select-Object -ExpandProperty Name
		$UserClassProperties = $UserClassProperties.ToLower()

		$NotOtherAttrs = @("SamAccountName","GivenName","sn","DisplayName")
		$NotOtherAttrs = $NotOtherAttrs.ToLower()

		foreach ($User in $Users) {
			try {
				if (![System.String]::IsNullOrEmpty($User.GivenName) -and ![System.String]::IsNullOrEmpty($User.sn)) {

					if ([System.String]::IsNullOrEmpty($User.SamAccountName)) {
						$SamAccountName = "$($User.GivenName).$($User.sn)"
					}
					else {
						$SamAccountName = $User.SamAccountName.Trim()
					}

					Write-Host "Processing $SamAccountName."
					if ($EnableLogging) { Write-Log "Processing $SamAccountName." }

					$SamAccountName = if ($SamAccountName.Length -gt 20) { $SamAccountName.Substring(0,20) } else {$SamAccountName}
			
					$Counter = 0
					$TempName = $SamAccountName
					$NameSuffix = [System.String]::Empty

					while ((Get-ADUser -Filter {samAccountName -eq $TempName}) -ne $null) {
						if ($Counter -gt 999) {
							Write-Log "SamAccountName suffix extension exceeded 999, cannot create $($User.SamAccountName) automatically."
							throw "SamAccountName suffix extension exceeded 999, cannot create $($User.SamAccountName) automatically."
						}

						Write-Warning "$TempName already exists."
						if ($EnableLogging) { Write-Log "$TempName already exists." }

						$NameSuffix = $Counter.ToString()

						while ($NameSuffix.Length -lt 3) {
							$NameSuffix = "0" + $NameSuffix				
						}
				
						$TempName = if ($SamAccountName.Length -ge 16) { $SamAccountName.SubString(0,16) + ".$NameSuffix" } else { $SamAccountName + ".$NameSuffix" }

						$Counter++
					}

					Write-Host "Using $TempName for the user."
					if ($EnableLogging) { Write-Log "Using $TempName for the user." }

					$SamAccountName = $TempName

					if (![System.String]::IsNullOrEmpty($User.DisplayName)) {
						$DisplayName = ($User.DisplayName + " " + $NameSuffix)
					}
					else {
						$DisplayName =  "$($User.GivenName) $($User.sn) $NameSuffix"
					}
				
					$OtherAttrs = @{}
				
					foreach ($Property in $User.psobject.Properties) {
						if (!$NotOtherAttrs.Contains($Property.Name.ToLower()) -and $UserClassProperties.Contains($Property.Name.ToLower())) {
							if ($Property.GetType() -eq [System.Array]) {
								$Value = "@(" + ($Property.Value -join ",") + ")"
							}
							else {
								$Value = $Property.Value.ToString()
							}
               
							$OtherAttrs.Add($Property.Name, $Value)
						}
					}
		
					Write-Host "Creating user $SamAccountName"
					if ($EnableLogging) { Write-Log "Creating user $SamAccountName" }

					if ($DefaultPassword -eq $null) {
						$DefaultPassword = New-RandomPassword -EnforceComplexity -AsSecureString
					}

					if ([System.String]::IsNullOrEmpty($User.Path)) {
						$Path = $UsersContainer
					} 
					else {
						$Path = "$($User.Path),$TopLevel"
					}

					try
					{
						$NewUser = New-ADUser -SamAccountName $SamAccountName `
							-DisplayName $DisplayName.Trim() `
							-GivenName $User.GivenName.Trim() `
							-Surname $User.sn.Trim() `
							-UserPrincipalName "$SamAccountName@$Suffix" `
							-Name $DisplayName.Trim() `
							-Path $Path `
							-AccountPassword $DefaultPassword `
							-PassThru
    
						if ($NewUser) {
							Set-ADUser -Identity $NewUser -Replace $OtherAttrs
						}

						foreach ($Group in $User.Membership) {
							Write-Host "Checking $Group to add $SamAccountName."
							if ($EnableLogging) { Write-Log "Checking $Group to add $SamAccountName." }
					
							if ((Get-ADGroup -Filter {name -eq $Group} -ErrorAction SilentlyContinue) -ne $null) {
								try {
									Write-Host "$Group exists, attempting to add $SamAccountName."
									if ($EnableLogging) { Write-Log "$Group exists, attempting to add $SamAccountName." }
									Add-ADGroupMember -Identity $Group -Members $SamAccountName
									Write-Host "Successfully added $SamAccountName to $Group."
									if ($EnableLogging) { Write-Log "Successfully added $SamAccountName to $Group." }
								}
								catch [Exception] {
									Write-Warning $_.Exception.Message
									if ($EnableLogging) { Write-Log $_ }
								}
							}
							else {
								Write-Warning "$Group does not exist."
								if ($EnableLogging) { Write-Log "$Group does not exist." }
							}
						}
					}
					catch [Exception] {
						Write-Warning $_.Exception.Message
						if ($EnableLogging) { Write-Log $_ }
					}
				}
				else {
					Write-Warning "The user object must have at least the GivenName and sn attributes defined."
					if ($EnableLogging) { Write-Log ("The user object must have at least the GivenName and sn attributes defined.`n" + (ConvertFrom-Json -InputObject $User)) }
				}
			}
			catch [Exception] {
				Write-Warning $_.Exception.Message
				if ($EnableLogging) { Write-Log $_ }
			}
		}
	}

	End {
	}
}

#endregion

#region GPO Functions

Function Add-SysvolFiles {
	<#
		.SYNOPSIS
			Extracts the contents of a zip file and places them in the SYSVOL.

		.DESCRIPTION
			The cmdlet takes a source zip file and extracts the contents to a destination. The default destination is the SYSVOL as located from Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty SysVol.
			However, this property is only available on domain controllers, so if the command is run remotely, the SYSVOL destination needs to be explicitly set.

		.PARAMETER ZipFilePath
			The path to the source zip file. This defaults to $PSScriptRoot\SysvolFiles.zip.

		.PARAMETER Destination
			The location where the zip file should be extracted to. This defaults to the SYSVOL when run on a domain controller.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Add-SysvolFiles

			Extracts the contents of $PSScriptRoot\SysvolFiles.zip to the SYSVOL directory of the current forest root domain of the computer the cmdlet is being run on.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path -Path $_})]		
		[System.String]$ZipFilePath = $script:SysvolFiles,

		[Parameter(Position=1)]
		[System.String]$Destination = [System.String]::Empty
	)

	Begin {		
	}

	Process {
		$ForestRootDomainName = Get-ADForest -Current LocalComputer | Select-Object -ExpandProperty Name

		if ([System.String]::IsNullOrEmpty($Destination)) {
			$SYSVOL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty SysVol
			$Destination = "$SYSVOL\$ForestRootDomainName\files"
		}

		Write-Log "Extracting $ZipFilePath to $Destination"
		Extract-ZipFile -Source $ZipFilePath -Destination $Destination
	}

	End {
	}
}

Function Set-GPPMigrationValues {
	<#
		.SYNOPSIS
			The cmdlet updates the values in Group Policy Preferences to replace any references of the source domain with the destination domain.

		.DESCRIPTION
			The cmdlet examines each GPO backup in the backup directory specified and searches GPPs for references to the source domain. It replaces any found matches with the forest root domain name.

		.PARAMETER BackupRootDirectory
			The top level folder containing GPO backups.

		.PARAMETER SourceDomain
			The name of the domain where the GPO backups were originated from. This defaults to admin.local.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Set-GPPMigrationValues -BackupRootDirectory "c:\gpobackups"

			Replaces all references of admin.local in GPO backups located in c:\gpobackups for GPPs.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]	
		[ValidateScript({Test-Path -Path $_})]	
		[System.String]$BackupRootDirectory,

		[Parameter(Position=1)]
		[System.String]$SourceDomain = "admin.local"
	)

	Begin {
		try {
			Import-Module GroupPolicy
		}
		catch [Exception] {
			throw "The GroupPolicy module must be installed to use this cmdlet."
		}				
	}

	Process {
		if ([System.String]::IsNullOrEmpty($SourceDomain)) {
			$SourceDomain = "admin.local"
		}

		$ForestRootDomainName = Get-ADForest -Current LocalComputer | Select-Object -ExpandProperty Name
		$Netbios = $ForestRootDomainName.Substring(0, $ForestRootDomainName.IndexOf("."))

		if ($SourceDomain.Contains(".")) {
			$SourceNetbios = $SourceDomain.Substring(0, $SourceDomain.IndexOf("."))
		}
		else {
			throw "The source domain name was not properly formatted."
		}

		$Directories = Get-ChildItem -Path $BackupRootDirectory -Recurse -Directory | Select-Object -ExpandProperty FullName

		foreach ($Directory in $Directories)
		{
			[Microsoft.GroupPolicy.BackupDirectory]$BackupDirectory = New-Object Microsoft.GroupPolicy.BackupDirectory($Directory, [Microsoft.GroupPolicy.BackupType]::Gpo)
            [Microsoft.GroupPolicy.GPSearchCriteria]$SearchCriteria = New-Object Microsoft.GroupPolicy.GPSearchCriteria
            $SearchCriteria.Add([Microsoft.GroupPolicy.SearchProperty]::MostRecentBackup, [Microsoft.GroupPolicy.SearchOperator]::Equals, $true)
            [Microsoft.GroupPolicy.GpoBackupCollection]$Backups = $BackupDirectory.SearchGpoBackups($SearchCriteria)

			if ($Backups -ne $null -and $Backups.Count -gt 0)
			{
				foreach($Backup in $Backups)
				{
					$Items = @()
					$MachineGPP = [System.IO.Path]::Combine($Backup.BackupDirectory, "DomainSysvol", "GPO", "Machine", "Preferences")
					$UserGPP = [System.IO.Path]::Combine($Backup.BackupDirectory, "DomainSysvol", "GPO", "User", "Preferences")
					$Netbios = $ForestRootDomainName.Substring(0, ([System.Math]::Min($ForestRootDomainName.IndexOf("."), 15)))

					if (Test-Path -Path $MachineGPP) {
						$Items += Get-ChildItem -Path $MachineGPP -File
					}

					if (Test-Path -Path $UserGPP) {
						$Items += Get-ChildItem -Path $UserGPP -File
					}

					foreach($Item in $Items) {
						$StrContent = Get-Content -Path $Item.FullName -Raw

						$StrContent = $StrContent -replace $SourceDomain,$ForestRootDomainName #Replace any reference of the default domain name
						$StrContent = $StrContent -replace "\b@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b","@$Netbios" #Replace any UPN type entries
						$Strcontent = $StrContent -replace ([System.Text.RegularExpressions.Regex]::Escape("$SourceNetbios\")),("$Netbios\")

						Set-Content -Value $StrContent -Path $Item.FullName
					}
				}
			}
		}
	}

	End {
	}
}

Function New-GPOMigrationTable {
	<#
		.SYNOPSIS
			The cmdlet creates a GPO migration table to replace any references with the source domain of the GPO backups with the destination domain.

		.DESCRIPTION
			The cmdlet creates a GPO migration table to replace any references with the source domain of the GPO backups with the destination domain.

		.PARAMETER BackupRootDirectory
			The top level folder containing GPO backups.

		.PARAMETER SourceDomain
			The name of the domain where the GPO backups were originated from. This defaults to admin.local.

		.PARAMETER DestinationDomain
			The name of the new domain where the GPOs will be imported. This defaults to the forest root domain of the computer running the cmdlet.

		.INPUTS
			System.String
		
		.OUTPUTS
			System.String
			The migration table path.

		.EXAMPLE 
			New-GPOMigrationTable -BackupRootDirectory "c:\gpobackups"

			Creates a migration table for all of the gpo backups in the c:\gpobackups folder.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path -Path $_})]		
		[System.String]$BackupRootDirectory,

		[Parameter(Position=1)]
		[System.String]$DestinationDomain = [System.String]::Empty,

		[Parameter(Position=2)]
		[ValidateScript({$_.Contains(".")})]
		[System.String]$SourceDomain = "admin.local"
	)

	Begin {
		try {
			Import-Module GroupPolicy
		}
		catch [Exception] {
			throw "The GroupPolicy module must be installed to use this cmdlet."
		}
	}

	Process {
		if ([System.String]::IsNullOrEmpty($DestinationDomain)) {
			$ForestRootDomainName = Get-ADForest -Current LocalComputer | Select-Object -ExpandProperty Name
		}
		else {
			$ForestRootDomainName = $DestinationDomain
		}

		if ($ForestRootDomainName.Contains(".")) {
			$Netbios = $ForestRootDomainName.Substring(0, $ForestRootDomainName.IndexOf("."))
		}
		else {
			throw "The destination domain name was not properly formatted."
		}

		$GPM = New-Object -ComObject GPMgmt.GPM
		$Constants = $GPM.GetConstants()

		if ([System.String]::IsNullOrEmpty($SourceDomain)) {
			$SourceDomain = "admin.local"
		}
		
		$MigrationTable = New-Object Microsoft.GroupPolicy.GPMigrationTable
		$Directories = Get-ChildItem -Path $BackupRootDirectory -Recurse -Directory | Select-Object -ExpandProperty FullName

		foreach ($Directory in $Directories)
		{
			[Microsoft.GroupPolicy.BackupDirectory]$BackupDirectory = New-Object Microsoft.GroupPolicy.BackupDirectory($Directory, [Microsoft.GroupPolicy.BackupType]::Gpo)
            [Microsoft.GroupPolicy.GPSearchCriteria]$SearchCriteria = New-Object Microsoft.GroupPolicy.GPSearchCriteria
            $SearchCriteria.Add([Microsoft.GroupPolicy.SearchProperty]::MostRecentBackup, [Microsoft.GroupPolicy.SearchOperator]::Equals, $true)
            [Microsoft.GroupPolicy.GpoBackupCollection]$Backups = $BackupDirectory.SearchGpoBackups($SearchCriteria)

			if ($Backups -ne $null -and $Backups.Count -gt 0)
			{
				foreach($Backup in $Backups)
				{
					$MigrationTable.Add($Backup, $false)
				}
			}
		}

		foreach($Entry in $MigrationTable.GetEntries()) {
			Write-Host $Entry.Source
			switch ($Entry.EntryType) {
				$Constants.EntryTypeUNCPath {
					Write-Host "UNC Path."
					if ($Entry.Source -like ".*$SoureDomain.*") {
						$MigrationTable.UpdateDestination($Entry.Source, ($Entry.Source -replace $SourceDomain,$ForestRootDomainName)) | Out-Null

						$UpdatedEntry = $MigrationTable.GetEntry($Entry.Source)
						Write-Host "Updated UNC Path Entry $($Entry.Source) to $($UpdatedEntry.Destination)"
					}
					break
				}
				{$_ -in $Constants.EntryTypeUser, $Constants.EntryTypeGlobalGroup, $Constants.EntryTypeUnknown} {
					Write-Host "User, Global Group, or Unknown."
					if ($Entry.Source -match "\b@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b") {
						$MigrationTable.UpdateDestination($Entry.Source, ($Entry.Source -replace "\b@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b","@$ForestRootDomainName")) | Out-Null

						$UpdatedEntry = $MigrationTable.GetEntry($Entry.Source)
						Write-Host "Updated User/Global Group/Unknown Entry $($Entry.Source) to $($UpdatedEntry.Destination)"
					}
					break
				}
				{$_ -in $Constants.EntryTypeUniversalGroup} {
					Write-Host "Universal Group"
					if ($Entry.Source -match "\b@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b") {
						$MigrationTable.UpdateDestination($Entry.Source, ($Entry.Source -replace "\b@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b","@$ForestRootDomainName")) | Out-Null

						$UpdatedEntry = $MigrationTable.GetEntry($Entry.Source)
						Write-Host "Updated Universal Group Entry $($Entry.Source) to $($UpdatedEntry.Destination)"
					}
					break
				}
			}
		}

		$MigrationTablePath = [System.IO.Path]::Combine($PSScriptRoot,"MigrationTable.migtable")
        $MigrationTable.Save($MigrationTablePath)

        Write-Output -InputObject $MigrationTablePath
	}

	End {
	}
}

Function New-GPOLinks {
	<#
		.SYNOPSIS
			The cmdlet creates GPO links for existing GPOs to specified OUs.

		.DESCRIPTION
			The cmdlet processes an inputted json file that defines the GPOs and where each one should be linked. If the GPO or destination for the link does not exist it is ignored.

		.PARAMETER LinksFilePath
			The path to the json file containing the link information. The OU property of each link object should not include the top level domain, this is generated programmatically. Leave the property blank to link the GPO
			to the domain. The GPO property is the name of the GPO, these are matched with an implicit wildcard at the end of the name, so multiple GPOs can be linked with just one definition.

			You must define the GPO and Path. You can optionally define "Enforced" as "Yes" or "No" and optionally define "Order" as an integer value.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			New-GPOLinks -LinksFilePath "$PSScriptRoot\Forest_GPLinks.json"

			Links all of the GPOs defined in the Forest_GPLinks.json file.

		.NOTES
			Refer to the Forest_GPLinks.json or ESAE_GPLinks.json file for correct syntax.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true, Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$LinksFilePath
	)

	Begin {
		try {
			Import-Module GroupPolicy
		}
		catch [Exception] {
			Write-Log "The group policy module is required to run this command."
			throw $_.Exception
		}
	}

	Process {
		if (!(Test-Path -Path $LinksFilePath)) {
			throw [System.IO.FileNotFoundException]("$LinksFilePath could not be found.")
		}

		$Links = ConvertFrom-Json -InputObject (Get-Content -Path $LinksFilePath -Raw)

		$DnsName = Get-ADForest -Current LocalComputer | Select-Object -ExpandProperty Name
		$TopLevelDomain = Get-ADDomain -Identity $DnsName | Select-Object -ExpandProperty DistinguishedName

		[Object[]]$AllGPOs = Get-GPO -All

		foreach ($Link in $Links) {
			Write-Host "Processing GPOs that match $($Link.GPO)"
			Write-Log "Processing GPOs that match $($Link.GPO)"

			$Subset = $AllGPOs | Where-Object {$_.DisplayName -like "$($Link.GPO)*"}
			
			if($Link.Enforced -eq $null) {
				$Enforced = "No"
			}
			else {
				$Enforced = $Link.Enforced
			}

			if ([System.String]::IsNullOrEmpty($Link.OU)) {
				$Target = $TopLevelDomain
			}
			else {
				$Target = "$($Link.OU),$TopLevelDomain"
			}

			if ($Subset.Length -gt 0) {
				foreach($Item in $Subset) {
					try {
						Write-Host "Linking $($Item.DisplayName) to $Target."
						Write-Log "Linking $($Item.DisplayName) to $Target."

						if ($Link.Order -ne $null) {
							New-GPLink -Guid $Item.Id -Target $Target -LinkEnabled Yes -Enforced $Enforced -Order $Link.Order -Server $env:COMPUTERNAME -Domain $DnsName
						}
						else {
							New-GPLink -Guid $Item.Id -Target $Target -LinkEnabled Yes -Enforced $Enforced -Server $env:COMPUTERNAME -Domain $DnsName
						}
					}
					catch [Exception] {
						Write-Warning $_.Exception.Message
						Write-Log $_
					}
				}
			}
			else {
				Write-Warning "The GPO $($Link.GPO) does not exist in the domain and could not be linked to $($Link.OU)."
				Write-Log "The GPO $($Link.GPO) does not exist in the domain and could not be linked to $($Link.OU)."
			}
		}

		Write-Host "Completed linking GPOs."
		Write-Log -Message "Completed linking GPOs."
	}

	End {		
	}
}

#endregion

#region Forest Trusts

Function New-ADForestTrust {
	<#
		.SYNOPSIS
			The cmdlet builds a forest trust between two forests.

		.DESCRIPTION
			The cmdlet creates a forest trust between two forests and configures settings associated with the trust. The command will remove existing trust objects with the same name if they are discovered. Because the 
			Microsoft function for trusts only checks the NetBIOS name when it checks for existence, a trust for another forest could inadvertently be removed. For example, if the local forest is admin.local and the remote 
			forest has a trust to admin.com, building the trust would fail.

		.PARAMETER LocalForest
			The name of the local forest where the cmdlet is being run. This defaults to the forest root domain of the computer running the cmdlet.

		.PARAMETER RemoteForest
			The name of the remote forest where the trust will connect.

		.PARAMETER TrustDirection
			The direction of the forest trust in relation to the server the cmdlet is being run on. This defaults to Inbound (the remote forest trusts the local forest). This can be Inbound, Outbound, or Bidirectional.

		.PARAMETER LocalForestCredential
			The credential to use to setup the local side of the trust. The credential should have Enterprise Admin rights and defaults to the user running the cmdlet.

		.PARAMETER RemoteForestCredential
			The credential to use to setup the remote side of the trust. The credential should have Enterprise Admin rights in the remote forest.

		.PARAMETER EnableSelectiveAuthentication
			Specify whether selective authentication is enabled or not. This defaults to true.

		.PARAMETER SidFilteringEnabled
			Specify whether SID filtering is enabled or not. This defaults to true.

		.PARAMETER CreateLocalConditionalForwarder
			Specifies whether to create a DNS conditional forwarder in the local forest in order to resolve the remote forest DNS name.

		.PARAMETER RemoteForestMasterServers
			The IP addresses of the remote forest DNS servers that the local conditional forwarder will point to. This is required if the CreateLocalConditionalForwarder is specified.

		.PARAMETER CreateRemoteConditionalForwarder
			Specifies whether to create a DNS conditional forwarder in the remote forest in order to resolve the local forest DNS name.

		.PARAMETER TrustingDomainSupportsKerberosAESEncryption
			Specifies whether the trusting domain supports Kerberos AES Encryption. This defaults to true.

		.PARAMETER EnableLogging
			Specify if the module logging function should be used when running the cmdlet.

		.PARAMETER WaitForRpcSs
			Specify whether to wait for the RPCSS service to be available on the local server before creating the DNS settings. The RPCSS service is sometime not available immediately after a reboot when the cmdlet is being
			run as a scheduled task and the DNS configuration fails.

		.INPUTS
			None
		
		.OUTPUTS
			None

		.EXAMPLE 
			New-ADForestTrust -RemoteForest "contoso.com" -RemoteForestCredential (Get-Credential) -CreateLocalConditionalForwarder -CreateRemoteConditionalForwarder -RemoteForestMasterServers @("192.168.2.1") -WaitForRpcSs

			Creates conditional forwarders in both the remote and local forest and establishes and inbound forest trust.

		.NOTES
			None
	#>
	[CmdletBinding(DefaultParameterSetName="None")]
	Param(
		[Parameter(Position=1)]
		[System.String]$LocalForest = [System.String]::Empty,

		[Parameter(Position=0, Mandatory=$true)]
		[System.String]$RemoteForest,

		[Parameter(Position=2)]
		[System.DirectoryServices.ActiveDirectory.TrustDirection]$TrustDirection = [System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound,

		[Parameter(Position=3)]
		[PSCredential]$LocalForestCredential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(Position=4,Mandatory=$true)]
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$RemoteForestCredential,

		[Parameter(Position=5)]
		[bool]$EnableSelectiveAuthentication = $true,

		[Parameter(Position=6)]
		[bool]$SidFilteringEnabled = $true,

		[Parameter(Position=7,ParameterSetName="StubZone")]
		[switch]$CreateLocalConditionalForwarder = $false,

		[Parameter(Position=8,ParameterSetName="StubZone",Mandatory=$true)]
		[System.String[]]$RemoteForestMasterServers,

        [Parameter(Position=9)]
        [switch]$CreateRemoteConditionalForwarder = $false,

        [Parameter(Position=10)]
        [bool]$TrustingDomainSupportsKerberosAESEncryption = $true,

		[Parameter(Position=11)]
		[switch]$EnableLogging,

		[Parameter(Position=12)]
		[switch]$WaitForRpcSs
	)

	Begin {		
	}

	Process {
		if ([System.String]::IsNullOrEmpty($LocalForest)) {
			$LocalForest = (Get-ADForest -Current LoggedOnUser).DnsRoot
		}

		if ($CreateLocalConditionalForwarder -and $RemoteForestMasterServers.Count -lt 1) {
			if ($EnableLogging) { Write-Log "The create local conditional forwarder parameter was specified, but no remote master servers were specified." }
			throw "The create local conditional forwarder was specified, but no remote master servers were specified."
		}

		if ($LocalForestCredential -ne $null -and $LocalForestCredential -ne [PSCredential]::Empty) {
            try
			{
				[System.DirectoryServices.ActiveDirectory.DirectoryContext]$LocalForestContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest, $LocalForest, $LocalForestCredential.UserName, (Convert-SecureStringToString -SecureString $LocalForestCredential.Password))
				[System.DirectoryServices.ActiveDirectory.Forest]$LocalForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($LocalForestContext)
			}
			catch [Exception] {
				Write-Warning $_.Exception
				if ($EnableLogging) { Write-Log $_ }
				throw $_.Exception
			}
		}
		else {
			try {
				[System.DirectoryServices.ActiveDirectory.Forest]$LocalForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
			}
			catch [Exception] {
				Write-Warning $_.Exception
				if ($EnableLogging) { Write-Log $_ }
				throw $_.Exception
			}
		}

		$Continue = $true
		
		if ($CreateLocalConditionalForwarder) {
			try {
				if ((Test-RpcAvailability -ComputerName $LocalForest.Name -EnableLogging -Wait:$WaitForRpcSs)) {

					Write-Host "RPC available, testing for the stub zone existing already."
					if ($EnableLogging) { Write-Log "RPC available, testing for the stub zone existing already." }

					if ((Get-DnsServerZone -Name $RemoteForest -ErrorAction SilentlyContinue) -eq $null) {
						Write-Host "Zone does not exist, creating conditional forwarder for remote forest $RemoteForest."
						if ($EnableLogging) { Write-Log "Zone does not exist, creating conditional forwarder for remote forest $RemoteForest." }

						try 
						{						
							$Counter = 0
							while ($true) {
								try {
									Add-DnsServerConditionalForwarderZone -Name $RemoteForest -MasterServers $RemoteForestMasterServers -ReplicationScope Forest -ComputerName $LocalForest.Name
									Write-Host "Conditional forwarder $RemoteForest successfully created."
									if ($EnableLogging) { Write-Log "Conditional forwarder $RemoteForest successfully created." }
									break
								}
								catch [Exception] {
									if ($Counter -gt 10) {
										throw $_.Exception
									}
									else {										
										Write-Warning "Failed to create conditional forwarder on attempt $($Counter + 1)."
										Write-Warning "$($_.Exception.Message)"
										if ($EnableLogging) { Write-Log "Failed to create conditional forwarder on attempt $($Counter + 1)."}
										if ($EnableLogging) { Write-Log $_ }
										$Counter++
										Start-Sleep -Seconds 10
									}
								}
							}
						}
						catch [Exception] {
							Write-Warning $_.Exception.Message
							if ($EnableLogging) { Write-Log $_ }
						}
					}
					else {
						Write-Warning "Zone $RemoteForest already exists."
						if ($EnableLogging) { Write-Log "Zone $RemoteForest already exists."}
					}
				}
				else {
					if ($EnableLogging) { Write-Log "RpcSs service not available on $($LocalForest.Name)."}
					throw "RpcSs service not available on $($LocalForest.Name)."
				}
			}
			catch [Exception] {
				Write-Warning $_.Exception.Message
				if ($EnableLogging) { Write-Log $_ }
				$Continue = $false
			}
		}

		try {
			Write-Host "Ensuring the remote forest name provided is actually the forest root."
			if ($EnableLogging) { Write-Log "Ensuring the remote forest name provided is actually the forest root." }
			$RemoteForest = (Get-ADDomain -Identity $RemoteForest -Credential $RemoteForestCredential).Forest
			Write-Host "Forest root is $RemoteForest."
			if ($EnableLogging) { Write-Log "Forest root is $RemoteForest." }
		}
		catch [Exception] {
			Write-Warning $_.Exception.Message
			if ($EnableLogging) { Write-Log "Error getting forest root."}
			if ($EnableLogging) { Write-Log $_ }
			$Continue = $false
		}

        if ($CreateRemoteConditionalForwarder -and $Continue) {
            try
            {
				$Servers = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$RemoteForest" -Type SRV | Where-Object {$_.Type -eq "SRV"} | Select-Object -ExpandProperty NameTarget 
				$RemoteServer = [System.String]::Empty

				foreach ($Server in $Servers) {
					Write-Host "Testing connection to $Server."
					if ($EnableLogging) { Write-Log "Testing connection to $Server." }
					if (Test-Connection -ComputerName $Server -Quiet) {
						Write-Host "Successfully connected to $Server."
						if ($EnableLogging) { Write-Log "Successfully connected to $Server." }
						$RemoteServer = $Server
						break
					}
					else {
						Write-Warning "Could not connect to $Server."
						if ($EnableLogging) { Write-Log "Could not connect to $Server." }
					}
				}

				if (![System.String]::IsNullOrEmpty($RemoteServer)) {

					Write-Host "Creating conditional forwarder in remote forest on server $RemoteServer."
					if ($EnableLogging) { Write-Log "Creating conditional forwarder in remote forest on server $RemoteServer."}
					Write-Host "Getting list of master servers in $($LocalForest.Name) to create in remote forest conditional forwarder."
					if ($EnableLogging) { Write-Log "Getting list of master servers in $($LocalForest.Name) to create in remote forest conditional forwarder." }
					$LocalMasterServers = @()

					Resolve-DnsName -Name $LocalForest.Name -Type NS | Where-Object {![System.String]::IsNullOrEmpty($_.NameHost)} | Select-Object -ExpandProperty NameHost | ForEach-Object {
						$LocalMasterServers += Resolve-DnsName -Name $_ -Type A | Select-Object -ExpandProperty IPAddress
					}

					Write-Host ("Master Servers: " + ($LocalMasterServers -join " "))
					if ($EnableLogging) { Write-Log ("Master Servers: " + ($LocalMasterServers -join " ")) }

					#Create DNS StubZone for Trusting Forest so it can identify the trusted forest
					Write-Host "Creating remote conditional forwarder pointing to the $($LocalForest.Name)."
					if ($EnableLogging) { Write-Log "Creating remote conditional forwarder pointing to $($LocalForest.Name)." }

					Write-Host "Connecting to $RemoteServer."
					if ($EnableLogging) { Write-Log "Connecting to $RemoteServer." }

					if (Test-Connection -ComputerName $RemoteServer -Quiet) {
				
						$Session = New-PSSession -ComputerName $RemoteServer -Credential $RemoteForestCredential -ErrorAction Stop

						$Result = Invoke-Command -Session $Session -ScriptBlock {
							$Zone = Get-DnsServerZone -Name $args[0] -ErrorAction SilentlyContinue
							if ($Zone -eq $null) {
								$Zone = Add-DnsServerConditionalForwarderZone -Name $args[0] -MasterServers $args[1] -ReplicationScope Forest -PassThru

								Write-Output $Zone
							}
							else {
								switch ($Zone.Type) {
									"Forwarder" {
										$Zone = Set-DnsServerConditionalForwarderZone -Name $args[0] -MasterServers $args[1] -PassThru
										break
									}
									"Stub" {
										$Zone = Set-DnsServerStubZone -Name $args[0] -MasterServers $args[1] -PassThru
										break
									}
									default {
										break
									}
								}

								Write-Output $Zone

							}
						} -ErrorVariable ErrResult -ArgumentList @($LocalForest.Name, $LocalMasterServers)

						Remove-PSSession -Session $Session

						if ($ErrResult -ne $null -and $ErrResult.Count -gt 0) {
							$Err = $ErrResult[0]
							throw $Err.Exception
						}
						else {
							Write-Host "Successfully created remote forest conditional forwarder."
							Write-Host ($Result | Format-List)
							if ($EnableLogging) { Write-Log "Successfully created remote forest conditional forwarder."}
							if ($EnableLogging) { Write-Log ($Result | Format-List | Out-String) }
						}
					}
					else {
						Write-Warning ("Could not connect to $RemoteServer.")
						if ($EnableLogging) { Write-Log "Could not connect to $RemoteServer." }
						$Continue = $false
					}
				}
				else {
					Write-Warning "Could not connect to any servers resolved from DNS."
					if ($EnableLogging) { "Could not connect to any servers resolved from DNS." }
					$Continue = $false
				}
			}
			catch [Exception] {
				Write-Warning $_.Exception.Message
				if ($EnableLogging) { Write-Log $_ }
				$Continue = $false
			}
		}
		
		if ($Continue) {
			try {
				#Now that the local conditional forwarder exists and the DC can resolve the other domain name, build the remote forest context items
	
				try {
					[System.DirectoryServices.ActiveDirectory.DirectoryContext]$RemoteForestContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest, $RemoteForest, $RemoteForestCredential.UserName, (Convert-SecureStringToString -SecureString $RemoteForestCredential.Password))
					[System.DirectoryServices.ActiveDirectory.Forest]$RemoteForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($RemoteForestContext)
				}
				catch [Exception] {
					Write-Warning $_.Exception.Message
					if ($EnableLogging) { Write-Log $_ }
					throw $_.Exception
				}

				$LocalNetbios = $LocalForest.Name.Substring(0, $LocalForest.Name.IndexOf("."))
				$RemoteNetbios = $RemoteForest.Name.Substring(0, $RemoteForest.Name.IndexOf("."))

				#Assume trust exists on the far side and prove otherwise
				$RemoteExists = $true
				if ($EnableLogging) { Write-Log "Testing for remote trust existence."}

				try {
					$RemoteTrust = Get-ADForestTrustRelationship -TargetForestName $LocalNetbios -CurrentForest $RemoteForest
					if ($RemoteTrust -eq $null) {
						$RemoteExists = $false
					}
					else {
						$RemoteExists = $true
					}
				}
				catch [Exception] {
					Write-Warning $_.Exception.Message
					if ($EnableLogging) { Write-Log $_ }
				}

				Write-Host "Remote trust exists: $RemoteExists for Netbios $LocalNetbios."
				if ($EnableLogging) { Write-Log "Remote trust exists: $RemoteExists for Netbios $LocalNetbios"}

				#Assume the local trust exists and prove otherwise
				$LocalExists = $true
				if ($EnableLogging) { Write-Log "Testing for local trust existence."}

				try {
					$LocalTrust = Get-ADForestTrustRelationship -TargetForestName $RemoteNetbios -CurrentForest $LocalForest

					if ($LocalTrust -eq $null) {
						$LocalExists = $false
					}
					else {
						$LocalExists = $true
					}
				}
				catch [Exception] {
					Write-Warning $_.Exception.Message
					if ($EnableLogging) { Write-Log $_ }
				}

				Write-Host "Local trust exists: $LocalExists"
				if ($EnableLogging) { Write-Log "Local trust exists: $LocalExists"}

				if ($RemoteExists -and $LocalExists) {
					Write-Host "Deleting existing trust relationship."
					if ($EnableLogging) { Write-Log "Deleting existing trust relationship."}					
					$Counter = 0

					while ($true) {
						try {
							$LocalForest.DeleteTrustRelationship($RemoteForest)
							Write-Host "Successfully deleted existing trust relationship."
							if ($EnableLogging) { Write-Log "Successfully deleted existing trust relationship."}
							break
						}
						catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
							Write-Warning $_.Exception.Message
							if ($EnableLogging) { Write-Log $_ }
							throw $_.Exception
						}	
						catch [Exception] {
							if ($Counter -gt 60) {
								throw $_.Exception
							}
							else {
								if ($EnableLogging) { Write-Log "Failed to delete the trust on attempt $($Counter + 1)."}
								if ($EnableLogging) { Write-Log $_ }
								Start-Sleep -Seconds 10
								$Counter++
							}
						}	
					}
				}

				if ($RemoteExists -and !$LocalExists) {
					Write-Host "Deleting local side of remote forest trust in relation to the remote forest."
					if ($EnableLogging) { Write-Log "Deleting local side of remote forest trust in relation to the remote forest."}
					$Counter = 0

					while ($true) {
						try {
							$RemoteForest.DeleteLocalSideOfTrustRelationship($LocalNetbios)
							Write-Host "Successfully deleted local side of remote forest trust."
							if ($EnableLogging) { Write-Log "Successfully deleted local side of remote forest trust."}
							break
						}
						catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
							Write-Warning $_.Exception.Message
							if ($EnableLogging) { Write-Log $_ }
							throw $_.Exception
						}
						catch [Exception] {
							if ($Counter -gt 60) {
								throw $_.Exception
							}
							else {
								if ($EnableLogging) { Write-Log "Failed to delete the trust on attempt $($Counter + 1)."}
								if ($EnableLogging) { Write-Log $_ }
								Start-Sleep -Seconds 10
								$Counter++
							}
						}	
					}
				}

				if (!$RemoteExists -and $LocalExists) {
					Write-Host "Deleting local side of local forest trust."
					if ($EnableLogging) { Write-Log "Deleting local side of local forest trust."}
					$Counter = 0	

					while ($true) {
						try {
							$LocalForest.DeleteLocalSideOfTrustRelationship($RemoteNetbios)
							Write-Host "Successfully deleted local side of local forest trust."
							if ($EnableLogging) { Write-Log "Successfully deleted local side of local forest trust."}
							break
						}
						catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
							Write-Warning $_.Exception.Message
							if ($EnableLogging) { Write-Log $_ }
							throw $_.Exception
						}
						catch [Exception] {
							if ($Counter -gt 60) {
								throw $_.Exception
							}
							else {
								if ($EnableLogging) { Write-Log "Failed to delete the trust on attempt $($Counter + 1)."}
								if ($EnableLogging) { Write-Log $_ }
								Start-Sleep -Seconds 10
								$Counter++
							}
						}	
					}
				}

				Write-Host "Creating trust relationship between $($LocalForest.Name) and $($RemoteForest.Name) in the direction of $($TrustDirection.ToString())."
				if ($EnableLogging) { Write-Log "Creating trust relationship between $($LocalForest.Name) and $($RemoteForest.Name) in the direction of $($TrustDirection.ToString())."}

				$LocalForest.CreateTrustRelationship($RemoteForest, $TrustDirection)

				Write-Host "Trust creation completed, verifying trust."
				if ($EnableLogging) { Write-Log "Trust creation completed, verifying trust."}

				$LocalForest.VerifyTrustRelationship($RemoteForest, $TrustDirection)

				Write-Host "Trust creation verified."
				if ($EnableLogging) { Write-Log "Trust creation verified."}

				try {
					if ($EnableLogging) { Write-Log "Setting Forest Trust selective authentication."}
					Set-ADForestTrustSelectiveAuthentication -TrustDirection $TrustDirection -LocalForest $LocalForest -RemoteForest $RemoteForest -SelectiveAuthenticationEnabled $true -EnableLogging
				}
				catch [Exception] {
					Write-Warning $_.Exception.Message
					if ($EnableLogging) { Write-Log $_ }
					$Continue = $false
				}

				Write-Host "Setting SID Filtering."
				if ($EnableLogging) { Write-Log "Setting SID Filtering." }

				switch ($TrustDirection) {
					#Inbound trust means that the remote forest trusts the local forest
					([System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound) {
						Write-Host "Inbound trust, setting SID filtering on remote forest."
						if ($EnableLogging) { Write-Log "Inbound trust, setting SID filtering on remote forest."}
						
						Set-ADForestTrustSIDFiltering -TrustingForest $RemoteForest -TrustedForest $LocalForest.Name -SidFilteringEnabled $SidFilteringEnabled -EnableLogging:$EnableLogging
							
						Write-Host "Completed enabling SID filtering."
						if ($EnableLogging) { Write-Log "Completed enabling SID filtering."}
						break
					}
					#Outbound trust means that the local forest trusts the remote forest
					([System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound) {
						Write-Host "Outbound trust, setting SID filtering on local forest."
						if ($EnableLogging) { Write-Log "Outboud trust, setting SID filtering on local forest."}

						Set-ADForestTrustSIDFiltering -TrustingForest $LocalForest -TrustedForest $RemoteForest.Name -SidFilteringEnabled $SidFilteringEnabled -EnableLogging:$EnableLogging
						
						Write-Host "Completed enabling SID filtering."
						if ($EnableLogging) { Write-Log "Completed enabling SID filtering."}
						break
					}
					([System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional) {
						Write-Host "Bidirectional trust, setting SID filtering on both forests."
						if ($EnableLogging) { Write-Log "Bidirectional trust, setting SID filtering on both forests."}

						Set-ADForestTrustSIDFiltering -TrustingForest $RemoteForest -TrustedForest $LocalForest.Name -SidFilteringEnabled $SidFilteringEnabled -EnableLogging:$EnableLogging
						Set-ADForestTrustSIDFiltering -TrustingForest $LocalForest -TrustedForest $RemoteForest.Name -SidFilteringEnabled $SidFilteringEnabled -EnableLogging:$EnableLogging
							
						Write-Host "Completed enabling SID filtering."
						if ($EnableLogging) { Write-Log "Completed enabling SID filtering."}
						break
					}
					default {
						if ($EnableLogging) { Write-Log "Could not determine trust direction."}
						throw "Could not determine trust direction."
					}
				}

				if ($EnableLogging) { Write-Log "Remote domain supports Kerberos AES encryption: $TrustingDomainSupportsKerberosAESEncryption"}

				if ($TrustingDomainSupportsKerberosAESEncryption) {                
					try
					{
						Write-Host "Setting Kerberos AES support."
						if ($EnableLogging) { Write-Log "Setting Kerberos AES support."}						
						Set-ADForestTrustKerberosSupport -TrustDirection $TrustDirection -RemoteForest $RemoteForest.Name -LocalForest $LocalForest.Name -RemoteCredential $RemoteForestCredential -EnableLogging							
					}
					catch [Exception] {
						Write-Warning $_.Exception.Message
						if ($EnableLogging) { Write-Log $_ }
						$Continue = $false
					}
				}			
			}
			catch [Exception] {
				Write-Warning $_.Exception.Message
				if ($EnableLogging) { Write-Log $_ }
				$Continue = $false
			}
		}

		if (!$Continue) {
			$CommandText = Get-CommandText -Command ($PSCmdlet.MyInvocation.MyCommand.Name) -Parameters $PSBoundParameters
			Write-Warning "A step failed in creating the trust and its settings. Review the error and try again."
			Write-Host "Rerun this command: $CommandText"

			if ($EnableLogging) { Write-Log "A step failed in creating the trust and its settings. Review the error and try again." }
			if ($EnableLogging) { Write-Log "Rerun this command: $CommandText" }
		}
	}

	End {		
	}
}

Function Set-ADForestTrustSelectiveAuthentication {
	<#
		.SYNOPSIS
			The cmdlet sets up selective authentication for a forest trust.

		.DESCRIPTION
			The cmdlet enables or disables selective authentication for a forest trust between the specified forests.

		.PARAMETER TrustDirection
			The direction of the trust that should use selective authentication.

		.PARAMETER LocalForest
			The forest object for the local forest. This defaults to the forest of the computer where the cmdlet is being run.

		.PARAMETER RemoteForest
			The forest object for the remote forest.

		.PARAMETER LocalForestName
			The name of the local forest where the cmdlet is being run. This defaults to the forest root domain of the computer running the cmdlet.

		.PARAMETER RemoteForestName
			The name of the remote forest where the trust will connect.

		.PARAMETER LocalForestCredential
			The credential to use to setup the local side of the trust. The credential should have Enterprise Admin rights and defaults to the user running the cmdlet.

		.PARAMETER RemoteForestCredential
			The credential to use to setup the remote side of the trust. The credential should have Enterprise Admin rights in the remote forest.

		.PARAMETER SelectiveAuthenticationEnabled
			Specify whether selective authentication should be enabled or not. This defaults to false.

		.PARAMETER EnableLogging
			Specifies whether to use the module logging function when the cmdlet is run.

		.INPUTS
			None
		
		.OUTPUTS
			None

		.EXAMPLE 
			Set-ADForestTrustSelectiveAuthentication -RemoteForestName "contoso.com" -RemoteForestCredential (Get-Credential) -SelectiveAuthenticationEnabled $true -TrustDirection ([System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound)

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,Mandatory=$true)]
		[System.DirectoryServices.ActiveDirectory.TrustDirection]$TrustDirection,

		[Parameter(Position=1,ParameterSetName="Objects")]
		[System.DirectoryServices.ActiveDirectory.Forest]$LocalForest = $null,

		[Parameter(Position=2,ParameterSetName="Objects",Mandatory=$true)]
		[System.DirectoryServices.ActiveDirectory.Forest]$RemoteForest,

		[Parameter(Position=1,ParameterSetName="Names")]
		[System.String]$LocalForestName = [System.String]::Empty,

		[Parameter(Position=2,ParameterSetName="Names",Mandatory=$true)]
		[System.String]$RemoteForestName,

		[Parameter(Position=3,ParameterSetName="Names")]
		[PSCredential]$LocalForestCredential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(Position=4,Mandatory=$true,ParameterSetName="Names")]
		[PSCredential]$RemoteForestCredential,

		[Parameter()]
		[bool]$SelectiveAuthenticationEnabled = $false,

		[Parameter()]
		[switch]$EnableLogging
	)

	Begin {		
	}

	Process {
		switch ($PSCmdlet.ParameterSetName) {
			"Objects" {
				if ($LocalForest -eq $null) {
					$LocalForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
				}
				break
			}
			"Names" {
				if ([System.String]::IsNullOrEmpty($LocalForestName)) {
					$LocalForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
				}
				else {
					try {
						if ($LocalForestCredential -ne $null -and $LocalForestCredential -ne [PSCredential]::Empty) {
							[System.DirectoryServices.ActiveDirectory.DirectoryContext]$LocalForestContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest, $LocalForestName, $LocalForestCredential.UserName, (Convert-SecureStringToString -SecureString $LocalForestCredential.Password))
						}
						else {
							[System.DirectoryServices.ActiveDirectory.DirectoryContext]$LocalForestContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest, $LocalForestName)
						}
						[System.DirectoryServices.ActiveDirectory.Forest]$LocalForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($LocalForestContext)
					}
					catch [Exception] {
						Write-Warning -Message $_.Exception.Message
						if ($EnableLogging) { Write-Log $_ }
						throw $_.Exception
					}
				}

				try {
					[System.DirectoryServices.ActiveDirectory.DirectoryContext]$RemoteForestContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest, $RemoteForestName, $RemoteForestCredential.UserName, (Convert-SecureStringToString -SecureString $RemoteForestCredential.Password))
					[System.DirectoryServices.ActiveDirectory.Forest]$RemoteForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($RemoteForestContext)
				}
				catch [Exception] {
					Write-Warning -Message $_.Exception.Message
					if ($EnableLogging) { Write-Log $_ }
					throw $_.Exception
				}
				break
			}
			default {
				throw "Parameter set for Set-ADForestTrustSelectiveAuthentication could not be determined."
			}
		}

		Write-Host "Setting selective authentication."
		if ($EnableLogging) { Write-Log "Setting selective authentication."}

		try {
			switch ($TrustDirection) {
				#Inbound trust means that the remote forest trusts the local forest
				([System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound) {
					$RemoteForest.SetSelectiveAuthenticationStatus($LocalForest.Name, $SelectiveAuthenticationEnabled)
					Write-Host "Completed setting selective authentication."
					if ($EnableLogging) { Write-Log "Completed setting selective authentication."}
					break
				}
				#Outbound trust means that the local forest trusts the remote forest
				([System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound) {
					$LocalForest.SetSelectiveAuthenticationStatus($RemoteForest.Name, $SelectiveAuthenticationEnabled)
					Write-Host "Completed setting selective authentication."
					if ($EnableLogging) { Write-Log "Completed setting selective authentication."}
					break
				}
				([System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional) {
					$LocalForest.SetSelectiveAuthenticationStatus($RemoteForest.Name, $SelectiveAuthenticationEnabled)
					$RemoteForest.SetSelectiveAuthenticationStatus($LocalForest.Name, $SelectiveAuthenticationEnabled)
					Write-Host "Completed setting selective authentication."
					if ($EnableLogging) { Write-Log "Completed setting selective authentication."}
					break
				}
				default {
					if ($EnableLogging) { Write-Log "Could not determine trust direction."}
					throw "Could not determine trust direction."
				}
			}
		}
		catch [Exception] {
			if ($EnableLogging) { Write-Log $_ }
			throw $_.Exception
		}
	}

	End {
	}
}

Function Set-ADForestTrustKerberosSupport {
	<#
		.SYNOPSIS
			The cmdlet enables Kerberos AES 128 and 256 encryption in the forest.

		.DESCRIPTION
			The cmdlet uses ksetup.exe to enables AES 128 and 256 encryption in the forest specified by the trust direction. An inbound trust enables encryption in the local forest, outbound in the remote forest, and bidirectional
			in both forests.

		.PARAMETER TrustDirection
			The direction of the forest trust in relation to the server the cmdlet is being run on. This can be Inbound, Outbound, or Bidirectional.

		.PARAMETER LocalForest
			The name of the local forest where the cmdlet is being run. This defaults to the forest root domain of the computer running the cmdlet.

		.PARAMETER RemoteForest
			The name of the remote forest.
			
		.PARAMETER RemoteCredential
			The credential used to run Invoke-Command on the remote server that is selected via DNS resolution of the domain name. This credential needs access to the remote domain controller and to be able to run ksetup.exe in the remote forest.

		.PARAMETER PassThru
			Returns the new or modified object. By default (i.e. if -PassThru is not specified), this cmdlet does not generate any output.
	
		.PARAMETER EnableLogging
			Specifies whether to use the module's logging function when the cmdlet is run.			

		.INPUTS
			None
		
		.OUTPUTS
			None or Microsoft.ActiveDirectory.Management.ADObject

		.EXAMPLE 
			Set-ADForestTrustKerberosSupport -RemoteForest "contoso.com" -TrustDirection ([System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound) -RemoteCredential (Get-Credential)

			Enables AES encryption in the contoso.com domain.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0, Mandatory=$true)]
		[System.DirectoryServices.ActiveDirectory.TrustDirection]$TrustDirection,

		[Parameter(Position=1, Mandatory=$true)]
		[System.String]$RemoteForest,

		[Parameter(Position=2)]
		[System.String]$LocalForest = [System.String]::Empty,

		[Parameter(Position=3,Mandatory=$true)]
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$RemoteCredential,

		[Parameter()]
		[switch]$PassThru,

		[Parameter()]
		[switch]$EnableLogging
	)

	Begin {		
	}

	Process {
		if ([System.String]::IsNullOrEmpty($LocalForest)) {
			$LocalForest = (Get-ADForest -Current LocalComputer).Name
		}

		switch ($TrustDirection) {
			#Inbound trust means that the remote forest trusts the local forest
			([System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound) {
				$Process = Start-Process -FilePath "$env:SYSTEMROOT\system32\ksetup.exe" -ArgumentList @("/setenctypeattr",$RemoteForest,"AES128-CTS-HMAC-SHA1-96","AES256-CTS-HMAC-SHA1-96") -NoNewWindow
				
				Write-Host "Configured Kerberos AES encryption setting."
				if ($EnableLogging) { Write-Log "Configured Kerberos AES encryption setting." }

				if ($PassThru) {
					Write-Output (Get-ADObject -Filter {(objectClass -eq "trustedDomain") -and (name -eq $RemoteForest)} -Properties "msDS-SupportedEncryptionTypes") 
				}

				break
			}
			#Outbound trust means that the local forest trusts the remote forest
			([System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound) {
				$Trust = Invoke-Command -ComputerName $RemoteForest.Name -ScriptBlock {
					$Domain = $args[0]
					$Proc = Start-Process -FilePath "$env:SYSTEMROOT\system32\ksetup.exe" -ArgumentList @("/setenctypeattr",$Domain,"AES128-CTS-HMAC-SHA1-96","AES256-CTS-HMAC-SHA1-96") -NoNewWindow
					Get-ADObject -Filter {(objectClass -eq "trustedDomain") -and (name -eq $Domain)} -Properties "msDS-SupportedEncryptionTypes" 
				} -ArgumentList ($LocalForest) -Credential $RemoteCredential
								
				Write-Host "Configured Kerberos AES encryption setting."
				if ($EnableLogging) { Write-Log "Configured Kerberos AES encryption setting." }

				if ($PassThru) {
					Write-Output $Trust
				}

				break
			}
			([System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional) {
				$Process = Start-Process -FilePath "$env:SYSTEMROOT\system32\ksetup.exe" -ArgumentList @("/setenctypeattr",$RemoteForest,"AES128-CTS-HMAC-SHA1-96","AES256-CTS-HMAC-SHA1-96") -NoNewWindow
				$Trust = Invoke-Command -ComputerName $RemoteForest.Name -ScriptBlock {
					$Domain = $args[0]
					$Proc = Start-Process -FilePath "$env:SYSTEMROOT\system32\ksetup.exe" -ArgumentList @("/setenctypeattr",$Domain,"AES128-CTS-HMAC-SHA1-96","AES256-CTS-HMAC-SHA1-96") -NoNewWindow
					Get-ADObject -Filter {(objectClass -eq "trustedDomain") -and (name -eq $Domain)} -Properties "msDS-SupportedEncryptionTypes" 
				} -ArgumentList ($LocalForest)

				Write-Host "Configured Kerberos AES encryption setting."
				if ($EnableLogging) { Write-Log "Configured Kerberos AES encryption setting." }
				
				if ($PassThru) {
					Write-Output (Get-ADObject -Filter {(objectClass -eq "trustedDomain") -and (name -eq $RemoteForest)} -Properties "msDS-SupportedEncryptionTypes") 
					Write-Output $Trust
				}

				break
			}
			default {
				Write-Warning "Could not determine trust direction."
				if ($EnableLogging) { Write-Log "Could not determine trust direction."}
			}
		}
	}

	End {
	}
}

Function Get-ADForestTrustRelationship {
	<#
		.SYNOPSIS
			The cmdlet gets the trust relationship information about the local and remote forest.

		.DESCRIPTION
			The cmdlet gets the trust relationship information about the local and remote forest. If no trust exists, the cmdlet returns null.

		.PARAMETER TargetForestName
			The name of the remote forest to get the trust information about.

		.PARAMETER CurrentForest
			The forest object to use to query about the trust information. This defaults to the current forest.

		.INPUTS
			System.String
		
		.OUTPUTS
			Null or System.DirectoryServices.ActiveDirectory.ForestTrustRelationshipInformation

		.EXAMPLE 
			Get-ADForestTrustRelationship -TargetForestName "contoso.com"

			Gets trust relationship information about contoso.com and the local forest.

		.NOTES
			None
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
        [System.String]$TargetForestName,

		[Parameter(Position=1)]
        [System.DirectoryServices.ActiveDirectory.Forest]$CurrentForest = $null
    )

    Begin {		
	}

    Process {
		if ($CurrentForest -eq $null) {
			$CurrentForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
		}

		try {
			Write-Output -InputObject $CurrentForest.GetTrustRelationship($TargetForestName)
		}
		catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
			Write-Warning $_.Exception.Message
			Write-Output -InputObject $null
		}
    }

	End {}
}

Function Set-ADForestTrustSIDFiltering {
	<#
		.SYNOPSIS
			The cmdlet sets SID filtering between two forests.

		.DESCRIPTION
			The cmdlet enables or disables SID filtering between two forests with a forest trust.

		.PARAMETER TrustingForest
			The forest object that trusts the other forest. The trust direction would be outbound or bidirectional for this forest. This defaults to the current forest.

		.PARAMETER TrustedForest
			The forest that is trusted by the other forest. The trust direction would be inbound or bidirectional for this forest.

		.PARAMETER SidFilteringEnabled
			Specify whether SID filtering should be enabled. This defaults to true.

		.PARAMETER EnableLogging
			Specify whether the module's logging function should be used when running the cmdlet.

		.INPUTS
			System.String
		
		.OUTPUTS
			None

		.EXAMPLE 
			Set-ADForestTrustSIDFiltering -TrustedForest "contoso.com" 

			The local forest, admin.local, that trusts contoso.com, has SID filtering enabled on the trust.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=1)]
		[System.DirectoryServices.ActiveDirectory.Forest]$TrustingForest = $null,

		[Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
		[System.String]$TrustedForest,

		[Parameter(Position=2)]
		[bool]$SidFilteringEnabled = $true,

		[Parameter()]
		[switch]$EnableLogging
	)

	Begin {		
	}

	Process {
		if ($TrustingForest -eq $null) {
			$TrustingForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
		}

		try {
			Write-Host "Setting SID Filtering for $($TrustingForest.Name) to $SidFilteringEnabled."
			if ($EnableLogging) { Write-Log "Setting SID Filtering for $($TrustingForest.Name) to $SidFilteringEnabled." }
			
			$TrustingForest.SetSidFilteringStatus($TrustedForest, $SidFilteringEnabled)

			Write-Host "Successfully set SID Filtering to $SidFilteringEnabled."
			if ($EnableLogging) { Write-Log "Successfully set SID Filtering to $SidFilteringEnabled."}

		}
		catch [Exception] {
			Write-Warning $_.Exception.Message
			if ($EnableLogging) { Write-Log $_ }
		}
	}

	End {
	}
}

#endregion

#region Scheduled Task Functions

Function New-SaveEncryptedPasswordTask {
	<#
		.SYNOPSIS
			The cmdlet runs a scheduled task as a specified account to save a password encrypted with the principal's credentials.

		.DESCRIPTION
			The cmdlet runs a scheduled task as a specified account to save a password encrypted with the principal's credentials. The scheduled task is deleted after the task is complete.

		.PARAMETER Password
			The password to encrypt and save.

		.PARAMETER FilePath
			The location to save the password file. This defaults to "$env:ALLUSERSPROFILE\Microsoft\ADPassword.txt".

		.PARAMETER Principal
			The principal that the scheduled task will run as. This defaults to SYSTEM.

		.PARAMETER Timeout
			The timeout for the scheduled task. This defaults to 10 minutes.

		.INPUTS
			System.Security.SecureString
		
		.OUTPUTS
			System.String
			The file path of the encrypted password.

		.EXAMPLE 
			New-SaveEncryptedPasswordTask 

			The cmdlet will prompt the user to enter the password, and then run a scheduled task as SYSTEM to encrypt the password.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)]
		[SecureString]$Password = $null,

		[Parameter(Position=1)]
		[System.String]$FilePath = "$env:ALLUSERSPROFILE\Microsoft\ADPassword.txt",

		[Parameter(Position=2)]
		[Microsoft.Management.Infrastructure.CimInstance]$Principal = $null,

		[Parameter(Position=3)]
		[System.Timespan]$Timeout = [System.Timespan]::FromSeconds(600)
	)

	Begin {	
	}

	Process {
		if ($FilePath -eq $null -or $FilePath -eq [System.String]::Empty) {
			throw [System.ArgumentNullException]("The specified file path was null or empty.")
		}

		while($Password -eq $null) {
			$Password = Read-Host -AsSecureString -Prompt "Enter the password to encrypt"
		}

		$TempPass = Convert-SecureStringToString -SecureString $Password
		$Command = "try {`$EncryptedPass = New-EncryptedPassword -Password $TempPass; Set-Content -Path $FilePath -Value `$EncryptedPass -Force } catch [Exception] { Write-Log `$_ }"
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
        $EncodedCommand = [Convert]::ToBase64String($Bytes)

        $TempPass = $null 

		Write-Host "Creating scheduled task to save password."

        $STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
    
        $STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
        $STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
		
		if ($Principal -eq $null) {
			$STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
		}
		else {
			$STPrincipal = $Principal
		}

        $STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
                        
        if ((Get-ScheduledTask -TaskName "SavePassword" -ErrorAction SilentlyContinue) -ne $null) {
			Unregister-ScheduledTask -TaskName "SavePassword" -Confirm:$false
        }
        
		Write-Host "Registering scheduled task."              
        $ScheduledTask = Register-ScheduledTask -TaskName "SavePassword" -Action $STAction -Principal $STPrincipal -Settings $STSettings -ErrorAction Stop

		Write-Host "Executing scheduled task."
		Start-ScheduledTask -TaskName "SavePassword"

		Write-Host "Waiting for password file to be created."
        $Counter = 0
		while (!(Test-Path -Path $FilePath)) {
			Start-Sleep -Seconds 1
            $Counter++

            if ($Counter -gt $Timeout.TotalSeconds) {
				Write-Warning "Password file failed to be created before timeout."
				throw "Password file failed to be created before timeout."
            }
        }

		Write-Host "Password file successfully created."

		if ((Get-ScheduledTask -TaskName "SavePassword" -ErrorAction SilentlyContinue) -ne $null) {
			Write-Host "Removing scheduled task."
			Unregister-ScheduledTask -TaskName "SavePassword" -Confirm:$false          
        }

		Write-Output $FilePath
	}

	End {		
	}                 
}

Function New-InstallSecureADForestScheduledTask {
	<#
		.SYNOPSIS
			The cmdlet creates a scheduled task to begin the Install-SecureADForest cmdlet after the next reboot.

		.DESCRIPTION
			The cmdlet creates a scheduled task to begin the Install-SecureADForest after the next reboot that will run as the specified principal. In order to both read the encrypted password and run the scheduled task with
			the appropriate permissions, the password should be encrypted with SYSTEM credentials and the scheduled task should be run as SYSTEM. This is the default configuration.

		.PARAMETER ConfigFilePath
			The path to the config file that Install-SecureADForest will use to execute.

		.PARAMETER PasswordFilePath
			The path to the password file containing the DSRM safe mode password.

		.PARAMETER Principal
			The principal that the scheduled task will run as. This defaults to SYSTEM.

		.INPUTS
			None
		
		.OUTPUTS
			Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask

		.EXAMPLE 
			New-InstallSecureADForestScheduledTask -ConfigFilePath "$PSScriptRoot\config.json" -PasswordFilePath "$env:ALLUSERSPROFILE\Microsoft\ADPassword.txt"

			Creates the scheduled task to run Install-SecureADForest as SYSTEM.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Position=0, Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$ConfigFilePath,

		[Parameter(Position=1, Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$PasswordFilePath,

		[Parameter(Position=2)]
		[Microsoft.Management.Infrastructure.CimInstance]$Principal = $null
	)

	Begin {		
	}

	Process {
		if ((Get-ScheduledTask -TaskName $script:InstallSecureADForestTask -ErrorAction SilentlyContinue) -ne $null) {
			Unregister-ScheduledTask -TaskName $script:InstallSecureADForestTask -Confirm:$false
        }

		$Command = "try {`$SafeModePassword = Get-EncryptedPassword -FilePath `"$PasswordFilePath`"; Remove-Item -Path `"$PasswordFilePath`" -Force -Confirm:`$false; Install-SecureADForest -ConfigFilePath `"$ConfigFilePath`" -SafeModePassword `$SafeModePassword} catch [Exception] {Write-Log `$_}"
		$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
		$EncodedCommand = [Convert]::ToBase64String($Bytes)
        
		$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
		$STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
		$STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
		
		if ($Principal -eq $null) {
			$STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
		}
		else {
			$STPrincipal = $Principal
		}

		$STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew
		$ScheduledTask = Register-ScheduledTask -TaskName $script:InstallSecureADForestTask -Action $STAction -Principal $STPrincipal -Trigger (New-ScheduledTaskTrigger -AtStartup -RandomDelay ([System.Timespan]::FromSeconds(30))) -Settings $STSettings -ErrorAction Stop

		Write-Output -InputObject $ScheduledTask
	}

	End {
		
	}
}

Function New-FinishSecureADForestInstallationScheduledTask {
	<#
		.SYNOPSIS
			The cmdlet creates a scheduled task to begin the Set-ADForestSecurityConfiguration cmdlet after the next reboot.

		.DESCRIPTION
			The cmdlet creates a scheduled task to begin the Set-ADForestSecurityConfiguration cmdlet after the next reboot that will run as the specified principal.

		.PARAMETER ConfigFilePath
			The path to the config file that Set-ADForestSecurityConfiguration will use to execute.

		.PARAMETER Principal
			The principal that the scheduled task will run as. This defaults to SYSTEM.

		.INPUTS
			None
		
		.OUTPUTS
			Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask

		.EXAMPLE 
			New-FinishSecureADForestInstallationScheduledTask -ConfigFilePath "$PSScriptRoot\config.json"

			Creates the scheduled task to run Set-ADForestSecurityConfiguration as SYSTEM.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$ConfigFilePath,

		[Parameter(Position=1)]
		[Microsoft.Management.Infrastructure.CimInstance]$Principal = $null
	)

	Begin {		
	}

	Process {
		if ((Get-ScheduledTask -TaskName $script:FinishSecureADForestTask -ErrorAction SilentlyContinue) -ne $null) {
			Unregister-ScheduledTask -TaskName $script:FinishSecureADForestTask -Confirm:$false
        }

		$Command = "try {Set-ADForestSecurityConfiguration -ConfigFilePath `"$ConfigFilePath`"} catch [Exception] {Write-Log `$_}"                            
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
        $EncodedCommand = [Convert]::ToBase64String($Bytes)
        
        $STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
        $STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
        $STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams

        if ($Principal -eq $null) {
			$STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
		}
		else {
			$STPrincipal = $Principal
		}

        $STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew
                               
        $ScheduledTask = Register-ScheduledTask -TaskName $script:FinishSecureADForestTask -Action $STAction -Principal $STPrincipal -Trigger (New-ScheduledTaskTrigger -AtStartup -RandomDelay ([System.Timespan]::FromSeconds(30))) -Settings $STSettings -ErrorAction Stop 

		Write-Output -InputObject $ScheduledTask
	}
	
	End {		
	}
}

#endregion

#region Utility Functions 

Function Test-RpcAvailability {
	<#
		.SYNOPSIS
			The cmdlet tests whether the RPCSS service is available on a computer.

		.DESCRIPTION
			The cmdlet tests whether the RPCSS service is available on a computer by running a Get-Service against the provided computer name.

		.PARAMETER ComputerName
			The computer to check the service availability on.

		.PARAMETER EnableLogging
			Specify whether to use the module's logging function.

		.PARAMETER Wait
			If the initial request returns null, specify whether to wait until the timeout to continue testing for the service's availability.

		.PARAMETER Timeout
			If the Wait parameter is used, the timeout as a multiple of 10 seconds to keep trying before failing. This defaults to 180, which is 1800 seconds, or 30 minutes.

		.INPUTS
			System.String
		
		.OUTPUTS
			System.Boolean

		.EXAMPLE 
			Test-RpcAvailability -ComputerName "AdminDC" -Wait

			Tests for the availability of the RPCSS service and waits up to 30 minutes for it to become available.

		.NOTES
			None
	#>
	[CmdletBinding()] 
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)]
		[System.String]$ComputerName = [System.String]::Empty,

		[Parameter()]
		[switch]$EnableLogging,

		[Parameter()]
		[switch]$Wait,

		[Parameter(Position = 1)]
		[System.Int32]$Timeout = 180
	)

	Begin {		
	}

	Process {
		if ([System.String]::IsNullOrEmpty($ComputerName)) {
			$ComputerName = $env:COMPUTERNAME
		}

		Write-Host "Testing for RPC availability on $ComputerName."
		if ($EnableLogging) { Write-Log "Testing for RPC availability on $ComputerName." }

		$RpcSs = $RpcSs = Get-Service -ComputerName $ComputerName -Name RpcSs -ErrorAction SilentlyContinue

		if ($RpcSs -eq $null) {
			if ($Wait) {
				$Counter = 0
			
				while ($RpcSs -eq $null) {
					if ($Counter -gt $Timeout) {
						if ($EnableLogging) { Write-Log "Timeout waiting for RpcSs service to be loaded. Could not create local stub zone." }
						Write-Output $false
					}
				
					Start-Sleep -Seconds 10
					$Counter++
					try {
						$RpcSs = Get-Service -ComputerName $ComputerName -Name RpcSs -ErrorAction SilentlyContinue

						Write-Host ("Current RpcSs status: RpcSs = null : " + ($RpcSs -eq $null))
						if ($EnableLogging) { Write-Log ("Current RpcSs status: RpcSs = null : " + ($RpcSs -eq $null)) }
					}
					catch [Exception] {
						if ($EnableLogging) { Write-Log ("Iteration $Counter " + $_.Exception.Message) }
					}
				}
			}
			else {
				if ($EnableLogging) { Write-Log "RpcSs service is not available." }
				Write-Output $false
			}
		}
		
		if ($EnableLogging) { Write-Log ("RpcSs service found: " + ($RpcSs -ne $null) + ".")}
		if ($EnableLogging) { Write-Log "Connected to $($RpcSs.MachineName)." }

		$ComputerName = $RpcSs.MachineName

		$RpcEptMapper = Get-Service -ComputerName $ComputerName -Name RpcEptMapper
		
		if ($EnableLogging) { Write-Log "Current RpcSs status: $($RpcSs.Status)." }
		if ($EnableLogging) { Write-Log "Current RpcEptMapper status: $($RpcEptMapper.Status)." }

		
		if ($RpcSs.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running -and $RpcEptMapper.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
			if ($Wait) {
				$Counter = 0
			
				while ($RpcSs.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running -and $RpcEptMapper.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
					if ($Counter -gt 180) {
						if ($EnableLogging) { Write-Log "Timeout waiting for RpcSs and RpcEptMapper to start. Could not create local stub zone." }
						Write-Output $false
					}

					Start-Sleep -Seconds 10
					$Counter++
					$RpcSs = Get-Service -ComputerName $ComputerName -Name RpcSs
					$RpcEptMapper = Get-Service -ComputerName $ComputerName -Name RpcEptMapper

					Write-Host "Current RpcSs status: $($RpcSs.Status)."
					Write-Host "Current RpcEptMapper status: $($RpcEptMapper.Status)."
					if ($EnableLogging) { Write-Log "Current RpcSs status: $($RpcSs.Status)." }
					if ($EnableLogging) { Write-Log "Current RpcEptMapper status: $($RpcEptMapper.Status)." }				
				}
			}
			else {
				if ($EnableLogging) { Write-Log "The RpcSs and RpcEptMapper services are not running." }
				Write-Output $false
			}
		}

		Write-Host "Rpc services are running, testing WMI connection via RPC."
		if ($EnableLogging) { Write-Log "Rpc services are running, testing WMI connection via RPC." }

		$Comp = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue

		if ($Comp -ne $null) {
			if ($EnableLogging) { Write-Log "Successfully connected to WMI via RPC."}
			Write-Output $true
		}
		else {
			if ($EnableLogging) { Write-Log "Could not connect to WMI via RPC, cannot create Stub Zone." }
			Write-Output $false
		}				
	}

	End {
	}
}

Function New-ConfigurationFile {
	<#
		.SYNOPSIS
			The cmdlet writes creates a new configuration json file from the inputted parameters of a cmdlet.

		.DESCRIPTION
			The cmdlet writes creates a new configuration json file from the inputted parameters of a cmdlet.

		.PARAMETER ParameterList
			The list of parameters to create the configuration file with.

		.PARAMETER SourceFilePath
			The path to the existing configuration file.

		.PARAMETER Destination
			The path to where the resulting configuration file is written.

		.INPUTS
			None
		
		.OUTPUTS
			System.Collections.Hashtable
			An object that contains the path to the configuration file and a JSON string of the content.

		.EXAMPLE 
			$ParameterList = @{}
			$ParameterList.Add("Name", "John Smith")
			$Info = New-ConfigurationFile -ParameterList $ParameterList -Destination "c:\config.json"

			Creates a new configuration file at c:\config.json and returns an object with the file path and configuration content.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,ParameterSetName="Parameters",Position=0, ValueFromPipeline = $true)]
		[System.Collections.Hashtable]$ParameterList,

		[Parameter(Mandatory=$true,ParameterSetName="File",Position=0, ValueFromPipeline = $true)]
		[ValidateScript({Test-Path -Path $_})]
		[System.String]$SourceFilePath,

		[Parameter(Position=1)]
		[System.String]$Destination = [System.String]::Empty
	)

	Begin {		
	 }

	Process {
		$Values = @()

		if ([System.String]::IsNullOrEmpty($Destination)) {
			$Destination = [System.IO.Path]::Combine($PSScriptRoot, "config.json")
		}

		switch ($PSCmdlet.ParameterSetName) {
			"Parameters" {
				$Json = ConvertTo-Json -InputObject $ParameterList
		
				Set-Content -Value $Json -Path $Destination
				break
			}
			"File" {
				Copy-Item -Path $SourceFilePath -Destination $Destination
				
				$Counter = 0
				while (!(Test-Path -Path $Destination)) {
					Start-Sleep -Seconds 1
					$Counter++

					if ($Counter -gt 120) {
						throw "Timeout waiting for config file to be copied."
					}
				}	
				$Json = Get-Content -Path $Destination -Raw
				break
			}
		}

		Write-Output -InputObject @{"FilePath"=$Destination;"Content"=$Json}
	}

	End {	
	}
}

Function Get-CommandText {
	<#
		.SYNOPSIS
			The cmdlet generates a string of the parameters and values that were used to run a cmdlet.

		.DESCRIPTION
			The cmdlet generates a string of the parameters and values that were used to run a cmdlet.

		.PARAMETER Command
			The command that was run.

		.PARAMETER Parameters
			The parameters that were specified when running the command.

		.INPUTS
			System.String
		
		.OUTPUTS
			System.String

		.EXAMPLE 
			Get-CommandText -Command "Get-Service"

			Recreates the string "Get-Service"

		.EXAMPLE
			Get-CommandText -Command "My-Function" -Parametets $PSBoundParameters

			When utilized inside the function "My-Function", it prints the command and parameters used to execute it.

		.NOTES
			None
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[System.String]$Command,

		[Parameter(Position=1)]
		[System.Object]$Parameters = $null
	)

	Begin {

	}

	Process {
		
		if ($Parameters -ne $null) {
			$Parameters.GetEnumerator() | ForEach-Object {
				$Param = $_.Key
				$Value = $_.Value

				if ($Value.GetType() -eq [System.String]) {
					$Command += " -$Param `"$Value`""
				}
				else {
					if ($Value.GetType() -eq [System.Boolean]) {
						$Command += " -$Param `$$($Value.ToString().ToLower())"
					}
					else {
						$Command += " -$Param $Value"
					}
				}
			}
		}

		Write-Output -InputObject $Command
	}

	End {		
	}
}

#endregion

$script:TrustAttributes = @(
			[PSCustomObject]@{Key="0x00000001";Value="TRUST_ATTRIBUTE_NON_TRANSITIVE"},
			[PSCustomObject]@{Key="0x00000002";Value="TRUST_ATTRIBUTE_UPLEVEL_ONLY"},
			[PSCustomObject]@{Key="0x00000004";Value="TRUST_ATTRIBUTE_QUARANTINED_DOMAIN"},
			[PSCustomObject]@{Key="0x00000008";Value="TRUST_ATTRIBUTE_FOREST_TRANSITIVE"},
			[PSCustomObject]@{Key="0x00000010";Value="TRUST_ATTRIBUTE_CROSS_ORGANIZATION"}
			[PSCustomObject]@{Key="0x00000020";Value="TRUST_ATTRIBUTE_WITHIN_FOREST"},
			[PSCustomObject]@{Key="0x00000040";Value="TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL"},
			[PSCustomObject]@{Key="0x00000080";Value="TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION"},
			[PSCustomObject]@{Key="0x00000200";Value="TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION"},
			[PSCustomObject]@{Key="0x00000400";Value="TRUST_ATTRIBUTE_PIM_TRUST"}
		)