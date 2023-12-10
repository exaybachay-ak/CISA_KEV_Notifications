################################################################################################
##############################      CISA KEV Notifier      #####################################
################################################################################################
### --->>>       1. Read in a configuration file of included and excluded strings            ###
### --->>>       2. Search all CISA KEV entries for those strings                            ###
### --->>>       3. Email if a string matches                                                ###
### --->>>       4. Store JSON file locally to track what notifications have been sent       ###
################################################################################################
################################################################################################

<###############################################################################################
    NOTES:
    Using minimum datetime of 01/01/0001 because datetime vars cannot be null

    Execution Flow: 
    1. Download KEVs from CISA website  (kevs.kev_array_online)
    2. Load KEVs from local storage (kevs.kev_array_local)
    3. Read each KEV (kev.check_environment)
    4. Compare the local and online version - make sure it has property for EmailNotificationSent (kev.notify_admins)
    5. If it doesn't have the property, just add it and move on (kev.update)
    6. If ew haven't been notified, and there is a match on vendors, email sysadmin(s) (kevs.send_email)
    7. Write KEVs to new local file (kevs.update_local)

    TO DO:
    1. Make a logger function to save info to local log file.  Don't log if nologging flag is set
    2. Implement proper exception handling 
    -----------------------------------/////////////////////////////////////////////////-----------------------------------
    ### Fields are cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, and notes

        ### Example:
        ### cveID             : CVE-2021-1732
        ### vendorProject     : Microsoft
        ### product           : Win32k
        ### vulnerabilityName : Microsoft Win32k Privilege Escalation Vulnerability
        ### dateAdded         : 2021-11-03
        ### shortDescription  : Windows Win32k Privilege Escalation Vulnerability. This CVE ID is unique from CVE-2021-1698.
        ### requiredAction    : Apply updates per vendor instructions.
        ### dueDate           : 2021-11-17
        ### notes             :

    -----------------------------------/////////////////////////////////////////////////-----------------------------------
    Example JSON configuration file contents
    
    {
	    "vendor": ["cisco","microsoft","adobe","java"],
	    "exclude": ["DOS"]
    }

################################################################################################>

### --->>> Configure environment and variables 
$kev_array = @()
$kev_array_new = @()
$kev_config_exclusions = @()
$kev_config_vendors = @()
$kev_emails = @()
$Debug = $True

### --->>> 
class KEV
{

    ###   KEV CVE Properties
    [String]$cveID
    [String]$vendorProject
    [String]$product
    [String]$vulnerabilityName
    [datetime]$dateAdded
    [String]$shortDescription
    [String]$requiredAction
    [datetime]$dueDate
    [String]$notes
    [bool]$emailNotificationSent # track whether or not we have notified IT about the KEV
    [datetime]$emailNotificationSentDate
    [bool]$vendorFound
    [bool]$exclusionFound

    [void] prep_email() 
    {
        $global:kev_emails += $($this)
        $this.emailNotificationSent = $True
        $this.emailNotificationSentDate = Get-Date        
    }

    [void] check_environment()
    {
        if(!($this.exclusionFound) -and !($this.emailNotificationSent)){
            # Load config for environment, then check KEV Array for matching items
            ForEach ($kev in $global:kev_array ) {
                #Write-host "Checking $($Kev.cveID)"
                if(!($this.exclusionFound) -and !($this.emailNotificationSent)){
                    # Checking KEVs against config
                    Foreach ($property in $this.PSObject.Properties.value) {
                        if(!($this.exclusionFound) -and !($this.emailNotificationSent)){
                            # Check for exclusions and break out if one matches
                            Foreach ($exclusion in $global:kev_config_exclusions) {
                                if(!($this.exclusionFound) -and !($this.emailNotificationSent)){
                                    $exclusionRegex = ($exclusion.PadLeft(($exclusion.length+1),'*')).PadLeft(($exclusion.length+2),'.').PadRight(($exclusion.length+3),'.').PadRight(($exclusion.length+4),'*')
                                    if($property -match $exclusionRegex) {
                                        $this.exclusionFound = $True # Set the exclusion found flag so we can break out of this loop
                                        if($Debug){
                                            Write-host "We matched on exclusion settings.  Breaking out of loop! "
                                            Write-host $property
                                            write-host $exclusionRegex
                                        }
                                    }
                                }   
                            }
                        }
                        Foreach ($vendor in $global:kev_config_vendors) {
                            if(!($this.vendorFound) -and !($this.emailNotificationSent)){
                                $vendorRegex = ($vendor.PadLeft(($vendor.length+1),'*')).PadLeft(($vendor.length+2),'.').PadRight(($vendor.length+3),'.').PadRight(($vendor.length+4),'*')
                                if($property -match $vendorRegex) {
                                    if(!($this.emailNotificationSent)){
                                        # No exclusions configured, and we have this vendor in our environment so we will notify Admins
                                        $this.prep_email()
                                        $this.vendorFound = $True
                                        if($Debug){
                                            Write-host "We matched on vendor settings.  Breaking out of loop! "
                                            Write-host $property
                                            write-host $vendorRegex
                                        }
                                    }
                                }   
                            }
                        }
                    }
                }    
            }
        } elseif ($this.emailNotificationSent) {
            write-host "We already have sent an email about this one on $($this.emailnotificationsentdate) .. skipping..."
        }
        if($Debug){
            Write-Host "DEBUG ----------------------------------"
            Write-Host $this.emailNotificationSent
            Write-Host $this.emailNotificationSentDate
            Write-Host "DEBUG ----------------------------------"
        }
        $global:kev_array_new += $this 
    }
}

### --->>> 
class KEVArray 
{
    ###   Array Properties
    [PSObject[]]$kev_array_local # This is where our kev entries are stored 
    [PSObject[]]$kev_array_online # This is where our kev entries are stored 

    ###   Config Properties
    [PSObject[]]$kev_config_exclusions # store exclusion hash list to ignore, 2-dimensional array
    [PSObject[]]$kev_config_vendors # store vendors to include

    ###   Methods
    [void] send_email()
    {
        $kev_email_body_array = $global:kev_emails 
        $kev_email_body = "<!DOCTYPE html><html><body>"
        $kev_email_body += "<p>Hello Admins,</p>"
        $kev_email_body += "<br />"
        $kev_email_body += "<p>We have identified the following KEV entries for your environment:</p>"

        foreach($item in $kev_email_body_array){
            foreach($itemvalue in $item.PSObject.Properties){
                $itemvalue_string = $itemvalue.value | Out-String
                $itemname_string = $itemvalue.name | Out-String
                $kev_email_body += "$itemname_string : $itemvalue_string"
                $kev_email_body += "<br />"
            }
            $kev_email_body += "<br />"
            $kev_email_body += "<br />"
        }
        
        $kev_email_body += "<br />"
        $kev_email_body += "<p>Regards,</p>"
        $kev_email_body += "<p>CISA KEV Notifier Script</p>"
      
        $login = "notifier@email.com"
        [SecureString]$password = "INSERT YOUR PASSWORD HERE" | ConvertTo-SecureString -AsPlainText -Force 
        $creds = New-Object System.Management.Automation.Pscredential -Argumentlist $login,$password
        Send-MailMessage -to "targetuser@email.com" -from "notifier@email.com" -smtpserver "smtp.email.com" -port "587" -usessl -credential $creds -subject "KEVs matched! " -body $kev_email_body -bodyasHTML
    }
    
    [void] load_kev_config() {
        # Obtain local kevs and then load into kev array 
        if(!(Test-Path ".\kevConfig.json")){
            # We're done, move along
            # pass
        } else {
            $kevconfig = ((Get-Content ".\kevconfig.json") | out-string | convertfrom-json)
            $this.kev_config_exclusions = $kevconfig.exclude
            $global:kev_config_exclusions = $this.kev_config_exclusions
            $this.kev_config_vendors = $kevconfig.vendor
            $global:kev_config_vendors = $this.kev_config_vendors
        }
    }

    [void] get_local_kevs() # Populate local KEV array
    {
        if(!(Test-Path ".\kevs.json")){
            # There is no local file, move along
            # pass
        } else {
            if($this.kev_array_local.length -gt 1000){
                #$this.kev_array = ((Get-Content ".\kevs.json") | out-string | convertfrom-json)
                # If it's null, delete the local file so we can create a new one with the online version
                $this.kev_array_local = Get-Content ".\kevs.json"
            } else {
                Remove-Item ".\kevs.json"
            }
        }
    }

    [void] get_online_kevs() # Populate online KEV array and local file
    {
        # Obtain online kevs and then load into kev array 
        $kevs_online = Invoke-WebRequest "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        # Check for 200/success status code
        if($kevs_online.statuscode -eq 200 ){
            $kevs_online_json = $kevs_online.content | out-string | convertfrom-json
            $this.kev_array_online = $kevs_online_json.vulnerabilities
            $global:kev_array = $this.kev_array_online
            $kevs_online_json.vulnerabilities | Out-File ".\kevsOnline.json"
        } else {
            Write-host "Exception occurred, please check the URL! "
            break
        }
    }
    [bool] compare_kevs_same() # Use this to determine if we should update local file
    {
        $kevs_local_hash = Get-FileHash ".\kevs.json"
        $kevs_online_hash = Get-FileHash ".\kevsOnline.json"
        if($kevs_local_hash -eq $kevs_online_hash) {
            # They are the same, delete the online KEV file and return true
            Remove-Item ".\kevsOnline.json"
            return $True
        } else {
            # They are different - just overwrite the local KEVs with online version 
            Copy-Item ".\kevsonline.json" ".\kevs.json"
            return $False # Return false so we can handle updates with other KEV method 
        }
    }

    [void] update_local_file()
    {
        $global:kev_array_new | Out-string | Out-File ".\kevs.json"
    }
}

<#########################################################################
////////////////////----       Main function       ----///////////////////
#########################################################################>
# Prepare the environment
$kevs = [KEVArray]::new()
$kevs.load_kev_config()   # Populate the configuration file parameters

# Obtain KEV information
$kevs.get_local_kevs()    # Look for and load local config
$kevs.get_online_kevs()   # Obtain online config and add to local if different 

# Sort the KEV Array 
$kev_array = $kev_array | Sort-Object -Property dateAdded

# Review against environment and notify if necessary 
Foreach ($k in $kev_array){
    $kev = [KEV]::new()
    $kev.cveID = $k.cveID
    $kev.vendorProject = $k.vendorProject
    $kev.product = $k.product
    $kev.vulnerabilityName = $k.vulnerabilityName
    if($k.dateAdded){
        $kev.dateAdded = $k.dateAdded
    }
    $kev.shortDescription = $k.shortDescription
    $kev.requiredAction = $k.requiredAction
    if($k.dueDate){
        $kev.dueDate = $k.dueDate
    }
    $kev.notes = $k.notes
    if($k.emailNotificationSent){
        $kev.emailNotificationSent = $k.emailNotificationSent
    } else {
        $kev.emailNotificationSent = $False
    }
    if($k.emailNotificationSentDate){
        $kev.emailNotificationSentDate = [datetime]$k.emailNotificationSentDate
    } else {
        $kev.emailNotificationSentDate = "01/01/0001" # Remember, since we can't use $Null, we are just using 1/1/0001
    }

    write-host $k
    $kev.check_environment() # Check KEVs against config file, if any CVE's match config, email admins
}

# If we sent any emails or added KEVs, save that to the local file
$kevs.update_local_file()
if($kev_emails.length -ne 0){
    $kevs.send_email()
}
