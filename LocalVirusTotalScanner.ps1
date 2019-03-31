# Process to VirusTotal Script 22/03/19
# This script is used to dump running processes from the host PC.  The processes are retrieved via 
# the get-process command, followed by obtaining the SHA256 hash. This information is stored in an 
# array table, where the unique values are submitted to VT to check the antivirus score of the file. 
# The results are piped into a CSV on the local file system for analysis. You need a valid API key 
# from VirusTotal for this to work, as well as administrator rights on all machines that you want to 
# dump processes from.

# Setup the array and populate variables
$array = @()
$pc = hostname

# Get process and dump hash into variable
        $process = get-process -computername $pc

            # For each process, grab the hash and store as object in array
            foreach($proc in $process)
                {
                    try
                        {
                            $array += New-Object psobject -Property @{'FileHash' = (Get-FileHash -Algorithm SHA256 -Path $proc.path).Hash ; 'Process' = $proc.name ; 'Host' = hostname}
                        }
                    catch
                {
                    $proc.name | out-file error.log
                }
            
    }

# Store array as a file for lookups later on
$array | export-csv machines-and-hashes.csv -Force -NoTypeInformation

# Convert array objects into strings
$array = $array | select 'FileHash' | sort | get-unique -AsString

# Use the strings and submit each to VirusTotal via API
foreach($line in $array)ls

    {
        $hash = $line.FileHash

        # Store VirusTotal HTTP parameters as a variable. This includes the API key
        $POSTParams = @{
        apikey    = "INSERT-API-KEY-HERE"
        resource       = $hash}
        
        # Send request to VT via invoke-request and store the last 12 records as a variable. This omits the detailed per-AV engine result. Adding Sleep function to 
        # slow down the script so that VT can keep up, and so that we do not breach the 4 submission per minute limitation
        echo "Submitting Hash $hash to VirusTotal..."
        $tempvariable = Invoke-WebRequest -uri 'https://www.virustotal.com/vtapi/v2/file/report' -method POST -body $PostParams -UseBasicParsing -Verbose | Select-Object -expandproperty content
        echo ""
                start-sleep 5

        $tempvariable2 = $tempvariable.split(',') | select-object -last 12

        $tempvariable3 = [regex]::matches($tempvariable2,'\":\s+\"*([-\s:\/\.a-zA-Z0-9\d]*)').value.replace('"',"").replace(": ","")

        # The final cleaned up result is stored as custom powershell objects in order to export into a CSV file
        [PSCustomObject]@{
             'scanid'=$tempvariable3[0]
             'sha1'=$tempvariable3[1]
             'resource'=$tempvariable3[2]
             'response_code'=$tempvariable3[3]
             'scan_date'=$tempvariable3[4]
             'permalink'=$tempvariable3[5]
             'total'=$tempvariable3[7]
             'positives'=$tempvariable3[8]
             'sha256'=$tempvariable3[9]
             } | export-csv virustotal-results.csv -Force -append -NoTypeInformation

         start-sleep 15

    }
