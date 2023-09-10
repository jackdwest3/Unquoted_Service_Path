# Import Syncro Module
Import-Module $env:SyncroModule

# List of individual services on the machine
$InstalledServices = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue

# Empty list to collect paths needing fixes
$VulnerablePaths = @()
$CorrectedPaths = @()

foreach ($IndividualService in $InstalledServices) {
    $ImagePath = $IndividualService.GetValue("ImagePath", $null)

    if ($ImagePath) {
        # Split the ImagePath into the path and arguments
        $splitResult = [System.Text.RegularExpressions.Regex]::Match($ImagePath, "^(.*\.\w+)")
        $pathUpToExtension = $splitResult.Groups[1].Value

        # Check if path up to extension has a space and isn't enclosed in quotes
        if ($pathUpToExtension.Contains(" ") -and (-not $ImagePath.StartsWith('"')) -and (-not $ImagePath.EndsWith('"'))) {
            $VulnerablePaths += $ImagePath
        }
    }
}

# If there are vulnerable paths, create a ticket and list them
if ($VulnerablePaths.Count -gt 0) {

    # Logging activity for identified vulnerabilities
    Log-Activity -Message "Vulnerable service paths identified for correction." -EventName "Vulnerability Identified"

    # Create ticket
    $ticketInfo = Create-Syncro-Ticket -Subject "Vulnerable Service Path Found" -IssueType "Security" -Status "New"
    $ticketId = $ticketInfo.ticket.id

    # Start the timer
    $startDateTime = Get-Date

    # Add initial comment
    Create-Syncro-Ticket-Comment -TicketIdOrNumber $ticketId -Subject "Initial Issue" -Body "Found vulnerable service path(s) that need to be fixed for vulnerabilities."

    # Add diagnosis comment with the list of vulnerable paths
    $diagnosisBody = $VulnerablePaths -join "`r`n"
    Create-Syncro-Ticket-Comment -TicketIdOrNumber $ticketId -Subject "Diagnosis" -Body $diagnosisBody

    # Add updte comment that creating restore point
    Create-Syncro-Ticket-Comment -TicketIdOrNumber $ticketId -Subject "Update" -Body "Creating Windows restore point."

    # Create a System Restore Point
    Checkpoint-Computer -Description "Before Service Path Corrections" -RestorePointType "Modify_Settings"
    # Logging activity for restore point
    Log-Activity -Message "System restore point created." -EventName "Restore Point Created"

    # Make sure backup folders are present
    ## Check if C:\Support directory exists and create if not
    if (!(Test-Path "C:\Support")) {
        mkdir "C:\Support";
    }
    $backupFolder = "C:\Support\RegBackups"
    if (-not (Test-Path $backupFolder)) {
       New-Item -Path $backupFolder -ItemType Directory
    }
        
    # Backup and correct the entries in the registry
    foreach ($path in $VulnerablePaths) {
        $service = $InstalledServices | Where-Object { $_.GetValue("ImagePath", $null) -eq $path }

        # Let's print out the PSChildName value for debugging
        Write-Host "Service PSChildName: $($service.PSChildName)"

        Write-Host "Inspecting Service Object:"
        $service | Format-List * | Out-String | Write-Host # This will print out all properties of the service object

        # Check for existing .reg files and adjust the filename accordingly
        $counter = 1
        $baseFileName = $service.PSChildName
        $currentFileName = $baseFileName + ".reg"
        while (Test-Path (Join-Path -Path $backupFolder -ChildPath $currentFileName)) {
            $currentFileName = "${baseFileName} (${counter}).reg"
            $counter++
        }

        $backupPath = Join-Path -Path $backupFolder -ChildPath ($service.PSChildName + ".reg")
        Write-Host "Constructed backup path: $backupPath" # Debugging line

        # Transform to REG compatible format
        $regFormatPath = $service.PSPath -replace 'Microsoft.PowerShell.Core\\Registry::', ''
    
        # Log the transformed path (for debugging)
        Write-Host "Attempting to export: $regFormatPath"

        # Try exporting the registry path and handle any exceptions
        try {
            & reg export $regFormatPath $backupPath
        } catch {
            Write-Error "Failed to export $regFormatPath. Error: $_"
        }

        # Correct the registry value
        Set-ItemProperty -Path $service.PSPath -Name "ImagePath" -Value "`"$path`""
        $CorrectedPaths += $path

        # Logging activity for each corrected path
        Log-Activity -Message "Corrected vulnerable service path: $path" -EventName "Vulnerability Corrected"
    }

    # Add 'Completed' comment with the list of corrected paths
    $completedBody = "Corrected vulnerability in service paths of the following:`r`n" + ($CorrectedPaths -join "`r`n")
    Create-Syncro-Ticket-Comment -TicketIdOrNumber $ticketId -Subject "Completed" -Body $completedBody

    # End the timer and calculate the rounded duration
    $endDateTime = Get-Date
    $timeTaken = $endDateTime - $startDateTime
    # Calculate the duration in minutes, rounded up to the nearest 5 minutes
    $roundedMinutes = [math]::Ceiling($timeTaken.TotalMinutes / 5) * 5

    # This ensures the following:
    # 0-4 minutes -> 5 minutes
    # 5-9 minutes -> 10 minutes
    # 10-14 minutes -> 15 minutes
    # ... and so on

    # Ensure a minimum of 5 minutes is recorded
    if ($durationMinutes -lt 5) {
        $durationMinutes = 5
    }

    # Post timer entry to the ticket
    # Calculate the start time for the entry based on duration
    $startAt = (Get-Date).AddMinutes(-$durationMinutes).toString("o")

    # Add timer entry to the ticket
    Create-Syncro-Ticket-TimerEntry -TicketIdOrNumber $ticketId -StartTime $startAt -DurationMinutes $durationMinutes -Notes "Vulnerable service path correction." -UserIdOrEmail "jack@westcomputers.com" -ChargeTime "true"

    # Simply updates a ticket, only currently supports status and custom fields.
    Update-Syncro-Ticket -TicketIdOrNumber $ticketId -Status "Resolved"
}