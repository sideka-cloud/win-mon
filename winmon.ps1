# Define the log directory and file naming format
$logDir = "C:\Logs\ProcessMonitor"
$logFilePrefix = "sysmon"
$logFileDateFormat = "ddMMM" # e.g., 10Mar
$retentionDays = 7

# Create the log directory if it doesn't exist
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

# Function to get the private working set using performance counters
function Get-PrivateWorkingSet {
    param (
        [int]$processId
    )
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process) {
        # Replace invalid characters in the process name
        $processName = $process.ProcessName -replace '[()#]', '_'
        $counterPath = "\Process($processName)\Working Set - Private"
        try {
            $counter = Get-Counter -Counter $counterPath -ErrorAction Stop
            return $counter.CounterSamples[0].CookedValue
        } catch {
            # Fallback to WorkingSet64 if the counter is not available
            return $process.WorkingSet64
        }
    }
    return 0
}

# Function to take a snapshot of process data
function Get-CPUUsageSnapshot {
    $snapshot = @{}
    foreach ($p in Get-Process) {
        # Skip the Memory Compression process
        if ($p.Name -eq "Memory Compression") { continue }

        $privateMemory = Get-PrivateWorkingSet -processId $p.Id
        $snapshot[$p.Id] = @{
            Name = $p.Name
            Id = $p.Id
            CPU = $p.CPU
            PrivateMemory = $privateMemory
            Path = $p.Path
        }
    }
    return $snapshot
}

# Function to get the top 20 processes by CPU and RAM
function Get-TopProcesses {
    $logicalProcessors = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors

    # Take two snapshots 1 second apart
    $before = Get-CPUUsageSnapshot
    Start-Sleep -Seconds 1
    $after = Get-CPUUsageSnapshot

    $processes = @()

    foreach ($id in $after.Keys) {
        if ($before.ContainsKey($id)) {
            $deltaCPU = $after[$id].CPU - $before[$id].CPU
            if ($deltaCPU -lt 0) { continue }  # skip if CPU time decreased (process restarted)

            $cpuPercent = [math]::Round(($deltaCPU / 1) / $logicalProcessors * 100, 2)
            if ($cpuPercent -gt 100) { $cpuPercent = 100 }

            $processes += [PSCustomObject]@{
                Name        = $after[$id].Name
                Id          = $after[$id].Id
                CPUPercent  = $cpuPercent
                PrivateMemory = $after[$id].PrivateMemory
                Path        = $after[$id].Path
            }
        }
    }

    # Sort and select top 20 by CPU and RAM (private memory)
    $topCPU = $processes | Sort-Object CPUPercent -Descending | Select-Object -First 20
    $topRAM = $processes | Sort-Object PrivateMemory -Descending | Select-Object -First 20

    return @{
        TopCPU = $topCPU
        TopRAM = $topRAM
    }
}

# Function to calculate total CPU and RAM usage
function Get-SystemUsageSummary {
    $logicalProcessors = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors

    # Take two snapshots 1 second apart
    $before = Get-CPUUsageSnapshot
    Start-Sleep -Seconds 1
    $after = Get-CPUUsageSnapshot

    $totalCPU = 0

    foreach ($id in $after.Keys) {
        if ($before.ContainsKey($id)) {
            $deltaCPU = $after[$id].CPU - $before[$id].CPU
            if ($deltaCPU -lt 0) { continue }  # skip if CPU time decreased (process restarted)

            $cpuPercent = [math]::Round(($deltaCPU / 1) / $logicalProcessors * 100, 2)
            $totalCPU += $cpuPercent
        }
    }

    # Cap total CPU usage at 100%
    if ($totalCPU -gt 100) { $totalCPU = 100 }

    # Get total and available physical memory using WMI
    $os = Get-WmiObject Win32_OperatingSystem
    $totalMemory = $os.TotalVisibleMemorySize * 1KB
    $freeMemory = $os.FreePhysicalMemory * 1KB
    $usedMemory = $totalMemory - $freeMemory
    $ramUsagePercent = [math]::Round(($usedMemory / $totalMemory) * 100, 2)

    return @{
        TotalCPU = $totalCPU
        TotalRAM = $ramUsagePercent
    }
}

# Function to write logs to a file
function Write-Log {
    param (
        [string]$logFilePath,
        [string]$logContent
    )
    Add-Content -Path $logFilePath -Value $logContent
}

# Function to clean up old log files
function Remove-OldLogs {
    $cutoffDate = (Get-Date).AddDays(-$retentionDays)
    Get-ChildItem -Path $logDir -Filter "$logFilePrefix*.log" | Where-Object {
        $_.LastWriteTime -lt $cutoffDate
    } | Remove-Item -Force
}

# Function to format process information as a table
function Format-ProcessTable {
    param (
        $processes
    )
    $table = @()
    foreach ($process in $processes) {
        $memoryUsage = [math]::Round($process.PrivateMemory / 1MB, 2) # Convert to MB
        $commandLine = if ($process.Path) { $process.Path } else { "N/A" }

        $table += [PSCustomObject]@{
            Name        = $process.Name
            PID         = $process.Id
            CPU         = "$($process.CPUPercent)%"
            Memory      = "$memoryUsage MB"
            CommandLine = $commandLine
        }
    }
    return $table
}

# Main loop to monitor processes every 60 seconds
while ($true) {
    # Get the current date for the log file name
    $logDate = Get-Date -Format $logFileDateFormat
    $logFilePath = Join-Path -Path $logDir -ChildPath "$logFilePrefix`_$logDate.log"

    # Get the top processes
    $processes = Get-TopProcesses

    # Get system usage summary
    $systemUsage = Get-SystemUsageSummary

    # Prepare log content
    $logContent = @()
    $logContent += "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $logContent += "System Usage Summary:"
    $logContent += "  Total CPU Usage: $($systemUsage.TotalCPU)%"
    $logContent += "  Total RAM Usage: $($systemUsage.TotalRAM)%"
    $logContent += "-------------------------------"
    $logContent += "=== Top 20 Processes by CPU ==="
    $logContent += (Format-ProcessTable -processes $processes.TopCPU | Format-Table -AutoSize | Out-String).Trim()
    $logContent += ""
    $logContent += "=== Top 20 Processes by RAM ==="
    $logContent += (Format-ProcessTable -processes $processes.TopRAM | Format-Table -AutoSize | Out-String).Trim()
    $logContent += ""

    # Write log content to the file
    Write-Log -logFilePath $logFilePath -logContent ($logContent -join "`r`n")

    # Clean up old log files
    Remove-OldLogs

    # Wait for 60 seconds before the next iteration
    Start-Sleep -Seconds 60
}