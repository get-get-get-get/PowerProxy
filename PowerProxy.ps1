

<#
    Author: @GetGetGetGet (github.com/get-get-get-get)
    License: GNU GPLv3
#>


##########
# Servers
#####

function Start-ReverseSocksProxy {
    <#
    .SYNOPSIS
    Connects to remote machine and acts as Socks server to tunnel traffic out.
    .DESCRIPTION
    Connects back to remote handler, then starts job tunneling connection out as proxy.
    .EXAMPLE
    # Act as proxy for remote machine listening at 172.1.1.20, port 2200
    Invoke-ReverseSocksProxy -RemoteHost 172.1.1.20 -Port 2200

    # Require authentication
    $Password = ConvertTo-SecureString -AsPlaintext -Force "Pa$$w0rd123"
    $Cred = New-Object System.Management.Automation.PSCredential ("ProxyUser", $Password)

    .EXAMPLE
    # Verify SSL cert of remote machine, and use SystemProxy
    Invoke-ReverseSocksProxy -RemoteHost 172.1.1.20 -SystemProxy -FingerPrint 93061FDB30D69A435ACF96430744C5CC5473D44E -Verbose
    
    .PARAMETER RemoteHost
    IP address of remote handler.
    .PARAMETER RemotePort
    Port on handler to connect to. Default = 443
    .PARAMETER Certificate
    Validate remote certificate matches given fingerprint.
    .PARAMETER MaximumRetries
    Maximum consecutive attempts to connect to handler before failure.
    .PARAMETER WaitBeforeRetry
    Seconds to wait after failed connection before trying again.
    .PARAMETER Connections
    Number of connections to maintain with remote host. Default: 10
    .PARAMETER NoEncryption
    Connect to remote host without TLS
    .PARAMETER Version
    Socks version
    .PARAMETER SystemProxy
    Tunnel via default system proxy. 
    .PARAMETER Credential 
    PSCredential. Clients will require USERPASS authentication, and version is restricted to Socks5
    #>

    [Alias("Start-ReverseProxy", "Invoke-ReverseProxy", "Invoke-ReverseSocksProxy")]

    # CMDletBinding should add support for Write-Verbose, among other things
    [CMDletBinding()]

    Param (

        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $true)]
        [Alias('Rhost', 'Address', 'IP', 'HandlerAddress')]
        [string]
        $RemoteHost,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [Alias('Rport', 'Port')]
        [ValidateScript( { $_ -le 65535 })]
        [int]
        $RemotePort = 443,
    
        [Parameter(Position = 2, ValueFromPipelineByPropertyName = $true)]
        [Alias('Validate', 'Fingerprint', 'Cert')]
        [string]
        $Certificate = "",

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('UseSystemProxy')]
        [switch]
        $SystemProxy = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Cleartext', 'NoSSL', 'NoTLS')]
        [switch]
        $NoEncryption = $False,

        # TODO: accept array of credentials
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('USERPASS', 'SocksCredential')]
        [pscredential]
        $Credential,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Retries', 'MaxRetries', 'MaxRetry')]
        [int]
        $MaximumRetries = 10,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('MaxConnections', 'MaximumConnections', 'Threads')]
        [int]
        $Connections = 10,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Wait')]
        [int]
        $WaitBeforeRetry = 3,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(4, 5)]
        [Alias('SocksVersion')]
        [int[]]
        $Version = @(4, 5)
    )

    if ($Credential) {
        Write-Warning "[!] Authentication is untested and should be considered insecure!"
        if ($Version -contains 4) {
            Write-Host "[!] Only Socks5 supports authentication! Restricting version to Socks5"
            $Version = @(5)
        }

        # Does this ampersand look like a lock?
        Write-Host "Securing proxy with Username/Password authentication"
    }

    <#
    
    1. Create synchonized objects for tracking certain states (e.g. connections, failures)

    1.5 Create ScriptBlock calling Invoke-ReverseProxyWorker with args being subset of current

    2. Create thread/runspace pool, where one thread is a single connection to remote proxy handler

    3. Spin up threads via some worker function, like Invoke-ReverseProxyWorker

    4. Invoke-ReverseProxyWorker threads should report back on certain states via the synchronized objects (step 1)

    5. Invoke-ReverseProxyWorker call Start-SocksProxyConnection if they get wake sequence from remote

    6. This thread is master, monitors threads via synchronized objects, acts based on condition

    #>

    
    ###### 1.5 Create Scriptblock (Need to implement version arg better, and in future add auth info)
    
    # Args to pass to worker function
    $WorkerArgs = new-object psobject -Property @{
        RemoteHost      = $RemoteHost
        RemotePort      = $RemotePort
        Certificate     = $Certificate
        SystemProxy     = $SystemProxy
        NoEncryption    = $NoEncryption
        MaximumRetries  = $MaximumRetries
        WaitBeforeRetry = $WaitBeforeRetry
        Credential      = $Credential
        Version         = $Version
        Verbose         = ($VerbosePreference -eq "CONTINUE")
    }

    # will this work?
    $ScriptBlock = {
        $WorkerArgs | Invoke-ReverseProxyWorker -Verbose:$WorkerArgs.Verbose
    }
    

    ##### 2. Create runspace pool

    # InitialSessionState for eventual runspacepool
    $InitialSessionState = [initialsessionstate]::CreateDefault()
    
    ### stolen from stackoverflow
    # https://stackoverflow.com/questions/51818599/how-to-call-outside-defined-function-in-runspace-scriptblock
    # Add all dot-sourced functions to ISS
    # includes functions from imported modules, but NOT iex ones...
    Get-ChildItem function:\ | Where-Object Source -like "" | ForEach-Object {
        $FunctionDefinition = Get-Content "Function:\$($_.Name)"
        $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $functionDefinition
        $InitialSessionState.Commands.Add($SessionStateFunction)
    }

    # Add variables to ISS ?
    # https://stackoverflow.com/questions/38102068/sessionstateproxy-variable-with-runspace-pools
    $WorkerVariable = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'WorkerArgs', $WorkerArgs, $null
    $InitialSessionState.Variables.Add($WorkerVariable)
    

    # Create runspacepool
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Connections, $InitialSessionState, $Host)
    $RunspacePool.Open()


    ###### 3. Start threads, add to workers array
    
    # Create array to track workers. Set length to avoid creating a new one w/ '+='
    $Workers = @(1..$Connections)
    $WorkersAsync = @(1..$Connections)

    # Start workers
    for ($i = 0; $i -lt $Connections; $i++) {
        # Instantiate
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool
        $PowerShell.AddScript($ScriptBlock) | Out-Null

        # Invoke and store as psobject
        $Worker = new-object psobject -Property @{
            Powershell = $PowerShell
            AsyncResult = $PowerShell.BeginInvoke()
        }

        # Also store AsyncResult in its own array for easy status check
        $WorkersAsync[$i] = $Worker.AsyncResult
        # Add to array
        $Workers[$i] = $Worker
    }
    Write-Verbose "Spawned $Connections workers"

    ##### 6. Monitor threads

    # https://blogs.technet.microsoft.com/dsheehan/2018/10/27/powershell-taking-control-over-ctrl-c/
    # Change the default behavior of CTRL-C so that the script can intercept and use it versus just terminating the script.
    [Console]::TreatControlCAsInput = $True
    Start-Sleep -Seconds 1              # Helps flush buffer
    $Host.UI.RawUI.FlushInputBuffer()

    # TODO: implement failure monitoring, map connections to track status
    while ($WorkersAsync.IsCompleted -contains $false) {
        
        if ($Host.UI.RawUI.KeyAvailable -and ($Key = $Host.UI.RawUI.ReadKey("AllowCtrlC,NoEcho,IncludeKeyUp"))) {
            if ([Int]$Key.Character -eq 3) {
                Write-Host ""
                Write-Warning "CTRL-C detected - closing connections and exiting"
                foreach ($Worker in $Workers) {
                    $Worker.Powershell.dispose()
                    #$Worker.Powershell.EndInvoke($Worker.AsyncResult)
                }
                [Console]::TreatControlCAsInput = $False
            }
            # Flush the key buffer again for the next loop.
            $Host.UI.RawUI.FlushInputBuffer()
        }
        
    }

    [Console]::TreatControlCAsInput = $False

}   


function Start-SocksProxy {
    <#
    .SYNOPSIS
    Starts Socks proxy server
    .DESCRIPTION
    Binds to given address and listens for incoming connections to proxy forward
    .EXAMPLE
    # Run proxy server on 172.10.2.20, port 9050
    Start-SocksProxy 172.10.2.20 -Port 9050

    # Require authentication
    $Password = ConvertTo-SecureString -AsPlaintext -Force "Pa$$w0rd123"
    $Cred = New-Object System.Management.Automation.PSCredential ("ProxyUser", $Password)
    Start-SocksProxy -Address 192.168.0.24 -Credential $Cred -Verbose
    
    .PARAMETER Address
    IP address to listen bind to.
    .PARAMETER Port
    TCP Port to listen on. Default: 1080
    .PARAMETER Credential
    PSCredential with Username and Password of valid users. Forces Socks5 as version
    .PARAMETER Version
    Socks version (4 or 5)
    .PARAMETER Threads
    Number of threads for handling connections. Default: 200
    .PARAMETER Encryption
    Use TLS to encrypt connections with clients. (not implemented)
    #>

    [Alias('Invoke-BindProxy', 'Start-SocksProxy', 'Start-BindProxy', 'Start-SocksProxyServer')]

    # CMDletBinding should add support for Write-Verbose, among other things
    [CMDletBinding()]

    param (

        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('Address', 'IP', 'Host', 'Lhost', 'ListenAddress')]
        [String]
        $BindAddress,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [Alias('Port', 'Lport')]
        [ValidateScript( { $_ -le 65535 })]
        [Int]
        $BindPort = 1080,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Connections', 'MaxThreads', "MaxConnections")]
        [Int]
        $Threads = 200,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('SSL', 'TLS')]
        [switch]
        $Encryption = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('USERPASS', 'SocksCredential')]
        [pscredential]
        $Credential,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(4, 5)]
        [Alias('SocksVersion')]
        [int[]]
        $Version = @(4, 5)

    )

    if ($Credential) {
        Write-Warning "[!] Authentication is untested and should be considered insecure!"
        if ($Version -contains 4) {
            Write-Host "[!] Only Socks5 supports authentication! Restricting version to Socks5"
            $Version = @(5)
        }

        # Does this ampersand look like a lock?
        Write-Host "Securing proxy with Username/Password authentication"
    }


    <# 
    
    1. Create runspacepool for spinning clients off into a different thread

    2. Listen for connections, spin connections off into thread

    3. Track threads and connections somehow    
    
    #>



    # Args to pass to worker function
    $WorkerArgs = new-object psobject -Property @{
        Version    = $Version
        Credential = $Credential
        Verbose    = ($VerbosePreference -eq "CONTINUE")
    }

    # Scriptblock
    $ScriptBlock = {
        $WorkerArgs | Start-SocksProxyConnection -Verbose:$WorkerArgs.Verbose
    }

    # InitialSessionState for eventual runspacepool
    $InitialSessionState = [initialsessionstate]::CreateDefault()
    
    ### stolen from stackoverflow
    # https://stackoverflow.com/questions/51818599/how-to-call-outside-defined-function-in-runspace-scriptblock
    # Add all dot-sourced functions to ISS
    # includes functions from imported modules, but NOT iex ones...
    Get-ChildItem function:\ | Where-Object Source -like "" | ForEach-Object {
        $FunctionDefinition = Get-Content "Function:\$($_.Name)"
        $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $functionDefinition
        $InitialSessionState.Commands.Add($SessionStateFunction)
    }

    # Add variables to ISS ?
    # https://stackoverflow.com/questions/38102068/sessionstateproxy-variable-with-runspace-pools
    $WorkerVariable = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'WorkerArgs', $WorkerArgs, $null
    $InitialSessionState.Variables.Add($WorkerVariable)

    # TODO: How to add/use ClientStream? Won't exist at point when create pool
    # Create runspacepool
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Connections, $InitialSessionState, $Host)
    $RunspacePool.Open()

    # Track threads
    $Workers = @(1..$Threads)
    $WorkersAsync = @(1..$Threads)       
    
    # Janky counter to track threads
    $ThreadCount = 0

    # Let's also count total connections received
    $ConnectionCount = 0

    try {
        # Start listener
        $SocksListener = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($BindAddress), $BindPort)
        $SocksListener.start()

        # Create thread pool
        $ThreadPool = [runspacefactory]::CreateRunspacePool(1, $Threads);
        $ThreadPool.CleanupInterval = New-TimeSpan -Seconds 30;
        $ThreadPool.open();

        Write-Host "Listening on $BindAddress`:$BindPort"

        # Listen and serve
        while ($true) {

            # Accept incoming connection
            $Client = $SocksListener.AcceptTcpClient()
            $ClientStream = $Client.GetStream()
            Write-Verbose "[*] New Connection from " $Client.Client.RemoteEndPoint
            $ConnectionCount++

            if ($Encryption) {
                Write-Verbose "[!] ERROR: I didn't do encryption stuff yet"
                raise "Encryption bullshit"             # idk lol
            }
            
            $PowerShell = [PowerShell]::Create()
            $PowerShell.RunspacePool = $ThreadPool
            # First attempt at adding ClientStream
            $PowerShell.AddScript($ScriptBlock).AddArgument($ClientStream)

            # This'll do for now. Just make sure not overwriting worker
            if ($Workers[$ThreadCount] -is [int]) {
                $WorkersAsync[$ThreadCount] = $PowerShell.BeginInvoke()
                $Workers[$ThreadCount] = $PowerShell
                $ThreadCount++            # Increment thread count
            }
            else {
                Write-Verbose "ThreadCount: $ThreadCount"
                # Search for a spot that isn't used (lol prolly dumb)
                for ($i = 0; $i -lt $ThreadCount; $i++) {
                    if ($Workers[$i] -is [int]) {
                        $ThreadCount = $i
                        $WorkersAsync[$ThreadCount] = $PowerShell.BeginInvoke()
                        $Workers[$ThreadCount] = $PowerShell
                        break
                    }
                }
            }

            # TODO: If ThreadCount hits maximum, do something
            if ($ThreadCount -ge $Threads) {
                Write-Verbose "[!] ThreadCount maxed! Is something fucked?"
                $ThreadCount = 0
            }
            
            Write-Verbose "Threads remaining: $($ThreadPool.GetAvailableRunspaces())" 
            
        }
    }
    catch {
        throw $_
    }
    finally {
        
        Write-Verbose "Server closing..."
        Write-Host "Total connections received: $ConnectionCount"

        $WorkerResults = @(1..$Threads)
        for ($i = 0; $i -lt $Threads; $i++) {

            # Continue if not worker
            if ($Workers[$i] -is [int]) {
                continue
            }
            
            $Worker = $Workers[$i]
            $WorkerResults[$i] = $Worker.EndInvoke($WorkersAsync[$i])

            Write-Host "$($WorkerResults[$i])"

        }

        if ($null -ne $PowerShell -and $null -ne $AsyncJobResult3) {
            $PowerShell.EndInvoke($AsyncJobResult3) | Out-Null
            $PowerShell.Runspace.Close()
            $PowerShell.Dispose()
        }

        # Close connections and jobs before exiting
        if ($null -ne $SocksListener) {
            $SocksListener.Stop()
        }
        if ($null -ne $Client) {
            $Client.Dispose()
            $Client = $null
        }

        Write-Host "[-] Server closed"
        
        
    }
}

##########
# MISC
#####

function Connect-TcpStreams {
    <#
    .SYNOPSIS
    Forward TCP traffic after SOCKS connection started
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER TcpStreamA
    [System.Net.Sockets.NetworkStream]
    .PARAMETER TcpStreamB
    [System.Net.Sockets.NetworkStream] 
    #>
    [Alias('Forward-TcpStreams')]

    [CMDletBinding()]

    param (
        # Client TCP stream
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,

        # TODO: figure out type to list here, or just don't put type.
        [Parameter(Mandatory = $True, Position = 1, ValueFromPipelineByPropertyName = $true)]
        $TargetStream
    )

    # Client/Destinations Streams are asynchronously copied
    $AsyncCopyResult_A = $ClientStream.CopyToAsync($TargetStream)
    $AsyncCopyResult_B = $TargetStream.CopyToAsync($ClientStream)

    # Wait for each copy to complete
    # TODO: fix issue where this never finishes, even though client closes connection
    # Issue is that the Python handler isn't checking connection status
    $AsyncCopyResult_A.AsyncWaitHandle.WaitOne()
    $AsyncCopyResult_B.AsyncWaitHandle.WaitOne()
    Write-Host "Forwarding complete!"
    return
}

function Invoke-ReverseProxyWorker {
    <#
    .SYNOPSIS
    Connects to remote machine and acts as Socks server to tunnel traffic out.
    .DESCRIPTION
    Connects back to remote handler, then starts job tunneling connection out as proxy.
    .EXAMPLE
    # Act as proxy for remote machine listening at 172.1.1.20, port 2200
    Invoke-ReverseSocksProxy -RemoteHost 172.1.1.20 -Port 2200
    .EXAMPLE
    # Verify SSL cert of remote machine, and use SystemProxy
    Invoke-ReverseSocksProxy -RemoteHost 172.1.1.20 -SystemProxy -FingerPrint 93061FDB30D69A435ACF96430744C5CC5473D44E -Verbose
    
    .PARAMETER RemoteHost
    IP address of remote handler.
    .PARAMETER RemotePort
    Port on handler to connect to. Default = 443
    .PARAMETER SystemProxy
    Tunnel via default system proxy. 
    .PARAMETER Certificate
    Validate remote certificate matches given fingerprint.
    .PARAMETER MaximumRetries
    Attempt to connect this many times before quiting
    .PARAMETER WaitBeforeRetry
    Seconds to wait after failed connection before trying again.
    .PARAMETER NoEncryption
    Connect to remote host without TLS
    .PARAMETER Version
    Socks version
    #>

    [CMDletBinding()]

    Param (

        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $true)]
        [Alias('Rhost', 'Address', 'IP', 'HandlerAddress')]
        [string]
        $RemoteHost,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [Alias('Rport', 'Port')]
        [ValidateScript( { $_ -le 65535 })]
        [int]
        $RemotePort = 443,
    
        [Parameter(Position = 2, ValueFromPipelineByPropertyName = $true)]
        [Alias('Validate', 'Fingerprint', 'Cert')]
        [string]
        $Certificate = "",

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Cleartext', 'NoSSL', 'NoTLS')]
        [switch]
        $NoEncryption = $False,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Alias('USERPASS', 'SocksCredential')]
        [pscredential]
        $Credential,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Retries', 'MaxRetries', 'MaxRetry')]
        [int]
        $MaximumRetries = 20,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('UseSystemProxy')]
        [switch]
        $SystemProxy = $False,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('Wait')]
        [int]
        $WaitBeforeRetry = 3,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(4, 5)]
        [Alias('SocksVersion')]
        [int[]]
        $Version = @(4, 5)
    )

    # TODO: something better.
    $ProxyArgs = new-object psobject -Property @{
        RemoteHost      = $RemoteHost
        RemotePort      = $RemotePort
        Certificate     = $Certificate
        SystemProxy     = $SystemProxy
        WaitBeforeRetry = $WaitBeforeRetry
        Credential      = $Credential
        Version         = $Version
        Verbose         = ($VerbosePreference -eq "CONTINUE")
    }


    <#
    
    1. Map message from remote to appropriate reply and action
        a. 'WAKE' --> reply 'WOKE' --> Start-ProxyConnection
        b. 'KILL --> reply 'DEAD' --> signal master thread to shut shit down
    
    2. Start while loop of connecting to remote host
        a. Exceptions/failures should report to master via synchronized object (not implemented)
        b. Successful connections should be tracked via synchronized object

    3. Within (2), a while loop listening for messages from remote
        a. If messaage launches a proxy connection, that should be reported to master

    #>


    # 1. Define messages, map to reply and action
    $WakeMessage = @{
        Message = "WAKE"
        BYTES   = Convert-StringToBytes "WAKE"
        Reply   = Convert-StringToBytes "WOKE"
        Action  = "Start-SocksProxyConnection"       # TODO: add args and things
    }
    $KillMessage = @{
        Message = "KILL"
        BYTES   = Convert-StringToBytes "KILL"
        Reply   = Convert-StringToBytes "DEAD"
        Action  = "Send-KillChain"                   # TODO: something to this effect
    }

    $Messages = $WakeMessage, $KillMessage

    $ConnectFailures = 0

    # 2. Connection loop
    while ($true) {

        # SNIPPET: connection flow
        try {
            
            # Try to connect
            try {
                # Handle $SystemProxy option 
                if ($SystemProxy -eq $false) {
                    $Client = New-Object System.Net.Sockets.TcpClient($RemoteHost, $RemotePort)
                    $ClientStream_Clear = $Client.GetStream()
                }
                else {
                    $ret = Get-SystemProxy -RemoteHost $RemoteHost -RemotePort $RemotePort
                    $Client = $ret[0]
                    $ClientStream_Clear = $ret[1]
                }
                
                # Reset counter
                $ConnectFailures = 0
            }
            catch {
                if ($ConnectFailures -eq 0) {
                    Write-Warning "[!] Connection to remote host fucking failed! :)"
                }
                $ConnectFailures++
                if ($ConnectFailures -ge $MaximumRetries) {
                    Write-Warning "[!] Connection failures maxed out! Exiting"
                    return
                }
                Write-Verbose "$($MaximumRetries - $ConnectFailures) connection attempts remain"
                Start-Sleep $WaitBeforeRetry
                continue
            }
            
            # SSL - handle certificate verification options
            if ($NoEncryption) {
                $ClientStream = $ClientStream_Clear
                Write-Verbose "[+] Connected to $RemoteHost`:$RemotePort"
            }
            else {
                if ($Certificate -eq '') {
                    $ClientStream = New-Object System.Net.Security.SslStream($ClientStream_Clear, $false, ( { $true } -as [Net.Security.RemoteCertificateValidationCallback]));
                }
                else {
                    # Checks if cert hash string matches hash given in $Validate param
                    $ClientStream = New-Object System.Net.Security.SslStream($ClientStream_Clear, $false, ( { return $args[1].GetCertHashString() -eq $Certificate } -as [Net.Security.RemoteCertificateValidationCallback]));
                }
                
                # SSL - do handshake (?)
                $ClientStream.AuthenticateAsClient($RemoteHost)
                if ($ClientStream.IsAuthenticated) {
                    Write-Verbose "[+] Connected to $RemoteHost`:$RemotePort"
                }
                else {
                    Write-Error "[!] Encryption failed!"
                }
                
            }
            
            # 3. Listen for message loop
            # Read a byte at a time, only listen for start of message
            [byte[]] $Alert = ( $messages | ForEach-Object { $_.bytes[0] } )
            # Buffer to read into
            $Buffer = New-Object System.Byte[] 4

            # Set timeout
            $OldTimeout = $ClientStream.ReadTimeout
            $ClientStream.ReadTimeout = 500

            while ($true) {
                # Question: if you read from a socket that's "empty", how is that represented
                # Also, what if message is split between reads??? e.g. "00WA" "KE00"

                # Read a byte at a time
                try {
                    $ClientStream.Read($Buffer, 0, 1)
                }
                catch [System.IO.IOException] {
                   continue
                }
                
                # If byte matches start of a message, test if it's a message
                if ($Buffer[0] -in $Alert) {
                    
                    $ClientStream.ReadTimeout = $OldTimeout

                    # Read rest of message
                    $ClientStream.Read($Buffer, 1, 3)
                    # Check if message matches action
                    foreach ($key in $messages) {
                        # If it's a message, send the reply and take the action
                        if ((Compare-Object $key.bytes $buffer -SyncWindow 0).length -eq 0) {
                            $Message = $key.Message
                            Write-Verbose "Received message from handler: '$($key.Message)'"

                            # NOTE: apparently NetworkStream is not buffered and doesn't need flush()
                            # but SSLStream seems to implement it, and maybe needs flush()
                            $Buffer = $key.reply
                            $ClientStream.Write($Buffer, 0, $Buffer.length)
                            $ClientStream.Flush()
                            $Buffer = New-Object System.Byte[] 4
                        }
                    }

                    # Do the action then 
                    if ($Message) {
                        if ($Message -eq "WAKE") {
                            $ProxyArgs | Start-SocksProxyConnection $ClientStream -Verbose:$ProxyArgs.Verbose
                            break
                        }
                        elseif ($Message -eq "KILL") {
                            Send-KillChain                  # TODO
                        }
                    }
                }
            }

            # Connection complete
            $Clientstream.Close()
            $Client.Close()
            Write-Verbose "[-] Job complete, connection to $RemoteHost closed"

        }
        catch {
            # Write-Verbose "[!] ERROR in ReverseProxyWorker: $($_.Exception.Message)"
            throw $_
            # TODO: report to master thread
            # TODO: handle exception, probably just pass
        }
        finally {
            # Note: figure out the flow/order of shutting this down
            if ($Client.connected -eq $True) {
                Write-Verbose "[-] Closed connection to $RemoteHost"
            }
            $ClientStream.close()
            $Client.Close()

        }

    }
    
}


##########
# SOCKS (generic/agnostic)
#####

function Start-SocksProxyConnection {
    <#
    .SYNOPSIS
    Handles SOCKS requests
    .DESCRIPTION
    Starts SOCKS process. Called by proxy servers upon receiving connection

    .PARAMETER ClientStream
    NetStream/SSLStream object representing client connection
    .PARAMETER Version
    4 or 5. Default: both
    .PARAMETER Credential
    PSCredential. Clients will require USERPASS authentication, and version is restricted to Socks5
    .PARAMETER AcceptedMethod
    Socks5 Method to accept in negotiation
    #>

    [CMDletBinding()]

    param (
        # Client TCP stream
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,
        
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(4, 5)]
        [Alias('SocksVersion')]
        [int[]]
        $Version = @(4, 5),

        # TODO: allow array of creds
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('USERPASS', 'SocksCredential')]
        [pscredential]
        $Credential,

        # TODO: should I delete and just have $Credential mean USERPASS
        # I don't think i'm planning to do GSSAPI
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('NOAUTH', 'GSSAPI', 'USERPASS')]
        [Alias('Method', 'Authentication', 'AcceptedMethod')]
        [string[]]
        $AcceptedMethods = @("NOAUTH")

    )


    # Get proxy request (returns full request if Socks4, else Socks5 initial message)
    $SocksRequest = Read-SocksRequest $ClientStream 

    # Reject request if wrong Socks version
    if ($Version -notcontains $SocksRequest.Version) {
        Write-Verbose "Client requested Socks $($SocksRequest.Version) but only Socks $Version was allowed"
        $SocksRequest | Write-SocksResponse $Clientstream -Reject
        Write-Verbose "[-] Client rejected"
        return
    }

    # Socks5 is its own thing
    if ($SocksRequest.Version -eq 5) {
        $Socks5Message = $SocksRequest
        Start-Socks5Negotiation $Socks5Message -Credential $Credential -AcceptedMethods $AcceptedMethods
        return
    }
        
    # Otherwise, connect to destination and send response accepting request
    Write-Verbose "[_] Proxying to $($SocksRequest.DestinationAddress)`:$($SocksRequest.DestinationPort)"
    $ProxyDestination = New-Object System.Net.Sockets.TcpClient($SocksRequest.DestinationAddress, $SocksRequest.DestinationPort)
    if ($ProxyDestination.Connected) {
        $SocksRequest | Write-SocksResponse $ClientStream
    }

    # Reject if connection failed
    else {
        Write-Host "[!] Connection FAILED!"
        $SocksRequest | Write-SocksResponse -Reject
        return
    }
    $ProxyDestinationStream = $ProxyDestination.GetStream()

    # Start Forwarding
    Connect-TcpStreams $ClientStream $ProxyDestinationStream
    return
}


function Read-SocksRequest {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    .PARAMETER AcceptedMethod
    Socks5 Method to accept in negotiation
    TODO, allow an array of accepted methods
    #>

    [CMDletBinding()]

    param (
        # Client TCP stream
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream

    )

    $Buffer = New-Object System.Byte[] 32

    # NOTE: NetworkStream Read/Write has signature: (byte[] buffer, int offset, int size)
    $ClientStream.Read($Buffer, 0, 1) | Out-Null

    # Socks version
    $Version = $Buffer[0]
  
    if ($Version -eq 4) {
        # Read request 
        $SocksRequest = Read-Socks4Request $ClientStream
        
    }
    elseif ($Version -eq 5) {
        
        # Read initial message indicating client's desired auth methods
        $Socks5Message = Read-Socks5Message $ClientStream
        $SocksRequest = $Socks5Message
        
    }

    $SocksRequest
}


function Write-SocksResponse {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    .PARAMETER DestinationAddress
    Requested destination
    .PARAMETER DestinationAddressType
    Type of address found in request. Only needed for Socks5
    .PARAMETER DestinationPort
    Requested port
    .PARAMETER Reject
    Rejects Socks4 request (default is to accept)
    TODO: Implement BND.ADDR and BND.PORT for socks5. Doesn't seem  to matter so I'm ignoring atm
    #>

    [CMDletBinding()]

    param (
        # Client TCP stream
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Net.IPAddress]
        $DestinationAddress,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [int]
        $DestinationPort,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(4, 5)]
        [Alias('SocksVersion')]
        [int]
        $Version,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('IPv4', 'IPv6', 'DN')]
        [string]
        $DestinationAddressType = "IPv4",

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Reject = $false
    )

    # Apparently that doesn't work, b/c of some shit I don't like
    # $ContextArgs = $PSBoundParameters

    if ($Version -eq 4) {
        # Testing by remove reject param
        Write-Socks4Response -ClientStream $ClientStream -DestinationAddress $DestinationAddress -DestinationPort $DestinationPort -Reject:$Reject
    }
    else {
        Write-Host "Sending Socks5 response (will fuck up apparently)"
        # NOTE: this will fuck up
        $ContextArgs | Write-Socks5Response
    }
}



##########
# SOCKS-4 functions
#####


function Read-Socks4Request {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    
    #>

    param (
        # Client TCP stream, with 1 byte already read (version)
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream

    )

    [CMDletBinding()]

    $Version = 4

    # Buffer for reading from ClientStream
    $Buffer = New-Object System.Byte[] 32

    # Read known parts of message (7 bytes b/c already read version)
    $ClientStream.Read($Buffer, 0, 7) | Out-Null
    
    # Parse CD
    if ($Buffer[0] -eq 1) {
        $Command = 'CONNECT'
    }
    elseif ($Buffer[0] -eq 2) {
        $Command = 'BIND'
    }
    else {
        $Command = $null
    }

    # Parse DSTPORT
    $DestPort = ($Buffer[1] * 256) + $Buffer[2]

    # Parse DSTIP (IPv4 only)   
    [Byte[]] $AddressBytes = $Buffer[3..6]
    $DestAddress = New-Object System.Net.IPAddress(, $AddressBytes)

    # Read and parse USERID (null-byte delimited)
    for ($i = 0; $i -le ($Buffer.Length - 1); $i++) {
        $ClientStream.Read($Buffer, $i, 1) | Out-Null
        Write-Host $Buffer[$i]
        if ($Buffer[$i] -eq 0) {
            $UserID = [System.Text.Encoding]::ascii.GetString($Buffer[0..$i])
            break
        }
    }
    


    # Instantiate some object
    $Socks4Request = new-object psobject -property @{
        ClientStream       = $ClientStream
        Version            = $Version
        Command            = $Command 
        DestinationAddress = $DestAddress
        DestinationPort    = $DestPort
        UserID             = $UserID
    }

    $Socks4Request
}

function Write-Socks4Response {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    .PARAMETER DestinationAddress
    Requested IPv4 destination
    .PARAMETER DestinationPort
    Requested port
    .PARAMETER Reject
    Rejects Socks4 request (default is to accept)
    #>

    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,

        # Unnecessary, consider deleting
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Net.IPAddress]
        $DestinationAddress,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [int]
        $DestinationPort,

        # Unnecessary, consider deleting
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Reject
    )

    # Use buffer to prep reply
    $Buffer = New-Object System.Byte[] 8

    # Write Response code
    $Buffer[1] = 90            # Accept code
    if ($Reject) {
        $Buffer[1] = 91        # Reject code (generic)
        Write-Host "Rejecting request"
    }

    # Send reply to client
    $ClientStream.Write($Buffer, 0, $Buffer.Length)
    $ClientStream.Flush()

}

##########
# SOCKS-5 functions
#####


function Start-Socks5Negotiation {
    <#
    .SYNOPSIS
    Starts SOCKS5 process after receiving initial message
    
    .PARAMETER Socks5Message
    PSobject representing initial message from client. Has properties: ClientStream,Version,Methods
    #>

    [CMDletbinding()]
    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('SocksMessage', 'Message')]
        [psobject]
        $Socks5Message,

        # TODO: allow array of creds
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('USERPASS', 'SocksCredential')]
        [pscredential]
        $Credential,

        # TODO: should I delete and just have $Credential mean USERPASS
        # I don't think i'm planning to do GSSAPI
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('NOAUTH', 'GSSAPI', 'USERPASS')]
        [Alias('Method', 'Authentication', 'AcceptedMethod')]
        [string[]]
        $AcceptedMethods = @("NOAUTH")
    )

    # debug
    Write-Host "Starting Socks5 negotiation"

    ##########
    # Negotiation
    #####

    # Select a method, send
    if ($AcceptedMethods -in $Socks5Message.Methods) {

        # Select a method
        $ChosenMethod = ""
        if ($Credential) {
            if ($AcceptedMethods -contains "GSSAPI") {
                $ChosenMethod = "GSSAPI"
                Write-Host "Fuck off, no GSSAPI"
                Write-Socks5MessageReply $ClientStream -Reject
                return
            }
            else {
                $ChosenMethod = "USERPASS"
            }
            Write-Verbose "[&] Using $ChosenMethod authentication"
        }
        else {
            if ($AcceptedMethods -contains "NOAUTH") {
                $ChosenMethod = "NOAUTH"
            }
            Write-Verbose "Using $ChosenMethod method"
        }

        # Reply with chosen method
        Write-Socks5MessageReply $ClientStream -AcceptedMethod $ChosenMethod

        # Do method-specific negotiation
        if ($ChosenMethod -eq "USERPASS") {
            $AuthenticationStatus = Confirm-Socks5UserPass $ClientStream -Credential $Credential
            Write-Host "Authentication Status: $AuthenticationStatus"

        }
        elseif ($ChosenMethod -eq "GSSAPI") {
            write-host "how did u get here"
        }
        else {

        }
    }
    # No acceptable methods; reject, return and close
    else {
        Write-Socks5MessageReply $ClientStream -Reject
        return
    }

    ##########
    # Socks5 for real
    #####

    <#
    $Socks5Request
        $Socks5Request = New-object psobject -Property 
        ClientStream           = $ClientStream
        Version                = $Version
        Command                = $Command 
        DestinationAddress     = $DestAddress
        DestinationPort        = $DestPort
        DestinationDomainName  = $DestDN
        DestinationAddressType = $AddressType       
    
    #>

    # Read actual Socks5 request. Expect object shown above
    $SocksRequest = Read-Socks5Request $ClientStream


}


function Read-Socks5Message {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    #>

    [CMDletBinding()]

    param (
        # Client TCP stream
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream
    )

    $Buffer = New-Object System.Byte[] 2
    
    # Read nmethods
    $ClientStream.Read($Buffer, 0, 1)
    $NMethods = $Buffer[0]
    
    # Read methods
    $Buffer = New-Object System.Byte[] $Nmethods
    $ClientStream.Read($Buffer, 0, $NMethods)
    $Methods = @()
    for ($i = 0; $i -le $Nmethods; $i++) {
        if ($Buffer[$i] -eq 0) {
            $Methods += "NOAUTH"
        }
        elseif ($Buffer[$i] -eq 1) {
            $Methods += "GSSAPI"
        }
        elseif ($Buffer[$i] -eq 2) {
            $Methods += "USERPASS"
        }
        # NOTE: there are a couple more assigned, but I don't wanna fuck with atm
    }

    $Socks5Message = new-object psobject -Property @{
        ClientStream = $ClientStream
        Version      = 5
        Methods      = $Methods
    }

    return $Socks5Message
}

function Write-Socks5MessageReply {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    .PARAMETER AcceptedMethod
    Method to accept in negotiation
    .PARAMETER Reject
    Send reply indicating no acceptable methods
    #>

    [CMDletBinding()]

    param (
        # Client TCP stream
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('NOAUTH', 'GSSAPI', 'USERPASS')]
        [Alias('Method')]
        [string[]]
        $AcceptedMethods = "NOAUTH",

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [bool]
        $Reject
    )

    $Buffer = new-object system.Byte[] 2

    # TODO: validate that this is supposed to be 5 and not 0 or something (VER field)
    $Buffer[0] = 5

    if ($Reject) {
        $Buffer[1] = 255
    }
    else {
        switch ($AcceptedMethods) {
            "NOAUTH" { $Buffer[1] = 0; break }
            "GSSAPI" { $Buffer[1] = 1; break }
            "USERPASS" { $Buffer[1] = 2; break }
        }
    }
    

    $ClientStream.Write($Buffer, 0, $Buffer.Length)
    $ClientStream.Flush()
}

function Confirm-Socks5UserPass {

    <#
    .SYNOPSIS 
    Performs USERPASS subnegotiation
    
    #>
    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,
    
        [Parameter(Mandatory = $True, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [Alias('USERPASS', 'SocksCredential')]
        [pscredential]
        $Credential
    )

    <# 
    https://tools.ietf.org/html/rfc1929

    Fields (REQUEST):
        VER: 1 byte, subnegotiation version (must be 1)
        ULEN: 1 byte, username length
        UNAME: n bytes, username
        PLEN: 1 byte, password length
        PASSWD: n bytes, password
    
    Fields (RESPONSE): 
        VER: 1 byte, subnegotiation version (must be 1)
        STATUS: 1 byte, 0 is success, anything else is fail
    #>

    $ValidAuthentication = $false 


    $Buffer = new-object byte[] 32
    
    # debug
    Write-Host "Readings USERPASS request"

    $ClientStream.Read($Buffer, 0, 2) | Out-Null

    if ($Buffer[0] -ne 1) {
        $ValidAuthentication
        Write-Host "[!] Invalid subnegotiation version: $($Buffer[0]). Rejecting"
        return
    }

    ##### USERNAME
    $UnameLen = $Buffer[1]
    Write-Host "Username length: $UnameLen bytes"
    # Probably safe to just create a buffer of this size since only 1 byte
    $Buffer = new-object byte[] $UnameLen
    $ClientStream.Read($Buffer, 0, $UnameLen) | Out-Null
    Write-Host "Username bytes: $Buffer"

    $Username = Convert-BytesToString $Buffer
    Write-Host "Username: $Username"

    ##### PASSWORD
    $ClientStream.Read($Buffer, 0, 1) | Out-Null
    $PasswdLen = $Buffer[0]
    Write-Host "Password length: $PasswdLen bytes"
    $Buffer = new-object byte[] $PasswdLen
    $ClientStream.Read($Buffer, 0, $PasswdLen) | Out-Null
    Write-Host "Password bytes: $Buffer"
    # Probably somewhat insecure to do this, but:
    $PlaintextPassword = Convert-BytesToString $Buffer
    Write-Host "Password: $PlaintextPassword"
    # Make credential
    $Password = ConvertTo-SecureString -AsPlainText -Force $PlaintextPassword
    $ClientCredential = New-Object System.Management.Automation.PSCredential($Username, $Password)

    ##### VALIDATE
    Write-Host "Validating client credentials..."
    $ValidAuthentication = Confirm-SocksCredential -ClientCredential $ClientCredential -ValidCredential $Credential 
    if ($ValidAuthentication) {
        Write-Verbose "[&] Client authenticated!"
    }
    else {
        Write-Warning "[!] Received invalid credentials!"
    }
    
    ##### RESPOND
    $Buffer = byte[] 2
    $Buffer[0] = 1          # VER - subnegotiation version
    $Buffer[1] = 1          # Default fail

    if ($ValidAuthentication) {
        $Buffer[1] = 0      # Success
    }

    $ClientStream.Write($Buffer, 0, $Buffer.Length)
    $ClientStream.Flush()

    # Immediately close connection if auth failed
    if ($ValidAuthentication -eq $false) {
        $ClientStream.Close()
        Write-Verbose "[-] Closed connected to unauthorized client"
        return
    }
}

function Write-Socks5UserPassResponse {
    
    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,
    
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Reject
    )

    $Buffer = byte[] 2

    $Buffer[0] = 1          # VER - subnegotiation version
    $Buffer[1] = 0          # STATUS - 0 is success
    if ($Reject) {
        $Buffer[1] = 2      # fail is anything by 0 (TODO: must immediately close connection)
    }

    Write-Host "Sending UserPass response: $Buffer"
    $ClientStream.Write($Buffer, 0, $Buffer.length)
    $ClientStream.Flush()
}


function Read-Socks5Request {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    
    #>

    [CMDletBinding()]

    param (
        # Client TCP stream, with 1 byte already read (version)
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream

    )
    
    $Buffer = new-object system.Byte[] 32
    $ClientStream.Read($Buffer, 0, 4)

    $Version = $Buffer[0]
    
    # Read CMD (NOTE: will throw error if not one of these, but would probably be error anyway)
    switch ($Buffer[1]) {
        1 { $Command = 'CONNECT'; break }
        2 { $Command = 'BIND'; break }
        3 { $Command = 'UDP'; break }
    }

    # Read ATYP
    switch ($Buffer[3]) {
        1 { $AddressType = "IPv4"; break }
        3 { $AddressType = "DN"; break }
        4 { $AddressType = "IPv6"; break }
    }

    # Read DST.ADDR
    if ($AddressType -eq "DN") {
        $ClientStream.Read($Buffer, 0, 1)
        $NameLength = $Buffer[0]
        $ClientStream.Read($Buffer, 0, $NameLength)
        
        $DestDN = Convert-BytesToString $Buffer[0..($NameLength - 1)]
        $DestAddress = Resolve-DomainName $DestDN
    }
    elseif ($AddressType -eq "IPv4") {
        $ClientStream.Read($Buffer, 0, 4)
        $DestAddress = $System.Net.IPAddress($Buffer[0..3])
    }
    else {
        $ClientStream.Read($Buffer, 0, 16)
        $DestAddress = $System.Net.IPAddress($Buffer[0..15])
    }

    # Read DST.PORT
    $ClientStream.Read($Buffer, 0, 2)
    $DestPort = Convert-BytesToInt $Buffer[0..1]

    $Socks5Request = New-object psobject -Property @{
        ClientStream           = $ClientStream
        Version                = $Version
        Command                = $Command 
        DestinationAddress     = $DestAddress
        DestinationPort        = $DestPort
        DestinationDomainName  = $DestDN
        DestinationAddressType = $AddressType
    }
    return $Socks5Request
}

function Write-Socks5Response {
    <#
    .SYNOPSIS
    TODO
    .DESCRIPTION
    TODO
    .EXAMPLE

    .PARAMETER ClientStream
    NetStream object representing client connection
    .PARAMETER BoundAddress
    TODO
    .PARAMETER BoundPort
    TODO
    .PARAMETER Reject
    Rejects Socks5 request (default is to accept)
    #>

    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        $ClientStream,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [bool]
        $Reject = $false
    )

    $Version = 5
    if ($Reject) {
        $ReplyCode = 1
    }
    else {
        $ReplyCode = 0
    }
    $BoundAddressType = 1       # IPv4 (I don't think this matters)
    $BoundAddress = [System.Net.IpAddress]::Parse("127.0.0.1").getbytes   # Don't think this matters
    $BoundPort = Convert-IntToBytes 42899 -Size 2                         # Don't think this matters, picked random
    
    # Make buffer length of response message
    $Buffer = New-Object System.Byte[] (5 + $BoundAddress.length)

    # Write variables to buffer, with 2nd byte being a reserved field
    $Buffer[0] = $Version
    $Buffer[1] = $ReplyCode
    $Buffer[3] = $BoundAddressType
    # Write address to buffer
    for ($i = 0; $i -le $BoundAddress.length; $i++) {
        $Buffer[($i + 4)] = $BoundAddress[$i]
    }
    # Write port to buffer
    $Buffer[-2] = $BoundPort[0]
    $Buffer[-1] = $BoundPort[1]

    # Send response
    $ClientStream.Write($Buffer, 0, $Buffer.Length)
    $ClientStream.Flush()
}

##########
# Authentication functions
#####

function Confirm-SocksCredential {

    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('UserCredential')]
        [pscredential]
        $ClientCredential,

        [Parameter(Mandatory = $True, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [pscredential]
        $ValidCredential
    )

    $UsernamesMatch = $false
    $PasswordsMatch = $false


    # Easier to work w/
    $UserNetCredential = $ClientCredential.GetNetworkCredential()
    $ValidNetCredential = $ValidCredential.GetNetworkCredential()

    # TODO: figure out proper syntax for sensitive comparisons
    $UsernamesMatch = ($UserNetCredential.Username -eq $ValidNetCredential.UserName)
    if ($UsernamesMatch) {
        $PasswordsMatch = ($UserNetCredential.Password -ceq $ValidNetCredential.Password)
    }

    # Okay this is lazy but:
    $PasswordsMatch

}


##########
# Helper functions
#####

# Utility function for using System's native proxy (IDK shit about this)
function Get-SystemProxy {

    [CMDletBinding()]

    param (

        [String]
        $RemoteHost,

        [Int]
        $RemotePort

    )

    $Request = [System.Net.HttpWebRequest]::Create("http://" + $RemoteHost + ":" + $RemotePort ) 
    $Request.Method = "CONNECT";

    $SystemProxy = [System.Net.WebRequest]::GetSystemWebProxy();
    $SystemProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;

    $Request.Proxy = $SystemProxy;
    $Request.timeout = 1000;

    $ServerResponse = $Request.GetResponse();
    $Request.timeout = 100000;
    $ResponseStream = $ServerResponse.GetResponseStream()

    $BindingFlags = [Reflection.BindingFlags] "NonPublic,Instance"
    $ResponseStreamType = $ResponseStream.GetType()
    $ConnectionProperty = $ResponseStreamType.GetProperty("Connection", $BindingFlags)
    $Connection = $ConnectionProperty.GetValue($ResponseStream, $null)
    $ConnectionType = $Connection.GetType()
    $NetworkStreamProperty = $ConnectionType.GetProperty("NetworkStream", $BindingFlags)
    $ServerStream = $NetworkStreamProperty.GetValue($Connection, $null)

    return $Connection, $ServerStream
}


# Helper function to resolve domain names, returning IP address. (IDK)
function Resolve-DomainName {
    <#
    .SYNOPSIS
    Resolves domain name
    
    .PARAMETER Domain
    Domain name
    .PARAMETER AsString
    Return address as string (otherwise it's IPAddress object)
    #>

    [CMDletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [String]
        $Domain,

        [Parameter(Position = 1)]
        [Switch]
        $AsString
    )

    # Get the first address
    $IP = [System.Net.Dns]::GetHostAddresses($Domain)[0]
    
    if ($AsString) {
        $IP.IPAddressToString
    }
    else {
        $IP
    }
}


function Convert-IntToBytes {

    <#
    .SYNOPSIS
    Converts integer into byte array
    .DESCRIPTION
    Converts integer into byte array
    .EXAMPLE
    TODO

    .PARAMETER Int
    String (ascii) or integer
    .PARAMETER Size
    Return an array of this size  
    #>

    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [int]
        $InputInt,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [alias('size')]
        [int]
        $OutputSize
    )

    $Result = [System.BitConverter]::GetBytes($InputInt)
    if ($OutputSize) {
        $Result = $Result[0..($OutputSize - 1)]
    }

    $Result
}

function Convert-BytesToInt {
    <#
    .SYNOPSIS
    Converts byte array to integer
    .DESCRIPTION
    Converts byte arrays of length <= 8 to integer (either int16, int32, or int64)
    .EXAMPLE
    # Convert range of an array into integer (returns int32)
    Get-Int $Buffer[0..3]

    .PARAMETER Bytes
    Byte array. Max length: 8
    #>

    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0)]
        [Byte[]]
        [ValidateScript( { $_.length -le 8 })]
        $Bytes 
    )

    if ($Bytes.length -lt 4) {
        [System.BitConverter]::ToInt16($Bytes, 0)
    }
    elseif ($Bytes.length -eq 4) {
        [System.BitConverter]::ToInt32($Bytes, 0)
    }
    else {
        [System.BitConverter]::ToInt64($Bytes, 0)
    }
}


function Convert-StringToBytes {

    <#
    .SYNOPSIS
    Converts a string into byte array
    .DESCRIPTION
    Converts (ascii) string into byte array
    .EXAMPLE
    TODO

    .PARAMETER String
    String (ascii) or integer
    .PARAMETER Unicode
    Return Unicode bytes
    #>

    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        $String,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [bool]
        $Unicode
    )

    if ($Unicode) {
        [system.text.encoding]::unicode.getbytes($String)
    }
    else {
        [system.text.encoding]::ascii.getbytes($String)
    }

}

function Convert-BytesToString {
    <#
    .SYNOPSIS
    Converts byte array to ascii
    .DESCRIPTION
    Converts byte arrays to ascii strings
    .EXAMPLE
    TODO
    .PARAMETER Bytes
    Byte array. Max length: 8
    .PARAMETER Unicode
    Bytes are unicode
    #>

    [CMDletBinding()]

    param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Byte[]]
        $Bytes,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)]
        [bool]
        $Unicode
    )

    if ($Unicode) {
        [system.text.encoding]::unicode.GetString($Bytes)
    }
    else {
        [system.text.encoding]::ascii.GetString($Bytes)
    }
}
