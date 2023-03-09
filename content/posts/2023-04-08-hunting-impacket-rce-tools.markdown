---
title: Hunting for Impacket's Remote Code Execution Tools
author: misthi0s
categories: ["detections"]
tags: [detections, impacket, smb, wmi, dcom. rce]
date: 2023-04-08 16:20:00
---

Impacket is an open-source collection of Python libraries that can be used to construct and manipulate network protocols. At its core, it provides low-level programmatic access to packets and, in some cases, complete protocol implementations. The GitHub repository for Impacket can be found [here](https://github.com/fortra/impacket).

Within the repository, Impacket contains a number of example scripts on how its modules can be utilized. These scripts show just how powerful Impacket can be in an offensive context; there are example scripts that allow for such things as performing a [Kerberoasting](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) or [DCSync](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) attack, [relaying NTLM credentials](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), and generating [Kerberos tickets](https://github.com/fortra/impacket/blob/master/examples/getTGT.py). It also includes scripts to remotely execute commands on a system via a number of different protocols.

## SMBExec

smbexec.py is an Impacket script that allows for the execution of commands against a remote system via SMB. SMBExec works by creating a temporary service on the target machine with a specially crafted command set as the service execution. This service command contains the following properties:
	- The command to be executed, `echo`'ed into a bat file
	- `stdout` and `stderr` outputs redirected to a temporary output file
	- The execution of the bat file containing the command to run
	- The deletion of the bat file
Once the above service command is run, the Python script pulls the output file via SMB and displays the results in the SMBExec shell. The service is then deleted, and the entire process is re-run whenever another command is executed via SMBExec.

Below is an example of the SMBExec shell executing a `whoami` command on a remote system:

![](/images/277a68ce12fb4ec727ec2ff7e8aa085ba704357b.png)

Below is a Sysmon `Process Create` event for the execution of the commandline specified within the service created:

![](/images/a34c492ca3e9cf57410dfef52600b5dc3d774481.png)

### SMBExec Detection

Let's take a look at the SMBExec source code from the GitHub repository. Near the beginning, we can see the following hardcoded variables:

```Python
OUTPUT_FILENAME = '__output'
SMBSERVER_DIR   = '__tmp'
DUMMY_SHARE     = 'TMP'
SERVICE_NAME    = 'BTOBTO'
CODEC = sys.stdout.encoding
```

In the Sysmon log, we can see the `OUTPUT_FILENAME` value in the commandline shortly after the `whoami` command specified, following the format: `\\127.0.0.1\C$\__output`. We also can see that the service name being created is set to `BTOBTO`, based on the variable name.

Back in the source code, we can see where this OUTPUT_FILENAME is being crafted in the `RemoteShell` class:

```Python
    def __init__(self, share, rpc, mode, serviceName, shell_type):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__output = '\\\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__shell_type = shell_type
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute'
```

We can also see from this that SMBExec supports executing commands via either `cmd.exe` (which is the value of the `%COMSPEC%` environment variable on Windows systems) or `powershell.exe`. 

Looking further into the code, we can see where all the different variables (output filename, command to execute, etc) are combined to make the full commandline value we saw in the Sysmon log:

```Python
command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + batchFile + ' & ' + \
        self.__shell + batchFile

if self.__mode == 'SERVER':
    command += ' & ' + self.__copyBack
command += ' & ' + 'del ' + batchFile
```

We can use all of the above information to craft detections for potential SMBExec execution within an environment. The best way to do this would be to use specially crafted RegEx strings against the `CommandLine` value found in the log.

Since we know the `OUTPUT_FILENAME` portion will always be `__output`, based on the hardcoded variable, we can use that to key off of. Likewise, we can see that the redirect string `2^>^&1 >` is hardcoded when creating the command, which can also be used in the detection. With this in mind, we can create the following RegEx to match on an SMBExec-formatted string in a `CommandLine`, regardless of what command was executed:

```RegEx
\\__output\s2\^>\^&1
```

## WMIExec

wmiexec.py is another Impacket script used to execute commands on a remote system using WMI. Unlike SMBExec, WMIExec does not require the creation of a service to execute commands, instead relying on DCOM and WMI providers to do so.

Below is an example of a WMIExec shell executing a `whoami` command on a remote system:

![](/images/4726dbed86c4f5c34850c557f2985195959c5d44.png)

Below is a Sysmon `Process Create` event for the above execution, outlining the commandline and parent process used:

![](/images/d5ad599c996e568d86473fda1c62c2037c8b1f43.png)

### WMIExec Detection

Let's take a look at the WMIExec source code. Like SMBExec, there is a hardcoded `OUTPUT_FILENAME` variable as follows:

```Python
OUTPUT_FILENAME = '__' + str(time.time())
```

Unlike SMBExec, this variable is not a hardcoded string, but instead created using Python's `time` module. According to [Python's documentation](https://docs.python.org/3/library/time.html#time.time), `time.time()` returns the current "time in seconds since the epoch as a floating point number." Basically, it returns what is commonly known as Unix time. This Unix time value is then appended to a `__` string and used as the `OUTPUT_FILENAME` variable in the script. In our test execution, this translated to `1677980195.873835`.

WMIExec includes a `RemoteShell` class very similar to SMBExec, as seen in the following:

```Python
    def __init__(self, share, win32Process, smbConnection, shell_type, silentCommand=False):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        self.__shell = 'cmd.exe /Q /c '
        self.__shell_type = shell_type
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__silentCommand = silentCommand
        self.__pwd = str('C:\\')
        self.__noOutput = False
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute\n[!] Press help for extra shell commands'
```

Just like SMBExec, we can see that these commands can be executed via either `cmd.exe` or `powershell.exe`. 

We can also see in the source code where all of these factors are combined into the full commandline, giving us the structure the code uses for each command passed:

```Python
command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output + ' 2>&1'
```

Since the `time.time()` module follows a specific structure, we can use RegEx formatting to account for the variability in the `OUTPUT_FILENAME` variable for this script. This, combined with the hardcoded redirect `2>&1` allows us to craft a RegEx to find a potential WMIExec execution via a `CommandLine` query:

```RegEx
\\__[0-9]{10}\.[0-9]{6,7}\s2>&1
```

## DCOMExec

dcomexec.py is yet another Impacket script that can be used to execute remote commands against a system, using DCOM endpoints. However, unlike WMIExec which uses a specific DCOM endpoint, DCOMExec allows for using a number of different DCOM endpoints. At the time of this writing, DCOMExec supports the following DCOM endpoints:
- MMC20.Application (49B2791A-B1AE-4C90-9B8E-E860BA07F889)
- ShellWindows (9BA05972-F6A8-11CF-A442-00A0C90A8F39)
- ShellBrowserWindow (C08AFD90-F2A1-11D1-8455-00A0C91F3880)

Below is an example of the DCOMExec shell executing a `whoami` command on a remote system, using the MMC20 DCOM endpoint:

![](/images/69dc2a256c15e80a84693f26197ce989dd58045c.png)

Below is the associated Sysmon `Process Create` event for the above behavior; note that the parent process is `mmc.exe` due to the fact the `MMC20` DCOM endpoint was used:

![](/images/6b7d82652d06b096baf3d5831322c923746caa32.png)

### DCOMExec Detection

Looking at the source code for DCOMExec, we can see that the `OUTPUT_FILENAME` variable is very similar to WMIExec, with one important distinction; rather than using the entire results of `time.time()`, only the first five numbers are returned. The code can be seen here:

```Python
OUTPUT_FILENAME = '__' + str(time.time())[:5]
```

These five digits are then appended to the `__` string, similarly to WMIExec. In our test execution, this translated to `__16779`.

Below is DCOMExec's `RemoteShell` class, again very similar to WMIExec's class, and shows that this script can also execute commands via `cmd.exe` or `powershell.exe`:

```Python
    def __init__(self, share, quit, executeShellCommand, smbConnection, shell_type, silentCommand=False):
        cmd.Cmd.__init__(self)
        self._share = share
        self._output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = ''
        self._shell = 'cmd.exe'
        self.__shell_type = shell_type
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__quit = quit
        self._executeShellCommand = executeShellCommand
        self.__transferClient = smbConnection
        self._silentCommand = silentCommand
        self._pwd = 'C:\\windows\\system32'
        self._noOutput = False
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute\n[!] Press help for extra shell commands'
```

Finally, we can also see a similar looking `command` variable that concatenates all of the specified options into the full commandline string to be used:

```Python
command += ' 1> ' + '\\\\127.0.0.1\\%s' % self._share + self._output + ' 2>&1'
```

Since the commandlines between DCOMExec and WMIExec are the same with the exception of the length of the `time.time()` string, we can use a RegEx similar to the one for WMIExec, just with a slightly different matching format for the digit string:

```RegEx
\\__[0-9]{5}\s2>&1
```

## Final Thoughts

It is important to remember that these RegEx strings provided will match on these Impacket scripts *in their default state.* Since these are simply variables in a script, they can be easily modified by a threat actor to be something completely different. That being said, a lot of the time threat actors, with the exception of the most sophisticated ones, tend to run these types of open source tools as is, making the detections still viable in most situations. Beyond the RegEx strings, the parent to child process chains can be a great way to detect the behavior of these scripts, as those will be much more difficult to modify. For instance, `wmiprvse.exe` (for WMIExec) or `mmc.exe` (For DCOMExec using the `MMC20.Application` endpoint) spawning a `cmd.exe` or `powershell.exe` process could be considered suspicious and can make for great detections. Parent processes for the DCOMExec script, however, will be variable depending on which DCOM endpoint is chosen, so that needs to be taken into consideration as well.

## Detections Summary
The following are potential detection capabilities for these Impacket scripts:
- `cmd.exe` or `powershell.exe` commandline strings matching the following RegEx patterns:
	- SMBExec: `\\__output\s2\^>\^&1`
	- WMIExec: `\\__[0-9]{10}\.[0-9]{6,7}\s2>&1`
	- DCOMExec: `\\__[0-9]{5}\s2>&1`
- Abnormal parent to child process chains, such as `mmc.exe` or `wmiprvse.exe` spawning `cmd.exe` or `powershell.exe`.

