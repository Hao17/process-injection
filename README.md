Simple demo for process hollowing & tls callback

Hider.dll hook NtQuerySystemInformation function of ntdll.dll to anti-detect process.



**install**

```console
$ git clone --recurse-submodules https://github.com/hao17/process-injection
```



**vcpkg**

```
$ git clone https://github.com/microsoft/vcpkg
$ .\vcpkg\bootstrap-vcpkg.bat
$ vcpkg integrate install
$ vcpkg install minhook:x64-windows-static
$ vcpkg install minhook:x86-windows-static
```