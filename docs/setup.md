# eBPF-for-DFIR Setup Guide
This document provides instructions on how to set up the eBPF-for-DFIR project.

## 1. Common Installation Requirements
The following requirements must be met for all environments.

### Required Installations
* eBPF for Windows
* Windows 10 or later, Windows Server 2019 or later
* Administrator privileges

### Installation Steps
Refer to the official eBPF for Windows documentation for installation instructions.

## 2. Development Environment Setup
The development environment should be configured to allow code modifications and debugging.

### Additional Requirements
* Visual Studio 2022 (with C++ support)
* Windows SDK

### Setup Steps
Install Visual Studio 2022 and required components.
Clone the project and build it:

```
# Clone the repository
git clone https://github.com/capelabs/ebpf-for-dfir.git
cd ebpf-for-dfir
```

## 3. Production Environment Setup
In a production environment, eBPF programs must run reliably with the appropriate security settings.

### Additional Requirements
* Configuration to load test drivers
* Code signing certificate is required for production use
* The driver must be signed with a Microsoft-trusted code signing certificate
* Unsigned drivers will not load in a production environment

### Setup Steps
Enable Test Signing Mode (for testing only)

```
bcdedit /set TESTSIGNING ON
shutdown /r /t 0
```

#### Additional Steps for Hyper-V Environments
Simply enabling TESTSIGNING ON may not be sufficient in a Hyper-V environment. If Secure Boot is enabled, test-signed drivers may not load.

### 1. Disable Secure Boot
If Secure Boot is enabled in the Hyper-V VM, test-signed drivers will be blocked.

To disable Secure Boot, open PowerShell as Administrator and run:

```
Set-VMFirmware -VMName "YourVMName" -EnableSecureBoot Off
```

Alternatively, go to Hyper-V Manager → Select your VM → Firmware settings → Uncheck Secure Boot.


#### Use a Signed Driver in Production

* Only signed drivers can be loaded in a production environment
* Submit the driver to Microsoft for signing or use an internal corporate Certificate Authority (CA)
* Example of signing a driver with an EV code signing certificate:

```
signtool sign /fd SHA256 /a /n "Your Company EV Code Signing Certificate" driver.sys
```

## 4. Additional Notes
* Running eBPF programs requires administrator privileges.
* Additional security settings may be required depending on Windows security policies.
