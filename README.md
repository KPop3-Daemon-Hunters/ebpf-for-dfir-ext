# eBPF-for-DFIR

eBPF-for-DFIR is an open-source tool that uses eBPF (Extended Berkeley Packet Filter) technology to collect real-time system data for Digital Forensics and Incident Response (DFIR) on Windows systems. By leveraging the eBPF-for-Windows framework, it provides deep visibility into system activity and helps incident responders gather crucial information during investigations.

## Features
* Real-Time Data Collection: Captures system data in real time from Windows machines.

* Windows Integration: Built on top of eBPF-for-Windows, enabling detailed data collection on Windows.

* DFIR-Focused: Designed for Digital Forensics and Incident Response to provide key insights during security investigations.

## Requirements
* Windows Operating System: The tool is designed for use on Windows environments. (Windows 10 or later, Windows Server 2019 or later)

* [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows): The tool relies on the eBPF framework for Windows to capture system events.

Please refer to this [setup document](docs/setup.md) for detailed configuration.


## Deep-dive
This tool extends eBPF-for-Windows by monitoring key system activities for DFIR:

* FileEventEbpfExt: Monitors file system events, detecting file creation, modification, and deletion.

* RegEventEbpfExt: Tracks registry modifications, providing insight into registry key changes.

* ProcEventEbpfExt: Monitors process execution, including process creation and termination.

* NetEventEbpfExt: Captures network-related events such as connections and data transmissions.

## Future works
* MutexEventEbpfExt: Monitors the creation of mutex objects to track synchronization events in the system.

* ProcEventEbpfExt: Extended to monitor DLL loading, image loading, and memory mapping in the system.

## Extending features
If ebpf-for-dfir does not support the features you need, you can extend the tool by following the [guide](docs/extension.md). We also welcome and appreciate your contributions!

## Contribution
We welcome contributions! Feel free to submit issues, feature requests, or pull requests.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
