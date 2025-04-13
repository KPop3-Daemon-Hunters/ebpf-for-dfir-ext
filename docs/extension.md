# eBPF for DFIR Extension Guide

This document serves as a guide for extending the functionality of `eBPF-for-DFIR`. Follow these instructions to add new features or modify existing ones.

## 1. How to Extend Functionality

### 1.1 Adding a New eBPF Event
1. Check the available eBPF hooks provided by `eBPF-for-DFIR`.
2. Develop an appropriate eBPF program to capture the desired event.
3. Integrate the eBPF program with the data collection engine of `eBPF-for-DFIR`.
4. Structure and transform the captured data to make it suitable for analysis.

### 1.2 Using eBPF Extension Templates
Some files serve as templates and should be configured to operate based on specific event names.

- `ebpf_extension_<provider_name>_on_client_attach`:
  - Executes when an eBPF client attaches.
  - Implement callback registration and initialization logic.

- `ebpf_extension_<provider_name>_on_client_detach`:
  - Executes when an eBPF client detaches or terminates.
  - Implement callback cleanup and resource release logic.

- `<provider_name>_bpf_attach_type`
  - This field specifies the eBPF attach type that determines how and where the BPF program will be attached in the kernel.
  - It acts as a routing key that allows the collector to understand which kind of kernel hook (e.g., tracepoint, kprobe, XDP) is being used for this provider.

- `<provider_name>_bpf_program_type`
  - This defines the type of BPF program that will be loaded and verified by the kernel for a specific use case.
  - It ensures the eBPF context interprets the program logic correctly and links it to the appropriate attach type for execution.

### 1.3 Extending Data Output Functionality
1. Analyze the existing output mechanisms (e.g., JSON file storage).
2. Add new output methods, such as remote server transmission or database storage.
3. Modify configuration files to allow user-defined settings if needed.

### 1.4 Enhancing Configuration and Management Features
1. Ensure new features can be controlled through configuration files.
2. Improve the logging system for better debugging and usability.
3. Add a CLI (Command Line Interface) if necessary to enhance management capabilities.

## 2. Development and Testing

### 2.1 Setting Up the Development Environment
- Ensure the Windows environment is configured to build and run `eBPF-for-Windows`.
- Install necessary libraries and tools.
- If you are running on a Virtual Machine (Hyper-V), please refer to the [vm-setup](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/vm-setup.md) document for guidance.

### 2.2 Testing Procedures
1. Develop unit tests for newly added features.
2. Run the application in a Windows environment to verify functionality.
3. Validate that the eBPF program correctly captures events.
4. Ensure data storage and output mechanisms function as expected.

## 3. Deployment and Maintenance
1. Update documentation whenever a new feature is released.
2. Regularly perform bug fixes and performance optimizations.
3. Continuously improve based on user feedback.

---
Follow this document to extend the functionality of `eBPF-for-DFIR`. If you have any questions or need further improvements, feel free to open an issue.

