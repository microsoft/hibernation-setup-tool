---
title: hibernation-setup-tool
section: 1
header: System Utilities
footer: hibernation-setup-tool 1.0
date: June 29, 2021
---


# NAME
hibernation-setup-tool - sets up a VM for hibernation

# SYNOPSIS
**hibernation-setup-tool**

# DESCRIPTION
**hibernation-setup-tool** is a tool that sets up a swap file suitable for
hibernation, and sets up the system to enable proper resuming.

It accomplishes that by creating a swap file in the root directory that's slightly
larger than the total amount of RAM available for the VM, ensuring it has no holes
and isn't fragmented, and setting up parameters for the currently-running kernel
(so the VM can be hibernated as soon as the set up is complete), and for next boots
(so that the VM can be resumed).

On Hyper-V virtual machines, it'll also ensure that proper udev rules
are set in place so that the machine can hibernate when receiving a
command from the host.  In addition, it'll install systemd hooks to
track hibernation success, failures, and cold-boot scenarios, and store
them in the system log.

It currently only fully supports distributions with GRUB2 as the bootloader (e.g.
those with `/etc/default/grub` as part of its configuration file), and those using
initramfs-tools (e.g. Debian and Ubuntu).  Use in systems where either of these
aren't used is possible, however the tool won't be able to adjust the system in
such a way that it'll resume from hibernation.

Installation can be performed either manually, by using the provided Makefile
(e.g. by issuing `make` to build and `make install` with superuser privileges
to install files in the correct locations), or by installing a .deb package.  To
build the .deb package, one can use the provided `build.sh` script in the
`debian-packaging` branch of this repository, which, in a system where tools to
build Debian packages have been installed, will perform all necessary steps
to output a file that can be installed via `dpkg`.

# OPTIONS
No command-line parameters exist.  The tool is fully automatic, and
will exit when set up has been completed.
It can be safely executed on every boot, without impacting boot time.

# RETURN VALUE
The tool will return 0 on success, and 1 on failure.

# AUTHORS
Written by [Leandro Pereira](mailto:leandro.pereira@microsoft.com).

# BUGS
[Submit bug reports online](https://github.com/microsoft/hibernation-setup-tool/issues).

# SEE ALSO
[Full source code is available](https://github.com/microsoft/hibernation-setup-tool/).

# NOTES
This program requires superuser privileges to execute.

Pull requests improving the tool are greatly appreciated.  Please refer
to the `CONTRIBUTING.md` file located in the source repository for more
information, including a link to the Microsoft Open Source Code of
Conduct document.

Trademarks This project may contain trademarks or logos for projects,
products, or services.  Authorized use of Microsoft trademarks or logos is
subject to and must follow [Microsoft’s Trademark & Brand
Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). 
Use of Microsoft trademarks or logos in modified versions of this project
must not cause confusion or imply Microsoft sponsorship.  Any use of
third-party trademarks or logos are subject to those third-party’s policies.
