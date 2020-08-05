![Spectre Rootkit Logo](https://i.imgur.com/P529RIt.png)

Welcome to the *Spectre Rootkit*, a proof-of-concept Windows kernel-mode rootkit I wrote with the hopes of demystifying the Windows kernel for red team usage. The Spectre Rootkit abuses legitimate communication channels in order to receive commands from a C2. You can read more about how it works [here](https://github.com/D4stiny/spectre/wiki/Hooking-IOCTL-Communication-via-Hooking-File-Objects). This project was the focus of my talk, "Demystifying Modern Windows Rootkits", presented at both [Black Hat USA 2020](https://www.blackhat.com/us-20/briefings/schedule/index.html#demystifying-modern-windows-rootkits-20918) and [DEF CON 28](https://defcon.org/html/defcon-safemode/dc-safemode-speakers.html#Demirkapi).

## Getting Started
Please see the [Getting Started](https://github.com/D4stiny/spectre/wiki/Getting-Started) section of the wiki.

## Components
Here are the projects inside the Spectre Rootkit solution.

- [spectre-kernel](https://github.com/D4stiny/spectre/tree/master/spectre/spectre-kernel) - The core driver project for the rootkit.
- [spectre-cli](https://github.com/D4stiny/spectre/tree/master/spectre/spectre-cli) - The CLI utility used from the C2 to control an infected machine.
- [spectre-stager](https://github.com/D4stiny/spectre/tree/master/spectre/spectre-stager) - The staging utility used to load the rootkit on a victim machine.
- [spectre-stager-util](https://github.com/D4stiny/spectre/tree/master/spectre/spectre-stager-util) - Takes the built driver file and converts it into a XOR-obfuscated header for use by the spectre-stager.

## Motivation
The primary motivation for this project was because of the lack of examples for Windows rootkits. You'll often find examples of red team tooling that lies in *user-mode*, but the amount of *kernel-mode* red team tooling is sparse. This project is meant to act as a point of reference, specifically to show *one-way* of approaching the problem of writing a rootkit. Not only did I want to write a rootkit to assist in the development of future red team tooling, but the secondary purpose of this project was to challenge myself by exploring parts of the kernel that aren't well-documented and researching novel techniques I could apply to the rootkit. You'll find that the code base follows a strict code style and is heavily documented.

## Notable Tricks and Techniques
The Spectre Rootkit is made up of several tricks and techniques, here are a few of the noteworthy ones:
- [Hooking IOCTL Communication via Hooking File Objects](https://github.com/D4stiny/spectre/wiki/Hooking-IOCTL-Communication-via-Hooking-File-Objects)
- [Spectre Rootkit Design](https://github.com/D4stiny/spectre/wiki/Spectre-Rootkit-Design)
- [Finding Unexported ZwXx Functions Reliably](https://github.com/D4stiny/spectre/wiki/Finding-unexported-ZwXx-functions-reliably)

## Thanks
Some well deserved thanks go to...
1. [Alex Ionescu](https://twitter.com/aionescu) - Long-time mentor and Windows internals expert.
2. [ReactOS Project](https://reactos.org) - An incredible reference about the internals of the Windows kernel.
3. [Nemanja Mulasmajic](https://twitter.com/0xNemi) - Gave the idea for the [NtFunctionResolver](https://github.com/D4stiny/spectre/blob/master/spectre/spectre-kernel/NtFunctionResolver.h) component of the rootkit.

## Licensing
Interested in a special license? Contact me at `billdemirkapi (AT) gmail (DOT) com`.
