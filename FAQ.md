# FAQ


# About the environment

## Can I use GEF on an OS other than Ubuntu?
It's probably fine for regular Linux. I've used it on debian and WSL2.
Some users are running it on Arch Linux.
However, I have not confirmed that all commands work correctly.

## What kernel versions does it support?
3.x ~ 6.5.x are supported.
However, I have not verified every kernel version, so there may be environments where GEF does not work.
If you have any trouble, please report it on the issue page.

## GDB will not load GEF.
Are you using an environment other than Ubuntu 22.04?
This is probably because gdb does not support cooperation with python3.
Consider building gdb from source with `./configure --enable-targets=all --with-python=/usr/bin/python3 && make && make install`.

## Will each GEF command be more accurate if I have vmlinux with debug symbols?
No. Whether vmlinux includes debug information has no effect on GEF behavior.
GEF always uses its own resolved address with `kallsyms-remote`.
It also performs its own heuristic structure member detection in each command.

## Does it support i386 16-bit mode (real mode)?
No. GEF does not support real mode.
Please consider using other scripts, such as [here](https://astralvx.com/debugging-16-bit-in-qemu-with-gdb-on-windows/).


# About commands

## What command should I start with when debugging the kernel?
Try `vmlinux-to-elf-apply` or `ks-apply`, then `pagewalk` and `kchecksec`.
After that, try `slub-dump` and `buddy-dump` as well.
Other commands are less important, so check them with `gef help` if necessary.

## I prefer the AT&T style.
Please specify each time using the `set disassembly-flavor att` command.
Or, since the `set disassembly-flavor intel` command is executed in the GEF's main function, it may be a good idea to comment it out.
However, since GEF does not take AT&T notation parsing into consideration, so the information such as branch destination will not be displayed.

## I don't like the color scheme.
Customize it using the `theme` command, then `gef save`. The config is saved to `~/.gef.rc` by default.
There is another option is disable colors. Try `gef config gef.disable_color True`.

## I don't want to add `-n` to every command to disable pager.
Try `gef config gef.always_no_pager True` then `gef save`.

## `ktask` (or other kernel related commands) does not work.
The kernel you are debugging may have been built with `CONFIG_RANDSTRUCT=y`.
In this case, except for a few commands, they will not work correctly.

## `vmmap` command does not recognize option.
When connected to qemu-system or vmware's gdb stub, the `vmmap` command is just redirected to the `pagewalk` command.
All options are ignored at this time. If you want to use some options, please use the `pagewalk` command instead of `vmmap` command.


# About development schedule

## Are there any plans to support kernels for other architectures?
There are no plans.
If implemented in the future, the architecture must at least disclose the `pagewalk` process in detail.
This is because a memory map is required to obtain the symbols, and a `pagewalk` implementation is required to obtain the memory map.

## Are there any plans to support more architectures with Qemu-user?
Yes. However, it is becoming difficult to find new support targets.
This is because three things are required:

1. toolchain
    * linux-headers, binutils, gcc, glibc (or uclibc) are needed.
    * Prebuilt tarball is prefer.
2. qemu-user
3. gdb
    * It needs python3-support.

## Are future development plans listed somewhere?
No. I develop this forked GEF freely.


# About reporting

## I found a bug.
Please feel free to report it on the issue page. I will respond as soon as possible.

## Can you please add this feature? / I don't like the XXX, so please fix it.
I will consider it, so please report it on the issue page.
But this is a personal development, so I have the final say. I appreciate your understanding.

## Is it okay to fork and modify?
Yes. However, please follow the license.


# About me

## What kind of environment are you developing in?
I don't use anything special.
I am using a test environment built with buildroot while viewing the Linux kernel source with Bootlin.
I also use images of kernel exploit task from variuos CTFs.

## Why is there no master branch?
I'm a git beginner, so one dev branch is the best I can do.

## Are you bad at English?
Yes. I mostly use Google Translate. This is the reason for the inconsistent writing style.
If the expression in English is strange, please feel free to correct it on the issue page.

## I would like to contact you about a GEF?
Find `bata___` on Discord of official GEF's server or Pwndbg's server.


# Other memo (Japanese)
* Why I decided to make this
    * [gefを改造した話](https://hackmd.io/@bata24/rJVtBJsrP)
* The story behind each command, etc.
    * [bata24/gefの機能紹介とか](https://hackmd.io/@bata24/SycIO4qPi)