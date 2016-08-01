=================================
Exporting Non-Exportable RSA Keys
=================================

This project has been directly inspired by the follwing paper:

https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf

by Jason Geffner <jason.geffner@ngssecure.com> that can be found in the doc folder

The repo contain a Visual Studio 2010 buildable project. The repo contains a Debug and Release build versions. Executable are in:

DEBUG:   https://github.com/luipir/ExportNotExportablePrivateKey/blob/master/exportrsa/Debug/exportrsa.exe
RELEASE: https://github.com/luipir/ExportNotExportablePrivateKey/blob/master/exportrsa/Release/exportrsa.exe

How to use
~~~~~~~~~~

The code parse all system key stores and export in .pxf files all that have a RSA private key available.

Just run exportrsa.exe in a command shell

probably you can have error due to missing of: msvcr100d.dll (debug) or msvcr100.dll (release version). You need to install: vcredist_x86_2010.exe (https://www.microsoft.com/en-us/download/details.aspx?id=5555)
