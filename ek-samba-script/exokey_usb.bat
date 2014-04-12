rem sam-ba.exe \jlink\ARM0 at91sama5d3x-ek exokey_main.tcl > logfile.log 2>&1
sam-ba.exe \usb\ARM0 at91sama5d3x-ek exokey_main.tcl | tee.bat logfile_usb.log
rem > logfile_usb.log 2>&1
notepad logfile_usb.log
