# Zodiac FX Firmware

This is the firmware for the [Northbound Networks](https://northboundnetworks.com/) Zodiac FX OpenFlow Switch.

## Background

The Zodiac FX began as a [Kickstarter campaign](https://www.kickstarter.com/projects/northboundnetworks/zodiac-fx-the-worlds-smallest-openflow-sdn-switch) in 2015, with the goal of providing an affordable Software Defined Networking (SDN) platform for developers, researchers, and networking hobbyists. To learn more about SDN, visit the [Northbound Networks Blog](https://northboundnetworks.com/blogs/sdn).

The Zodiac FX SDN switch uses the [OpenFlow protocol](https://www.opennetworking.org/sdn-resources/openflow), an open standard for communication in an SDN architecture. OpenFlow allows communication between the SDN controller (where applications can be run) and OpenFlow switches in the network. These switches use application-generated "Flows" to determine how network data is processed.

This repository contains the entire open-source firmware for the Zodiac FX including OpenFlow libraries. The firmware is constantly being updated with support for features of the OpenFlow specification, and to improve compatability with the various SDN controllers. OpenFlow version 1.0 and version 1.3 are currently supported.

## Flashing/Updating the Firmware

The latest firmware is available in the [Northbound Networks Forums](http://forums.northboundnetworks.com/index.php?topic=52.0).

Starting from version 0.81, Zodiac FX supports firmware updates via the CLI and web interface. In order to make this possible, major changes were made to the firmware flashing process. Follow the update process below, based on your current firmware version.

#### For firmware versions BEFORE version 0.81

To update to version 0.81 or later, a **full upgrade firmware** needs to be flashed.

Download the latest **full upgrade firmware** from the [Northbound Networks Forums](http://forums.northboundnetworks.com/index.php?topic=52.0) - 'Full Upgrade Firmware (v0.XX) - ZodiacFX_vXX_full_install.bin'

Follow the firmware update process detailed in **Section 2. Updating Firmware** in the [Zodiac FX User Guide](http://forums.northboundnetworks.com/downloads/zodiac_fx/guides/ZodiacFX_UserGuide_0317.pdf).

#### For firmware versions AFTER version 0.81

The update process has been simplified for the newer releases.

Download the latest **update firmware** from the [Northbound Networks Forums](http://forums.northboundnetworks.com/index.php?topic=52.0) - 'Update Firmware (v0.XX) - ZodiacFX_vXX_update.bin'

* **To update via the CLI**:
	* In the root context, type the 'update' command
	* When prompted, begin the firmware update via the XMODEM protocol
		* Note: not all serial terminal applications support XMODEM
	* If the firmware update is successful, Zodiac FX will automatically restart to complete the update

* **To update via the web interface**:
	* Go to the 'Update f/w' page in the Zodiac FX web interface
		* Note: the web interface is available by going to the Zodiac FX IP address in a web browser on the controller
		* This feature is currently fully supported in Google Chrome
	* Browse and select the downloaded firmware
	* Click 'Upload File' and wait for a confirmation page to appear
	* Click 'Restart' in the web interface header to complete the update

* **[Advanced] To update via cURL**:
	* Run the following command: **curl --verbose -0 --form "file=@ZodiacFX_vXX_update.bin" *ip_address***
	* If the firmware upload fails, you may need to use the multipart/related content type like so: **curl -H "Content-Type: multipart/related" --verbose -0 --form "file=@ZodiacFX_vXX_update.bin" *ip_address***
		* Note: a restart is required after the update to load the new firmware.

## Building the Project

If you want to modify the firmware for your own project, either download this project or fork this repository.

[Atmel Studio 7](https://www.atmel.com/Microsite/atmel-studio/) is required to build the project.

#### Debugging the project

For full source-level debugging, a [Zodiac FX Hardware Debugger](https://northboundnetworks.com/products/zodiac-fx-hardware-debugger) is required.

* Ensure that the hardware debugger appears in Project -> ZodiacFX Properties -> Tool -> Selected debugger/programmer
	* Zodiac FX uses the JTAG interface
* Select the 'Debug' Solution Configuration in the Atmel Studio Standard toolbar
	* The 'Release' configuration has been modified to build firmware updates, and will not run directly in Atmel Studio
* Select the 'Start Debugging and Break' option in the Debug menu to begin stepping through the source

The firmware will continue to run by cycling power to the Zodiac FX (after removing the hardware debugger). However, firmware updating will not function until a **full upgrade firmware** is flashed. The modified firmware can be written to the Zodiac FX by following the steps outlined below: **running the code without a hardware debugger**.

#### Running the code without a hardware debugger

Modified firmware can be tested without the Zodiac FX Hardware Debugger, however source-level debugging is not possible.

* Build the 'Release' configuration of the ZodiacFX solution
* Navigate to the compiled binary
	* \ZodiacFX\Release\ZodiacFX.bin
* Follow the steps in Signing Binaries to allow the Zodiac FX to update to the modified firmware

## Signing Binaries

The Zodiac FX uses a simple additive checksum to verify the integrity of the uploaded firmware.

To sign your own modified firmware, follow the steps below:
* Build a 'Release' binary of the modified firmware
* Update the Zodiac FX with the modified firmware
	* Follow the instructions outlined in Flashing/Updating the Firmware - For firmware versions AFTER version 0.81
* The firmware will fail the verification check, but will still be stored inside the Zodiac FX flash memory
* In the root context of the CLI, type in the hidden command 'get crc'
* Open the ZodiacFX.bin file in a hex editor, and append the 8 bytes to the end of the firmware file
	* For example, if 'get crc' provides [A05A1201 00000000], append 'A0 5A 12 01 00 00 00 00' to the end of the firmware file
* Update the Zodiac FX again with the (now signed) modified firmware
* The firmware update should be successful, and the Zodiac FX will run the new firmware after restarting

## Reporting Bugs and Issues

Any bugs and issues can be brought up in the [Northbound Networks Forums](http://forums.northboundnetworks.com/index.php?board=3.0).

Issues can also be [raised](https://github.com/NorthboundNetworks/ZodiacFX/issues) in this repository.

## Release Notes

**Version 0.81**
* Firmware upload fixes (full upgrade required)
* Metering bug-fixes & updates (initial DSCP remark support)
* Port stat output bug-fixes
* Web interface improvements

**Version 0.80**
* Firmware upload via CLI and web interface added
* Metering added to OpenFlow 1.3

## Authors

* **Paul Zanna** - Creator
* **Kristopher Chen** - Firmware Developer

## License

[GPL 3.0](LICENSE)
