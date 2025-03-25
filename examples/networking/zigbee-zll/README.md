# ZBOSS Zigbee ZLL example

After flashing the device, wait about 5-10 seconds for the device to fully initialise.
Use the set_ch command to set it to one of the primary Touchlink channels
(11,15,20,25). 
Take a ZigBee enabled light bulb and place it close to the microcontroller.
The run the tl_scan command. This will initiate a Touchlink c
omissioning procedure. Wait few seconds for the joining to finish.
Finally, zcl_toggle should toggle the light.

Note: If no encryped key is shown on the command line, the device is likely on the 
wrong channel or not close enough to the bulb.
Also, ZBOSS is currently unable to clear some outgoing command buffers.
It is best practice to reboot the microcontroller after each tl_scan.
Use the zconfig command to view ZigBee information including the current channel.
ZBOSS is also very unstable, expect HARD-FAULTS and assertion failurs!


