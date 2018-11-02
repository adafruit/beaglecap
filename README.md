This is a very rough Wireshark extcap plugin to control a Beagle 12 USB sniffer. Its based on this
code: https://github.com/wireshark/wireshark/blob/master/doc/extcap_example.py

It also uses the Beagle Python API available here: https://www.totalphase.com/products/beagle-software-api/

To use:

1. Find your Wireshark extcap directory by looking at "About Wireshark" and the "Folders" tab.
2. Copy beaglecap.py and usbmon.py from this repo there.
3. Make sure beaglecap.py is executable and that you have python2 installed.
4. Copy the compiled beagle library and beagle_py.py from the Beagle SDK to the same folder.
5. Startup Wireshark and you should see an interface for each Beagle present. Double and it should
   start displaying packets.

A couple caveats though. First, the controls seem to freeze Wireshark. Second, USB info is
aggregated into Linux like URBs so lower level details are lost. However, Wireshark does class-level
parsing which is very helpful.
