import struct

class SetupData:
    def __init__(self):
        # From http://www.beyondlogic.org/usbnutshell/usb6.shtml
        # D7 Data Phase Transfer Direction
        #   0 = Host to Device
        #   1 = Device to Host
        # D6..5 Type
        #   0 = Standard
        #   1 = Class
        #   2 = Vendor
        #   3 = Reserved
        # D4..0 Receipient
        #   0 = Device
        #   1 = Interface
        #   2 = Endpoint
        #   3 = Other
        #   4..31 = Reserved
        self.bmRequestType = 0
        self.bRequest = 0
        self.wValue = 0
        self.wIndex = 0
        self.wLength = 0 # Number of bytes in the data phase.

    def decode(self, packed):
        unpacked = struct.unpack_from(">BBHHH", packed)
        self.bmRequestType, self.bRequest, self.wValue, self.wIndex, self.wLength = unpacked

    def encode(self):
        return struct.pack(">BBHHH", self.bmRequestType, self.bRequest, self.wValue, self.wIndex, self.wLength)

# These get packed into pcap packets.
# https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/usb.h#L104
# https://github.com/wireshark/wireshark/blob/9cd114fbe5d622ef7345259d143b4e09f5c0e6eb/wiretap/pcap-common.c#L1075
class Packet:
    urb_types = {ord('S'): "Submit",
                 ord('C'): "Complete",
                 ord('E'): "Error"}
    transfer_types = ["URB_ISOCHRONOUS", "URB_INTERRUPT", "URB_CONTROL", "URB_BULK"]
    def __init__(self):
        self.id = 0
        self.event_type = 0
        self.transfer_type = 0
        self.endpoint_number = 0
        self.device_address = 0
        self.bus_id = 0
        self.setup_flag = 1
        self.data_flag = 0
        self.ts_sec = 0
        self.ts_usec = 0
        self.status = 0
        self.urb_len = 64
        self.union = None
        self.interval = 0
        self.start_frame = 0
        self.xfer_flags = 0
        self.ndesc = 0

        self.data = b''

    def decode(self, data):
        unpacked = struct.unpack_from("<QBBBBHccqiiIIxxxxxxxxiiII", data)
        self.id = unpacked[0]
        self.event_type = unpacked[1]
        self.transfer_type = unpacked[2]
        self.endpoint_number = unpacked[3]
        self.device_address = unpacked[4]
        self.bus_id = unpacked[5]
        self.setup_flag = unpacked[6]
        self.data_flag = unpacked[7]
        self.ts_sec = unpacked[8]
        self.ts_usec = unpacked[9]
        self.status = unpacked[10]
        self.urb_len = unpacked[11]
        data_len = unpacked[12]
        self.union = data[40:48]
        self.interval = unpacked[13]
        self.start_frame = unpacked[14]
        self.xfer_flags = unpacked[15]
        self.ndesc = unpacked[16]
        if data_len > 0:
            self.data = data[-1 * data_len:]
        else:
            self.data = b''

    def encode(self):
        raw = struct.pack("<QBBBBHccqiiIIxxxxxxxxiiII", self.id, self.event_type, self.transfer_type, self.endpoint_number, self.device_address, self.bus_id, chr(self.setup_flag), chr(self.data_flag), self.ts_sec, self.ts_usec, self.status, len(self.data), len(self.data), self.interval, self.start_frame, self.xfer_flags, self.ndesc)
        raw = bytearray(raw)
        if type(self.union) == SetupData:
            raw[40:48] = self.union.encode()
        raw.extend(self.data)
        return raw

    def __str__(self):
        return ("URB id: {:x}\n" +
                "URB type: {}\n" +
                "URB transfer type: {}\n" +
                "Endpoint: {:x}, Direction: {}\n" +
                "Device: {}\n" +
                "URB bus id: {}\n" +
                "Device setup request: {}relevant ({})\n" +
                "Data: {}present ({})\n" +
                "URB sec: {}\n" +
                "URB usec: {}\n" +
                "URB status: {}\n" +
                "URB len: {}\n" +
                "Data len: {}\n" +
                "Interval: {}\n" +
                "Start frame: {}\n" +
                "Copy of Transfer Flags: {}\n" +
                "Number of ISO descriptors: {}\n" +
                "Data: {}\n").format(
                    self.id,
                    self.urb_types[self.event_type], self.transfer_types[self.transfer_type],
                    self.endpoint_number & 0xf, "IN" if (self.endpoint_number & 0xf0) else "OUT",
                    self.device_address,
                    self.bus_id,
                    "not " if self.setup_flag != b'\x00' else "", self.setup_flag,
                    "not " if self.data_flag != b'\x00' else "", self.data_flag,
                    self.ts_sec,
                    self.ts_usec,
                    self.status,
                    self.urb_len,
                    len(self.data),
                    self.interval,
                    self.start_frame,
                    self.xfer_flags,
                    self.ndesc,
                    self.data)
