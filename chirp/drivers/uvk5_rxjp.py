# Quansheng UV-K5-RX-JP driver (c) 2023 weboo
#
# based on uvk5.py Copyright 2023 Jacek Lipkowski <sq5bpf@lipkowski.org>
#
#
# This is a preliminary version of a driver for the UV-K5
# It is based on my reverse engineering effort described here:
# https://github.com/sq5bpf/uvk5-reverse-engineering
#
# Warning: this driver is experimental, it may brick your radio,
# eat your lunch and mess up your configuration.
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import logging
import struct
import time

from chirp import chirp_common, directory, bitwise, memmap, errors, util
from chirp.settings import (
    RadioSetting,
    RadioSettings,
    RadioSettingGroup,
    RadioSettingValueBoolean,
    RadioSettingValueInteger,
    RadioSettingValueList,
    RadioSettingValueString,
)

LOG = logging.getLogger(__name__)

# Show the obfuscated version of commands. Not needed normally, but
# might be useful for someone who is debugging a similar radio
DEBUG_SHOW_OBFUSCATED_COMMANDS = False

# Show the memory being written/received. Not needed normally, because
# this is the same information as in the packet hexdumps, but
# might be useful for someone debugging some obscure memory issue
DEBUG_SHOW_MEMORY_ACTIONS = False

MEM_FORMAT = """
struct {
  ul32 freq1;
  ul32 freq2;

  u8 rxcode;
  u8 txcode;
  u8 txcodeflag:4,
     rxcodeflag:4;

  u8 modulation:4,
     shift:4;

  u8 unused1:4,
     bandwidth:2,
     txpower:1,
     freq_reverse:1;

  u8 unused2;
  u8 step;
  u8 scrambler;
} channel[200];

#seekto 0xca0;
struct {
  ul32 start;
  ul32 end;
} custom_band_freq[16];

struct {
  u8 reserved1:2,
     bandwidth:2,
     modulation:4;
  u8 step;
  u8 reserved2;
  u8 reserved3;
} custom_band[16];

struct {
  u8 is_scanlist1:1,
     is_scanlist2:1,
     compander:2,
     is_free:1,
     band:3;
} channel_attributes[200];

#seekto 0xe40;
ul16 fmfreq[20];

#seekto 0xe70;
u8 call_channel;
u8 squelch;
u8 max_talk_time;
u8 noaa_autoscan;
u8 key_lock;
u8 vox_switch;
u8 vox_level;
u8 mic_gain;
struct {
  u8 backlight_min:4,
     backlight_max:4;
} backlight;
u8 channel_display_mode;
u8 crossband;
u8 battery_save;
u8 dual_watch;
u8 backlight_time;
u8 tail_note_elimination;
u8 vfo_open;

#seekto 0xe90;
u8 keyM_longpress_action:7,
   beep_control:1;
u8 key1_shortpress_action;
u8 key1_longpress_action;
u8 key2_shortpress_action;
u8 key2_longpress_action;
u8 scan_resume_mode;
u8 auto_keypad_lock;
u8 power_on_dispmode;
u8 password[4];

#seekto 0xea0;
u8 language;
u8 s0_level;
u8 s9_level;

#seekto 0xeb0;
char logo_line1[16];
char logo_line2[16];

#seekto 0xf50;
struct {
  char name1[8];
  char name2[8];
} channelname[200];

#seekto 0x1bd0;
struct {
  char name[16];
} bandname[16];
"""

# bits that we will save from the channel structure (mostly unknown)
SAVE_MASK_0A = 0b11001100
SAVE_MASK_0B = 0b11101100
SAVE_MASK_0C = 0b11100000
SAVE_MASK_0D = 0b11111000
SAVE_MASK_0E = 0b11110001
SAVE_MASK_0F = 0b11110000

# flags1
FLAGS1_OFFSET_NONE = 0b00
FLAGS1_OFFSET_MINUS = 0b10
FLAGS1_OFFSET_PLUS = 0b01

POWER_HIGH = 0b10
POWER_MEDIUM = 0b01
POWER_LOW = 0b00

# scrambler
SCRAMBLER_LIST = [
    "off",
    "2600Hz", "2700Hz", "2800Hz", "2900Hz", "3000Hz",
    "3100Hz", "3200Hz", "3300Hz", "3400Hz", "3500Hz",
]

# channel display mode
CHANNELDISP_LIST = [
    "Frequency", "Channel Number", "Name", "Name + Frequency",
]

# battery save
BATSAVE_LIST = ["OFF", "1:1", "1:2", "1:3", "1:4"]

# Backlight auto mode
BACKLIGHT_LIST = [
    "OFF", "5s", "10s", "20s", "1min", "2min", "4min", "Always On",
]

# Crossband receiving/transmitting
DUALWATCH_LIST = ["OFF", "ON"]

# steps
STEPS = [
    2.5, 5.0, 6.25, 10.0, 12.5, 25.0, 8.33,
    0.01, 0.1, 0.5, 1, 15, 20, 30, 50, 100, 125, 200,
]

# ctcss/dcs codes
TMODES = ["", "TSQL", "DTCS", "DTCS", "TSQL-R"]
TONE_NONE    = 0
TONE_CTCSS   = 1
TONE_DCS     = 2
TONE_DCS_R   = 3
TONE_CTCSS_R = 4

SCANRESUME_LIST = [
    "TIMEOUT: Resume after 5 seconds",
    "CARRIER: Resume after signal disappears",
    "STOP: Stop scanning after receiving a signal",
]

WELCOME_LIST = ["Full Screen", "Message", "Voltage", "About", "None"]

MEM_SIZE = 0x2000  # size of all memory
PROG_SIZE = 0x1d00  # size of the memory that we will write
MEM_BLOCK = 0x80  # largest block of memory that we can reliably write

# fm radio supported frequencies
FMMIN = 76.0
FMMAX = 108.0

# bands supported by the UV-K5-RX-JP
BANDS = {
    0: [15.0, 76.0],
    1: [108.0, 630.0],
    2: [840.0, 1300.0]
}

SPECIALS = {
    "BAND1": 200,
    "BAND2": 201,
    "BAND3": 202,
    "BAND4": 203,
    "BAND5": 204,
    "BAND6": 205,
    "BAND7": 206,
    "BAND8": 207,
    "BAND9": 208,
    "BAND10": 209,
    "BAND11": 210,
    "BAND12": 211,
    "BAND13": 212,
    "BAND14": 213,
    "BAND15": 214,
    "BAND16": 215,
}

BANDWIDTH_LIST = ["W", "N", "N-", "W+"]
SCANLIST_LIST = ["", "1", "2", "1+2"]

KEYACTIONS_LIST_ALL = [
    "NONE",
    "FLASHLIGHT",
    "BANDWIDTH",
    "MONITOR",
    "SCAN",
    "VOX",
    "ALARM",
    "FM RADIO",
    "1750",
    "LOCK KEYPAD",
    "SWITCH A/B",
    "SWITCH VFO/MEMORY",
    "SWITCH DEMODULATION",
    "BLMIN_TMP_OFF",
    "CHANGE STEP",
    "ABOUT",
]
KEYACTIONS_LIST = [
    "NONE", "FLASHLIGHT", "BANDWIDTH", "MONITOR", "SCAN", "FM RADIO",
    "LOCK KEYPAD", "SWITCH A/B", "SWITCH VFO/MEMORY", "SWITCH DEMODULATION",
    "CHANGE STEP", "ABOUT",
]

# the communication is obfuscated using this fine mechanism
def xorarr(data: bytes):
    tbl = [22, 108, 20, 230, 46, 145, 13, 64, 33, 53, 213, 64, 19, 3, 233, 128]
    ret = b""
    idx = 0
    for byte in data:
        ret += bytes([byte ^ tbl[idx]])
        idx = (idx + 1) % len(tbl)
    return ret


# if this crc was used for communication to AND from the radio, then it
# would be a measure to increase reliability.
# but it's only used towards the radio, so it's for further obfuscation
def calculate_crc16_xmodem(data: bytes):
    poly = 0x1021
    crc = 0x0
    for byte in data:
        crc = crc ^ (byte << 8)
        for i in range(8):
            crc = crc << 1
            if (crc & 0x10000):
                crc = (crc ^ poly) & 0xFFFF
    return crc & 0xFFFF


def _send_command(serport, data: bytes):
    """Send a command to UV-K5 radio"""
    LOG.debug("Sending command (unobfuscated) len=0x%4.4x:\n%s" %
              (len(data), util.hexprint(data)))

    crc = calculate_crc16_xmodem(data)
    data2 = data + struct.pack("<H", crc)

    command = struct.pack(">HBB", 0xabcd, len(data), 0) + \
        xorarr(data2) + \
        struct.pack(">H", 0xdcba)
    if DEBUG_SHOW_OBFUSCATED_COMMANDS:
        LOG.debug("Sending command (obfuscated):\n%s" % util.hexprint(command))
    try:
        result = serport.write(command)
    except Exception:
        raise errors.RadioError("Error writing data to radio")
    return result


def _receive_reply(serport):
    header = serport.read(4)
    if len(header) != 4:
        LOG.warning("Header short read: [%s] len=%i" %
                    (util.hexprint(header), len(header)))
        raise errors.RadioError("Header short read")
    if header[0] != 0xAB or header[1] != 0xCD or header[3] != 0x00:
        LOG.warning("Bad response header: %s len=%i" %
                    (util.hexprint(header), len(header)))
        raise errors.RadioError("Bad response header")

    cmd = serport.read(int(header[2]))
    if len(cmd) != int(header[2]):
        LOG.warning("Body short read: [%s] len=%i" %
                    (util.hexprint(cmd), len(cmd)))
        raise errors.RadioError("Command body short read")

    footer = serport.read(4)

    if len(footer) != 4:
        LOG.warning("Footer short read: [%s] len=%i" %
                    (util.hexprint(footer), len(footer)))
        raise errors.RadioError("Footer short read")

    if footer[2] != 0xDC or footer[3] != 0xBA:
        LOG.debug(
                "Reply before bad response footer (obfuscated)"
                "len=0x%4.4x:\n%s" % (len(cmd), util.hexprint(cmd)))
        LOG.warning("Bad response footer: %s len=%i" %
                    (util.hexprint(footer), len(footer)))
        raise errors.RadioError("Bad response footer")

    if DEBUG_SHOW_OBFUSCATED_COMMANDS:
        LOG.debug("Received reply (obfuscated) len=0x%4.4x:\n%s" %
                  (len(cmd), util.hexprint(cmd)))

    cmd2 = xorarr(cmd)

    LOG.debug("Received reply (unobfuscated) len=0x%4.4x:\n%s" %
              (len(cmd2), util.hexprint(cmd2)))

    return cmd2


def _getstring(data: bytes, begin, maxlen):
    tmplen = min(maxlen+1, len(data))
    s = [data[i] for i in range(begin, tmplen)]
    for key, val in enumerate(s):
        if val < ord(' ') or val > ord('~'):
            break
    return ''.join(chr(x) for x in s[0:key])


def _sayhello(serport):
    timestamp = int(time.time())
    hellopacket = b"\x14\x05\x04\x00" + timestamp.to_bytes(4, 'little')

    tries = 5
    while True:
        LOG.debug("Sending hello packet")
        _send_command(serport, hellopacket)
        rep = _receive_reply(serport)
        if rep:
            break
        tries -= 1
        if tries == 0:
            LOG.warning("Failed to initialise radio")
            raise errors.RadioError("Failed to initialize radio")

    if rep.startswith(b'\x18\x05'):
        raise errors.RadioError(_(
            "This radio is in firmware flash mode (PTT + turn on). "
            "Please do this according to the vendor documentation"))

    firmware = _getstring(rep, 4, 20)
    LOG.info("Found firmware: %s", firmware)

    return firmware, timestamp.to_bytes(4, 'little')


def _readmem(serport, token, offset, length):
    LOG.debug("Sending readmem offset=0x%4.4x len=0x%4.4x" % (offset, length))

    readmem = b"\x1b\x05\x08\x00" + \
        struct.pack("<HBB", offset, length, 0) + token
    _send_command(serport, readmem)
    o = _receive_reply(serport)
    if DEBUG_SHOW_MEMORY_ACTIONS:
        LOG.debug("readmem Received data len=0x%4.4x:\n%s" %
                  (len(o), util.hexprint(o)))
    return o[8:]


def _writemem(serport, token, data, offset):
    LOG.debug("Sending writemem offset=0x%4.4x len=0x%4.4x" %
              (offset, len(data)))

    if DEBUG_SHOW_MEMORY_ACTIONS:
        LOG.debug("writemem sent data offset=0x%4.4x len=0x%4.4x:\n%s" %
                  (offset, len(data), util.hexprint(data)))

    dlen = len(data)
    writemem = b"\x1d\x05" + \
        struct.pack("<BBHBB", dlen+8, 0, offset, dlen, 1) + token + data

    _send_command(serport, writemem)
    o = _receive_reply(serport)

    LOG.debug("writemem Received data: %s len=%i" % (util.hexprint(o), len(o)))

    if (o[0] == 0x1e and
        o[4] == (offset & 0xff) and
        o[5] == (offset >> 8) & 0xff):
        return True
    else:
        LOG.warning("Bad data from writemem")
        raise errors.RadioError("Bad response to writemem")


def _resetradio(serport):
    resetpacket = b"\xdd\x05\x00\x00"
    _send_command(serport, resetpacket)


def do_download(radio):
    """download eeprom from radio"""
    serport = radio.pipe
    serport.timeout = 0.5
    status = chirp_common.Status()
    status.cur = 0
    status.max = MEM_SIZE
    status.msg = "Downloading from radio"
    radio.status_fn(status)

    eeprom = b""
    f, token = _sayhello(serport)
    if not f:
        raise errors.RadioError('Unable to determine firmware version')

    if not radio.k5_approve_firmware(f):
        raise errors.RadioError(
            'Firmware version is not supported by this driver')

    radio.metadata = {'uvk5_firmware': f}

    addr = 0
    while addr < MEM_SIZE:
        o = _readmem(serport, token, addr, MEM_BLOCK)
        status.cur = addr
        radio.status_fn(status)

        if o and len(o) == MEM_BLOCK:
            eeprom += o
            addr += MEM_BLOCK
        else:
            raise errors.RadioError("Memory download incomplete")

    return memmap.MemoryMapBytes(eeprom)


def do_upload(radio):
    serport = radio.pipe
    serport.timeout = 0.5
    status = chirp_common.Status()
    status.cur = 0
    status.max = PROG_SIZE
    status.msg = "Uploading to radio"
    radio.status_fn(status)

    f, token = _sayhello(serport)
    if not f:
        raise errors.RadioError('Unable to determine firmware version')

    if not radio.k5_approve_firmware(f):
        raise errors.RadioError(
            'Firmware version is not supported by this driver')
    LOG.info('Uploading image from firmware %r to radio with %r',
             radio.metadata.get('uvk5_firmware', 'unknown'), f)

    addr = 0
    while addr < PROG_SIZE:
        dat = radio.get_mmap()[addr:addr+MEM_BLOCK]
        _writemem(serport, token, dat, addr)
        status.cur = addr
        radio.status_fn(status)
        if dat:
            addr += MEM_BLOCK
        else:
            raise errors.RadioError("Memory upload incomplete")
    status.msg = "Uploaded OK"

    _resetradio(serport)

    return True


def _find_band(hz, include_end=False):
    mhz = hz / 1000000.0

    for a in BANDS:
        if include_end and mhz == BANDS[a][1]:
            return a
        if BANDS[a][0] <= mhz < BANDS[a][1]:
            return a
    return False


@directory.register
class UVK5RXJPRadio(chirp_common.CloneModeRadio):
    """Quansheng UV-K5"""
    VENDOR = "Quansheng"
    MODEL = "UV-K5-RX-JP"
    BAUD_RATE = 38400
    NEEDS_COMPAT_SERIAL = False

    @classmethod
    def k5_approve_firmware(cls, firmware):
        return firmware.startswith('RX-JP ')

    @classmethod
    def detect_from_serial(cls, pipe):
        firmware, _ = _sayhello(pipe)
        for rclass in [UVK5RXJPRadio]:
            if rclass.k5_approve_firmware(firmware):
                return rclass
        raise errors.RadioError(_('Firmware %r not supported') % firmware)

    def get_prompts(x=None):
        rp = chirp_common.RadioPrompts()
        rp.experimental = _(
            'This is an experimental driver for the Quansheng UV-K5. '
            'It may harm your radio, or worse. Use at your own risk.\n\n'
            'Before attempting to do any changes please download '
            'the memory image from the radio with chirp '
            'and keep it. This can be later used to recover the '
            'original settings. \n\n'
            'some details are not yet implemented')
        rp.pre_download = _(
            "1. Turn radio on.\n"
            "2. Connect cable to mic/spkr connector.\n"
            "3. Make sure connector is firmly connected.\n"
            "4. Click OK to download image from device.\n\n"
            "It will may not work if you turn on the radio "
            "with the cable already attached\n")
        rp.pre_upload = _(
            "1. Turn radio on.\n"
            "2. Connect cable to mic/spkr connector.\n"
            "3. Make sure connector is firmly connected.\n"
            "4. Click OK to upload the image to device.\n\n"
            "It will may not work if you turn on the radio "
            "with the cable already attached")
        return rp

    # Return information about this radio's features, including
    # how many memories it has, what bands it supports, etc
    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_bank = False
        rf.has_bandwidth = True
        rf.valid_dtcs_codes = chirp_common.DTCS_CODES
        rf.has_rx_dtcs = False
        rf.has_ctone = False
        rf.has_settings = True
        rf.has_offset = False
        rf.has_comment = False
        rf.has_freq2 = True
        rf.has_name2 = True
        rf.valid_name_length = 10
        rf.valid_special_chans = list(SPECIALS.keys())
        rf.valid_duplexes = []
        rf.valid_dtcs_pols = ["NN", "RR"]

        # hack so we can input any frequency,
        rf.valid_tuning_steps = STEPS

        rf.valid_tmodes = ["", "TSQL", "TSQL-R", "DTCS"]

        rf.valid_characters = chirp_common.CHARSET_ASCII
        rf.valid_modes = ["FM", "AM", "USB"]
        rf.valid_bandwidths = BANDWIDTH_LIST

        rf.valid_skips = []

        # This radio supports memories 1-200, 201-216 are the custom bands
        rf.memory_bounds = (1, 200)

        rf.valid_bands = []
        for _, b in BANDS.items():
            rf.valid_bands.append(
                (int(b[0] * 1000000), int(b[1] * 1000000)))
        return rf

    # Do a download of the radio from the serial port
    def sync_in(self):
        self._mmap = do_download(self)
        self.process_mmap()

    # Do an upload of the radio to the serial port
    def sync_out(self):
        do_upload(self)

    def _check_firmware_at_load(self):
        firmware = self.metadata.get('uvk5_firmware')
        if not firmware:
            LOG.warning(_(
                'This image is missing firmware information. '
                'It may have been generated with an old or '
                'modified version of CHIRP. It is advised that '
                'you download a fresh image from your radio and '
                'use that going forward for the best safety and '
                'compatibility.'))
        elif not self.k5_approve_firmware(self.metadata['uvk5_firmware']):
            raise errors.RadioError(
                _('Image firmware is %r but is not supported by this driver') % firmware)

    # Convert the raw byte array into a memory object structure
    def process_mmap(self):
        self._check_firmware_at_load()
        self._memobj = bitwise.parse(MEM_FORMAT, self._mmap)
        self._memobj.language = 3

    def validate_memory(self, mem):
        msgs = super().validate_memory(mem)

        # Sub Frequency
        if mem.freq2 and mem.freq2 > 0:
            if (len(mem.name) > 8):
                msg = _("When setting SubFrequency, the Name and SubName are limited to 8 characters each")
                msgs.append(chirp_common.ValidationError(msg))

            if _find_band(mem.freq2, mem.number > 200) is False:
                msg = _("The sub frequency %.4f MHz is not supported by this radio") \
                    % (mem.freq2 / 1000000.0)
                msgs.append(chirp_common.ValidationError(msg))

        # tone is FM mode only
        if (mem.mode != "FM" and mem.tmode != ""):
                msg = _("Tone mode can be set in FM mode only")
                msgs.append(chirp_common.ValidationError(msg))

        return msgs

    def _set_tone(self, mem, _mem):
        match mem.tmode:
            case "TSQL":
                _mem.rxcodeflag = TONE_CTCSS
                _mem.rxcode = chirp_common.TONES.index(mem.rtone)
            case "TSQL-R":
                _mem.rxcodeflag = TONE_CTCSS_R
                _mem.rxcode = chirp_common.TONES.index(mem.rtone)
            case "DTCS":
                if mem.dtcs_polarity == "RR":
                    _mem.rxcodeflag = TONE_DCS_R
                else:
                    _mem.rxcodeflag = TONE_DCS
                _mem.rxcode = chirp_common.DTCS_CODES.index(mem.dtcs)
            case _:
                _mem.rxcodeflag = TONE_NONE
                _mem.rxcode = 0

        _mem.txcodeflag = _mem.rxcodeflag
        _mem.txcode = _mem.rxcode

    def _get_tone(self, mem, _mem):
        mem.tmode = TMODES[_mem.rxcodeflag]
        match mem.tmode:
            case "TSQL" | "TSQL-R":
                mem.rtone = chirp_common.TONES[_mem.rxcode]
            case "DTCS":
                mem.dtcs = chirp_common.DTCS_CODES[_mem.rxcode]
                mem.dtcs_polarity = "RR" if _mem.rxcodeflag == TONE_DCS_R else "NN"

    def _clean_name(self, text):
        out = ''
        for char in text:
            if str(char) == "\xFF" or str(char) == "\x00":
                break
            out += str(char)
        return out.strip()

    def _get_mem_extra(self, mem):
        enc = 0
        tmpscn = SCANLIST_LIST[0]

        # We'll also look at the channel attributes if a memory has them
        if mem.number <= 200:
            _mem = self._memobj.channel[mem.number - 1]
            _mem3 = self._memobj.channel_attributes[mem.number - 1]
            # free memory bit
            if _mem3.get_raw(asbytes=False)[0] == "\xff":
                mem.empty = True
            elif _mem3.is_free > 0:
                mem.empty = True
                _mem3.set_raw("\xFF")

            # scanlists
            if _mem3.is_scanlist1 > 0 and _mem3.is_scanlist2 > 0:
                tmpscn = SCANLIST_LIST[3]  # "1+2"
            elif _mem3.is_scanlist1 > 0:
                tmpscn = SCANLIST_LIST[1]  # "1"
            elif _mem3.is_scanlist2 > 0:
                tmpscn = SCANLIST_LIST[2]  # "2"

            # Scrambler
            if _mem.scrambler & 0x0f < len(SCRAMBLER_LIST):
                enc = _mem.scrambler & 0x0f

        mem.extra = RadioSettingGroup("Extra", "extra")
        rs = RadioSetting(
            "scrambler", _("Scrambler"),
            RadioSettingValueList(SCRAMBLER_LIST, SCRAMBLER_LIST[enc])
        )
        mem.extra.append(rs)
        rs = RadioSetting(
            "scanlists", _("Scanlists"),
            RadioSettingValueList(SCANLIST_LIST, tmpscn)
        )
        mem.extra.append(rs)

    def _get_custom_band_memory(self, number2):
        mem = chirp_common.Memory()
        mem.name = '-'
        mem.immutable = [
            "name", "tmode", "rtone", "dtcs", "dtcs_polarity", "scanlists",
            "extra.scrambler", "extra.scanlists",
        ]

        if isinstance(number2, str):
            number0 = SPECIALS.get(number2)
            mem.extd_number = number2
        else:
            number0 = number2 - 1

        mem.number = number0 + 1

        band_idx = number0 - 200
        _mem1 = self._memobj.custom_band_freq[band_idx]
        _mem2 = self._memobj.custom_band[band_idx]

        # freq
        mem.freq = int(_mem1.start) * 10
        mem.freq2 = int(_mem1.end) * 10

        band1 = _find_band(mem.freq)
        band2 = _find_band(mem.freq2, include_end=True)
        if band1 is False:
            mem.freq = 0
            mem.freq2 = 0
            mem.empty = True
            return mem
        elif band2 is False:
            mem.freq2 = mem.freq

        # name
        mem.name2 = self._clean_name(self._memobj.bandname[band_idx].name)

        # mode
        match _mem2.modulation:
            case 1:
                mem.mode = "AM"
            case 2:
                mem.mode = "USB"
            case _:
                mem.mode = "FM"

        # Bandwidth
        bw = _mem2.bandwidth if _mem2.bandwidth < len(BANDWIDTH_LIST) else 0
        mem.bandwidth = BANDWIDTH_LIST[bw]

        # tuning step
        tstep = _mem2.step if _mem2.step < len(STEPS) else 2
        mem.tuning_step = STEPS[tstep]

        self._get_mem_extra(mem)
        return mem

    # Extract a high-level memory object from the low-level memory map
    # This is called to populate a memory in the UI
    def get_memory(self, number2):
        # custom_band
        if isinstance(number2, str) or number2 > 200:
            return self._get_custom_band_memory(number2)

        mem = chirp_common.Memory()
        mem.number = number2
        number0 = number2 - 1
        _mem = self._memobj.channel[number0]
        self._get_mem_extra(mem)

        # We'll consider any blank (i.e. 0 MHz frequency) to be empty
        if (_mem.freq1 == 0xffffffff) or (_mem.freq1 == 0):
            mem.empty = True
            return mem

        # Convert your low-level frequency to Hertz
        mem.freq = int(_mem.freq1) * 10
        mem.freq2 = int(_mem.freq2) * 10

        # name
        _mem2 = self._memobj.channelname[number0]
        mem.name = self._clean_name(_mem2.name1)
        if _mem.freq2 > 0:
            mem.name2 = self._clean_name(_mem2.name2)
        else:
            mem.name += self._clean_name(_mem2.name2)

        # tone data
        self._get_tone(mem, _mem)

        # mode
        match _mem.modulation:
            case 1:
                mem.mode = "AM"
            case 2:
                mem.mode = "USB"
            case _:
                mem.mode = "FM"

        # Bandwidth
        bw = _mem.bandwidth if _mem.bandwidth < len(BANDWIDTH_LIST) else 0
        mem.bandwidth = BANDWIDTH_LIST[bw]

        # tuning step
        tstep = _mem.step if _mem.step < len(STEPS) else 2
        mem.tuning_step = STEPS[tstep]

        return mem

    def set_settings(self, settings):
        _mem = self._memobj
        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue

            # basic settings

            # squelch
            if element.get_name() == "squelch":
                _mem.squelch = int(element.value)

            # Channel display mode
            if element.get_name() == "channel_display_mode":
                _mem.channel_display_mode = CHANNELDISP_LIST.index(
                    str(element.value))

            # Battery Save
            if element.get_name() == "battery_save":
                _mem.battery_save = BATSAVE_LIST.index(str(element.value))
            # Dual Watch
            if element.get_name() == "dualwatch":
                _mem.dual_watch = DUALWATCH_LIST.index(str(element.value))

            # Backlight auto mode
            if element.get_name() == "backlight_time":
                _mem.backlight_time = BACKLIGHT_LIST.index(str(element.value))

            # Tail tone elimination
            if element.get_name() == "tail_note_elimination":
                _mem.tail_note_elimination = element.value and 1 or 0

            # Beep control
            if element.get_name() == "beep_control":
                _mem.beep_control = element.value and 1 or 0

            # Scan resume mode
            if element.get_name() == "scan_resume_mode":
                _mem.scan_resume_mode = SCANRESUME_LIST.index(
                    str(element.value))

            # Keypad lock
            if element.get_name() == "key_lock":
                _mem.key_lock = element.value and 1 or 0

            # Auto keypad lock
            if element.get_name() == "auto_keypad_lock":
                _mem.auto_keypad_lock = element.value and 1 or 0

            # Power on display mode
            if element.get_name() == "welcome_mode":
                _mem.power_on_dispmode = WELCOME_LIST.index(str(element.value))

            # Logo string 1
            if element.get_name() == "logo1":
                b = str(element.value).rstrip("\x20\xff\x00")+"\x00"*12
                _mem.logo_line1 = b[0:12]+"\x00\xff\xff\xff"

            # Logo string 2
            if element.get_name() == "logo2":
                b = str(element.value).rstrip("\x20\xff\x00")+"\x00"*12
                _mem.logo_line2 = b[0:12]+"\x00\xff\xff\xff"

            # fm radio
            for i in range(1, 21):
                freqname = "FM_" + str(i)
                if element.get_name() == freqname:
                    val = str(element.value).strip()
                    try:
                        val2 = int(float(val)*10)
                    except Exception:
                        val2 = 0xffff

                    if val2 < FMMIN*10 or val2 > FMMAX*10:
                        val2 = 0xffff
#                        raise errors.InvalidValueError(
#                                "FM radio frequency should be a value "
#                                "in the range %.1f - %.1f" % (FMMIN , FMMAX))
                    _mem.fmfreq[i-1] = val2

            if element.get_name() == "key1_shortpress_action":
                _mem.key1_shortpress_action = KEYACTIONS_LIST_ALL.index(
                        str(element.value))

            if element.get_name() == "key1_longpress_action":
                _mem.key1_longpress_action = KEYACTIONS_LIST_ALL.index(
                        str(element.value))

            if element.get_name() == "key2_shortpress_action":
                _mem.key2_shortpress_action = KEYACTIONS_LIST_ALL.index(
                        str(element.value))

            if element.get_name() == "key2_longpress_action":
                _mem.key2_longpress_action = KEYACTIONS_LIST_ALL.index(
                        str(element.value))

            if element.get_name() == "keyM_longpress_action":
                _mem.keyM_longpress_action = KEYACTIONS_LIST_ALL.index(
                        str(element.value))

    def get_settings(self):
        _mem = self._memobj
        basic = RadioSettingGroup("basic", _("Basic Settings"))
        keya = RadioSettingGroup("keya", _("Programmable keys"))
        fmradio = RadioSettingGroup("fmradio", _("FM Radio"))

        roinfo = RadioSettingGroup("roinfo", _("Driver information"))

        top = RadioSettings(
                basic, keya, fmradio, roinfo)

        # Programmable keys
        tmpval = int(_mem.key1_shortpress_action)
        if tmpval >= len(KEYACTIONS_LIST_ALL):
            tmpval = 0
        rs = RadioSetting("key1_shortpress_action", _("Side key 1 short press"),
                          RadioSettingValueList(
                              KEYACTIONS_LIST, KEYACTIONS_LIST_ALL[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.key1_longpress_action)
        if tmpval >= len(KEYACTIONS_LIST_ALL):
            tmpval = 0
        rs = RadioSetting("key1_longpress_action", _("Side key 1 long press"),
                          RadioSettingValueList(
                              KEYACTIONS_LIST, KEYACTIONS_LIST_ALL[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.key2_shortpress_action)
        if tmpval >= len(KEYACTIONS_LIST_ALL):
            tmpval = 0
        rs = RadioSetting("key2_shortpress_action", _("Side key 2 short press"),
                          RadioSettingValueList(
                              KEYACTIONS_LIST, KEYACTIONS_LIST_ALL[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.key2_longpress_action)
        if tmpval >= len(KEYACTIONS_LIST_ALL):
            tmpval = 0
        rs = RadioSetting("key2_longpress_action", _("Side key 2 long press"),
                          RadioSettingValueList(
                              KEYACTIONS_LIST, KEYACTIONS_LIST_ALL[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.keyM_longpress_action)
        if tmpval >= len(KEYACTIONS_LIST_ALL):
            tmpval = 0
        rs = RadioSetting("keyM_longpress_action", _("Menu key long press"),
                          RadioSettingValueList(
                              KEYACTIONS_LIST, KEYACTIONS_LIST_ALL[tmpval]))
        keya.append(rs)

        # basic settings

        # squelch
        tmpsq = _mem.squelch
        if tmpsq > 9:
            tmpsq = 1
        rs = RadioSetting("squelch", _("Squelch"),
                          RadioSettingValueInteger(0, 9, tmpsq))
        basic.append(rs)

        # Channel display mode
        tmpchdispmode = _mem.channel_display_mode
        if tmpchdispmode >= len(CHANNELDISP_LIST):
            tmpchdispmode = 0
        rs = RadioSetting(
                "channel_display_mode",
                _("Channel display mode"),
                RadioSettingValueList(
                    CHANNELDISP_LIST,
                    CHANNELDISP_LIST[tmpchdispmode]))
        basic.append(rs)

        # Battery save
        tmpbatsave = _mem.battery_save
        if tmpbatsave >= len(BATSAVE_LIST):
            tmpbatsave = BATSAVE_LIST.index("1:4")
        rs = RadioSetting(
                "battery_save",
                _("Battery Save"),
                RadioSettingValueList(
                    BATSAVE_LIST,
                    BATSAVE_LIST[tmpbatsave]))
        basic.append(rs)

        # Dual watch
        tmpdual = _mem.dual_watch
        if tmpdual >= len(DUALWATCH_LIST):
            tmpdual = 1
        rs = RadioSetting("dualwatch", _("Dual RX"), RadioSettingValueList(
            DUALWATCH_LIST, DUALWATCH_LIST[tmpdual]))
        basic.append(rs)

        # Backlight auto mode
        tmpback = _mem.backlight_time
        if tmpback >= len(BACKLIGHT_LIST):
            tmpback = 0
        rs = RadioSetting("backlight_auto_mode",
                          _("Backlight auto mode"),
                          RadioSettingValueList(
                              BACKLIGHT_LIST,
                              BACKLIGHT_LIST[tmpback]))
        basic.append(rs)

        # Tail tone elimination
        rs = RadioSetting(
                "tail_note_elimination",
                _("Tail tone elimination"),
                RadioSettingValueBoolean(
                    bool(_mem.tail_note_elimination > 0)))
        basic.append(rs)

        # Beep control
        rs = RadioSetting(
                "beep_control",
                _("Beep control"),
                RadioSettingValueBoolean(bool(_mem.beep_control > 0)))
        basic.append(rs)

        # Scan resume mode
        tmpscanres = _mem.scan_resume_mode
        if tmpscanres >= len(SCANRESUME_LIST):
            tmpscanres = 0
        rs = RadioSetting(
                "scan_resume_mode",
                _("Scan resume mode"),
                RadioSettingValueList(
                    SCANRESUME_LIST,
                    SCANRESUME_LIST[tmpscanres]))
        basic.append(rs)

        # Keypad locked
        rs = RadioSetting(
                "key_lock",
                _("Keypad lock"),
                RadioSettingValueBoolean(bool(_mem.key_lock > 0)))
        basic.append(rs)

        # Auto keypad lock
        rs = RadioSetting(
                "auto_keypad_lock",
                _("Auto keypad lock"),
                RadioSettingValueBoolean(bool(_mem.auto_keypad_lock > 0)))
        basic.append(rs)

        # Power on display mode
        tmpdispmode = _mem.power_on_dispmode
        if tmpdispmode >= len(WELCOME_LIST):
            tmpdispmode = 0
        rs = RadioSetting(
                "welcome_mode",
                _("Power on display mode"),
                RadioSettingValueList(
                    WELCOME_LIST,
                    WELCOME_LIST[tmpdispmode]))
        basic.append(rs)

        # Logo string 1
        logo1 = str(_mem.logo_line1).strip("\x20\x00\xff") + "\x00"
        logo1 = _getstring(logo1.encode('ascii', errors='ignore'), 0, 12)
        rs = RadioSetting("logo1", _("Logo string 1 (12 characters)"),
                          RadioSettingValueString(0, 12, logo1))
        basic.append(rs)

        # Logo string 2
        logo2 = str(_mem.logo_line2).strip("\x20\x00\xff") + "\x00"
        logo2 = _getstring(logo2.encode('ascii', errors='ignore'), 0, 12)
        rs = RadioSetting("logo2", _("Logo string 2 (12 characters)"),
                          RadioSettingValueString(0, 12, logo2))
        basic.append(rs)

        # FM radio
        for i in range(1, 21):
            freqname = "FM_"+str(i)
            fmfreq = _mem.fmfreq[i-1]/10.0
            if fmfreq < FMMIN or fmfreq > FMMAX:
                rs = RadioSetting(freqname, freqname,
                                  RadioSettingValueString(0, 5, ""))
            else:
                rs = RadioSetting(freqname, freqname,
                                  RadioSettingValueString(0, 5, str(fmfreq)))

            fmradio.append(rs)

        # readonly info
        # Firmware
        firmware = self.metadata.get('uvk5_firmware', 'UNKNOWN')

        val = RadioSettingValueString(0, 128, firmware)
        val.set_mutable(False)
        rs = RadioSetting("fw_ver", "Firmware Version", val)
        roinfo.append(rs)

        return top

    def _set_mem_mode(self, _mem, mode):
        match mode:
            case "FM":
                _mem.modulation = 0
            case "AM":
                _mem.modulation = 1
            case "USB":
                _mem.modulation = 2
                _mem.bandwidth = 2  # N-

    def _set_custom_band_memory(self, mem):
        if isinstance(mem.number, str):
            number = SPECIALS.get(mem.number) - 200
        else:
            number = mem.number - 201

        # Get a low-level memory object mapped to the image
        _mem1 = self._memobj.custom_band_freq[number]
        _mem2 = self._memobj.custom_band[number]

        if mem.empty:
            _mem1.set_raw("\xFF" * 8)
            _mem2.set_raw("\xFF" * 4)
            return

        if _mem1.get_raw(asbytes=False)[0] == "\xff":
            # this was an empty memory
            _mem1.set_raw("\x00" * 8)
            _mem2.set_raw("\x00" * 4)

        # frequency
        if mem.freq2 == 0:
            mem.freq2 = mem.freq
        if mem.freq > mem.freq2:
            _mem1.start = mem.freq2 / 10
            _mem1.end = mem.freq / 10
        else:
            _mem1.start = mem.freq / 10
            _mem1.end = mem.freq2 / 10

        # bandwidth
        match mem.bandwidth:
            case 'N':
                _mem2.bandwidth = 1
            case 'N-':
                _mem2.bandwidth = 2
            case 'W+':
                _mem2.bandwidth = 3
            case _:
                _mem2.bandwidth = 0

        # modulation
        self._set_mem_mode(_mem2, mem.mode)

        # step
        _mem2.step = STEPS.index(mem.tuning_step)

        # name
        self._memobj.bandname[number].name = mem.name2[:15].ljust(16)

    # Store details about a high-level memory to the memory map
    # This is called when a user edits a memory in the UI
    def set_memory(self, mem):
        if isinstance(mem.number, str):
            number = SPECIALS.get(mem.number)
        else:
            number = mem.number - 1

        # custom band
        if number >= 200:
            self._set_custom_band_memory(mem)
            return

        # Get a low-level memory object mapped to the image
        _mem = self._memobj.channel[number]
        _mem4 = self._memobj
        # empty memory
        if mem.empty:
            _mem.set_raw("\xFF" * 16)
            if number < 200:
                _mem2 = self._memobj.channelname[number]
                _mem2.set_raw("\xFF" * 16)
                _mem4.channel_attributes[number].set_raw("\xFF")
            return

        # clean the channel memory, restore some bits if it was used before
        if _mem.get_raw(asbytes=False)[0] == "\xff":
            # this was an empty memory
            _mem.set_raw("\x00" * 16)
        else:
            # this memory wasn't empty, save some bits that we don't know the
            # meaning of, or that we don't support yet
            prev_0a = _mem.get_raw()[0x0a] & SAVE_MASK_0A
            prev_0b = _mem.get_raw()[0x0b] & SAVE_MASK_0B
            prev_0c = _mem.get_raw()[0x0c] & SAVE_MASK_0C
            prev_0d = _mem.get_raw()[0x0d] & SAVE_MASK_0D
            prev_0e = _mem.get_raw()[0x0e] & SAVE_MASK_0E
            prev_0f = _mem.get_raw()[0x0f] & SAVE_MASK_0F
            _mem.set_raw("\x00" * 10 +
                         chr(prev_0a) + chr(prev_0b) + chr(prev_0c) +
                         chr(prev_0d) + chr(prev_0e) + chr(prev_0f))

        _mem4.channel_attributes[number].is_free = 0
        _mem4.channel_attributes[number].is_scanlist1 = 0
        _mem4.channel_attributes[number].is_scanlist2 = 0

        # bandwidth
        match mem.bandwidth:
            case 'N':
                _mem.bandwidth = 1
            case 'N-':
                _mem.bandwidth = 2
            case 'W+':
                _mem.bandwidth = 3
            case _:
                _mem.bandwidth = 0

        # mode
        self._set_mem_mode(_mem, mem.mode)

        # frequency/shift
        _mem.freq1 = mem.freq / 10
        if (mem.freq2 and mem.freq2 > 0):
            _mem.freq2 = mem.freq2 / 10
        _mem.shift = 0

        # channelname
        _mem2 = self._memobj.channelname[number]
        if (mem.freq2 and mem.freq2 > 0):
            _mem2.name1 = mem.name[:8].ljust(8)
            _mem2.name2 = mem.name2[:8].ljust(8)
        else:
            _mem2.name1 = mem.name[:8].ljust(8)
            _mem2.name2 = mem.name[8:16].ljust(8)

        # tone data
        self._set_tone(mem, _mem)

        # step
        _mem.step = STEPS.index(mem.tuning_step)

        # set default value
        _mem.txpower = POWER_LOW
        _mem.freq_reverse = 0

        for setting in mem.extra:
            sname = setting.get_name()
            svalue = setting.value.get_value()

            if sname == "scrambler":
                _mem.scrambler = (
                    _mem.scrambler & 0xf0) | SCRAMBLER_LIST.index(svalue)

            elif sname == "scanlists":
                match svalue:
                    case "1":
                        _mem4.channel_attributes[number].is_scanlist1 = 1
                        _mem4.channel_attributes[number].is_scanlist2 = 0
                    case "2":
                        _mem4.channel_attributes[number].is_scanlist1 = 0
                        _mem4.channel_attributes[number].is_scanlist2 = 1
                    case "1+2":
                        _mem4.channel_attributes[number].is_scanlist1 = 1
                        _mem4.channel_attributes[number].is_scanlist2 = 1
                    case _:
                        _mem4.channel_attributes[number].is_scanlist1 = 0
                        _mem4.channel_attributes[number].is_scanlist2 = 0
