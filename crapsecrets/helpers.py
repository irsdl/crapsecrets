import base64
import binascii
import json
import re
import sys
import hmac
import struct
import hashlib
from urllib.parse import urlparse
from colorama import Fore, Style, init
import httpx
from crapsecrets.errors import BadsecretsException
from enum import Enum

init(autoreset=True)  # Automatically reset the color to default after each print statement


def print_status(msg, passthru=False, color="white", colorenabled=True):
    color_dict = {"white": Fore.WHITE, "red": Fore.RED, "yellow": Fore.YELLOW, "blue": Fore.BLUE, "green": Fore.GREEN}

    colorama_color = color_dict.get(color.lower(), Fore.WHITE)

    if msg:
        if colorenabled:
            msg = f"{colorama_color}{msg}{Style.RESET_ALL}"
        if passthru:
            return msg
        else:
            print(msg)


def _writeuint(v):
    return struct.pack(">I", v)

def isolate_app_process(vkey, apppath_hashcode):
    # This is when we have IsolateApps enabled in DOTNET40 (legacy)
    # IsolateApps changes the first 4 bytes of the validationkey
    # It uses the app path to generate the first 4 bytes
    key = binascii.unhexlify(vkey)
    key = bytearray(key)
    if len(key) < 4:
        return None
    key[0] = (apppath_hashcode & 0xff)
    key[1] = (apppath_hashcode & 0xff00) >> 8
    key[2] = (apppath_hashcode & 0xff0000) >> 16
    key[3] = (apppath_hashcode & 0xff000000) >> 24
    return binascii.hexlify(key)

def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]


def matchLooseBase64RegEx(str):
    try:
        if re.match(r'^[A-Za-z0-9+/=]*$', str) or re.match(r'^[A-Za-z0-9-_]*$', str):
            return True
        else:
            return False
    except Exception as e:
        return False

def decode_urlsafe_base64(encoded_str):
    # Calculate the number of missing padding characters
    missing_padding = len(encoded_str) % 4
    if missing_padding:
        encoded_str += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(encoded_str)

def aspnet_resource_b64_to_standard_b64(urlsafe_str):
    """
    The input token is expected to have the last character as a digit indicating the number of '=' 
    padding characters that were removed from the standard base64 string.
    """
    # Replace URL-safe characters with standard Base64 characters
    pad_count = int(urlsafe_str[-1])
    standard_str = urlsafe_str[:-1].replace('-', '+').replace('_', '/')
    standard_str += ('=' * pad_count)

    return standard_str

def sp800_108_derivekey(key, label, context, keyLengthInBits):
    lblcnt = 0 if label is None else len(label)
    ctxcnt = 0 if context is None else len(context)
    buffer = b"\x00" * (4 + lblcnt + 1 + ctxcnt + 4)
    if lblcnt != 0:
        buffer = buffer[:4] + label + buffer[4 + lblcnt :]
    if ctxcnt != 0:
        buffer = buffer[: 5 + lblcnt] + context + buffer[5 + lblcnt + ctxcnt :]
    buffer = buffer[: 5 + lblcnt + ctxcnt] + _writeuint(keyLengthInBits) + buffer[5 + lblcnt + ctxcnt + 4 :]
    v = int(keyLengthInBits / 8)
    res = b"\x00" * v
    num = 1
    while v > 0:
        buffer = _writeuint(num) + buffer[4:]
        h = hmac.new(key, buffer, hashlib.sha512)
        hash = h.digest()
        cnt = min(v, len(hash))
        res = hash[:cnt] + res[cnt:]
        v -= cnt
        num += 1
    return res


def write_vlq_string(string):
    encoded_string = string.encode("utf-8")
    length = len(encoded_string)
    length_vlq = bytearray()
    while length >= 0x80:
        length_vlq.append((length | 0x80) & 0xFF)
        length >>= 7
    length_vlq.append(length)
    return bytes(length_vlq) + encoded_string


def sp800_108_get_key_derivation_parameters(primary_purpose, specific_purposes):
    derived_key_label = primary_purpose.encode("utf-8")
    derived_key_context = b"".join([write_vlq_string(purpose) for purpose in specific_purposes])
    return derived_key_label, derived_key_context


class Purpose(Enum):
    AnonymousIdentificationModule_Ticket = "AnonymousIdentificationModule.Ticket"
    AssemblyResourceLoader_WebResourceUrl = "AssemblyResourceLoader.WebResourceUrl"
    FormsAuthentication_Ticket = "FormsAuthentication.Ticket"
    WebForms_Page_PreviousPageID = "WebForms.Page.PreviousPageID"
    RolePrincipal_Ticket = "RolePrincipal.Ticket"
    ScriptResourceHandler_ScriptResourceUrl = "ScriptResourceHandler.ScriptResourceUrl"
    WebForms_ClientScriptManager_EventValidation = "WebForms.ClientScriptManager.EventValidation"
    WebForms_DetailsView_KeyTable = "WebForms.DetailsView.KeyTable"
    WebForms_GridView_DataKeys = "WebForms.GridView.DataKeys"
    WebForms_GridView_SortExpression = "WebForms.GridView.SortExpression"
    WebForms_HiddenFieldPageStatePersister_ClientState = "WebForms.HiddenFieldPageStatePersister.ClientState"
    WebForms_ScriptManager_HistoryState = "WebForms.ScriptManager.HistoryState"
    WebForms_SessionPageStatePersister_ClientState = "WebForms.SessionPageStatePersister.ClientState"
    User_MachineKey_Protect = "User.MachineKey.Protect"
    User_ObjectStateFormatter_Serialize = "User.ObjectStateFormatter.Serialize"

class Csharp_pbkdf1_exception(BadsecretsException):
    pass


class Csharp_pbkdf1:
    def __init__(self, passwordBytes, saltBytes, iterations):
        self.passwordBytes = passwordBytes
        self.saltBytes = saltBytes
        self.iterations = iterations
        self.extra = bytes([])
        self.extra_count = 0
        self.magic_number = 0
        if not iterations > 0:
            raise Csharp_pbkdf1_exception("Iterations must be greater than 0")

        try:
            self.lasthash = hashlib.sha1(passwordBytes + saltBytes).digest()
        except TypeError:
            raise Csharp_pbkdf1_exception("Password and Salt must be of type bytes")

        self.iterations -= 1

        for i in range(self.iterations - 1):
            self.lasthash = hashlib.sha1(self.lasthash).digest()

        self.derivedBytes = hashlib.sha1(self.lasthash).digest()
        self.ctrl = 1

    def GetBytes(self, keylen):
        if not isinstance(keylen, int):
            raise Csharp_pbkdf1_exception("GetBytes() must be called with an int")

        result = bytearray()

        if len(self.extra) > 0:
            self.magic_number = len(self.extra) - self.extra_count
            if self.magic_number >= keylen:
                result.extend(self.extra[self.extra_count : self.extra_count + keylen])
                if self.magic_number > keylen:
                    self.extra_count += keylen
                else:
                    self.extra = bytes([])
                self.derivedBytes = bytes([])
                return result

            result.extend(self.extra[self.magic_number : self.magic_number + self.magic_number])
            self.extra = bytes([])

        while len(self.derivedBytes) < keylen:
            self.derivedBytes += hashlib.sha1(bytes([ord(str(self.ctrl))]) + self.lasthash).digest()
            self.ctrl += 1

        result.extend(self.derivedBytes[: keylen - self.magic_number])

        if (len(self.derivedBytes) + self.magic_number) > keylen:
            self.extra = self.derivedBytes
            self.extra_count = keylen - self.magic_number

        self.derivedBytes = bytes([])
        return result


def twos_compliment(unsigned):
    bs = bin(unsigned).replace("0b", "")
    val = int(bs, 2)
    b = val.to_bytes(1, byteorder=sys.byteorder, signed=False)
    return int.from_bytes(b, byteorder=sys.byteorder, signed=True)


class Java_sha1prng:
    def __init__(self, key):
        keyBytes = key
        if not isinstance(key, bytes):
            keyBytes = key.encode()

        self.seed = hashlib.sha1(keyBytes).digest()
        self.state = None
        self.outBytes = b""

        # Simulate setseed()
        self.state = hashlib.sha1(self.seed).digest()
        self.outBytes = hashlib.sha1(self.state).digest()
        self.updateState(self.outBytes)

    def updateState(self, output):
        last = 1
        outputBytesArray = bytearray(output)
        newState = bytearray()

        for c, n in zip(self.state, outputBytesArray):
            v = twos_compliment(c) + twos_compliment(n) + last
            finalv = v & 255
            newState.append(finalv)
            last = v >> 8
        self.state = newState

    def get_sha1prng_key(self, outLen):
        while len(self.outBytes) < outLen:
            output = hashlib.sha1(self.state).digest()
            self.outBytes += output
            self.updateState(output)
        return self.outBytes[:outLen]


# Based on https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Plugins/ViewStatePlugin.cs and translated to python. All credit to ysoserial.net.
# Extended by Soroush Dalili (the author of ViewStatePlugin in ysoserial.net) to support more features in Python.
class Viewstate_Helpers:
    is_debug = False

    # JSON mapping DB to create hashcode when missing!
    # This is a hack of an undocumented Microsoft native function used in creating __VIEWSTATEGENERATOR
    JSON_DB = r'''{"\u0001":[1,1,1,1,255,255,3,18,0],"\u0002":[1,1,1,1,255,255,4,18,0],"\u0003":[1,1,1,1,255,255,5,18,0],"\u0004":[1,1,1,1,255,255,6,18,0],"\u0005":[1,1,1,1,255,255,7,18,0],"\u0006":[1,1,1,1,255,255,8,18,0],"\u0007":[1,1,1,1,255,255,9,18,0],"\b":[1,1,1,1,255,255,10,18,0],"\t":[7,5,1,1,1,1,0],"\n":[7,6,1,1,1,1,0],"\u000b":[7,7,1,1,1,1,0],"\f":[7,8,1,1,1,1,0],"\r":[7,9,1,1,1,1,0],"\u000e":[1,1,1,1,255,255,11,18,0],"\u000f":[1,1,1,1,255,255,12,18,0],"\u0010":[1,1,1,1,255,255,13,18,0],"\u0011":[1,1,1,1,255,255,14,18,0],"\u0012":[1,1,1,1,255,255,15,18,0],"\u0013":[1,1,1,1,255,255,16,18,0],"\u0014":[1,1,1,1,255,255,17,18,0],"\u0015":[1,1,1,1,255,255,18,18,0],"\u0016":[1,1,1,1,255,255,19,18,0],"\u0017":[1,1,1,1,255,255,20,18,0],"\u0018":[1,1,1,1,255,255,21,18,0],"\u0019":[1,1,1,1,255,255,22,18,0],"\u001a":[1,1,1,1,255,255,23,18,0],"\u001b":[1,1,1,1,255,255,24,18,0],"\u001c":[1,1,1,1,255,255,25,18,0],"\u001d":[1,1,1,1,255,255,26,18,0],"\u001e":[1,1,1,1,255,255,27,18,0],"\u001f":[1,1,1,1,255,255,28,18,0]," ":[7,2,1,1,1,1,0],"!":[7,28,1,1,1,1,0],"\"":[7,29,1,1,1,1,0],"#":[7,31,1,1,1,1,0],"$":[7,33,1,1,1,1,0],"%":[7,35,1,1,1,1,0],"&":[7,37,1,1,1,1,0],"'" :[1,1,1,1,255,255,128,18,0],"(":[7,39,1,1,1,1,0],")":[7,42,1,1,1,1,0],"*":[7,45,1,1,1,1,0],"+":[8,3,1,1,1,1,0],",":[7,47,1,1,1,1,0],"-":[1,1,1,1,255,255,130,18,0],".":[7,51,1,1,1,1,0],"/":[7,53,1,1,1,1,0],"0":[13,3,1,1,1,1,0],"1":[13,26,1,1,1,1,0],"2":[13,28,1,1,1,1,0],"3":[13,30,1,1,1,1,0],"4":[13,32,1,1,1,1,0],"5":[13,34,1,1,1,1,0],"6":[13,36,1,1,1,1,0],"7":[13,38,1,1,1,1,0],"8":[13,40,1,1,1,1,0],"9":[13,42,1,1,1,1,0],":":[7,55,1,1,1,1,0],";":[7,58,1,1,1,1,0],"<":[8,14,1,1,1,1,0],"=":[8,18,1,1,1,1,0],">":[8,20,1,1,1,1,0],"?":[7,60,1,1,1,1,0],"@":[7,62,1,1,1,1,0],"A":[14,2,1,1,1,1,0],"B":[14,9,1,1,1,1,0],"C":[14,10,1,1,1,1,0],"D":[14,26,1,1,1,1,0],"E":[14,33,1,1,1,1,0],"F":[14,35,1,1,1,1,0],"G":[14,37,1,1,1,1,0],"H":[14,44,1,1,1,1,0],"I":[14,50,1,1,1,1,0],"J":[14,53,1,1,1,1,0],"K":[14,54,1,1,1,1,0],"L":[14,72,1,1,1,1,0],"M":[14,81,1,1,1,1,0],"N":[14,112,1,1,1,1,0],"O":[14,124,1,1,1,1,0],"P":[14,126,1,1,1,1,0],"Q":[14,137,1,1,1,1,0],"R":[14,138,1,1,1,1,0],"S":[14,145,1,1,1,1,0],"T":[14,153,1,1,1,1,0],"U":[14,159,1,1,1,1,0],"V":[14,162,1,1,1,1,0],"W":[14,164,1,1,1,1,0],"X":[14,166,1,1,1,1,0],"Y":[14,167,1,1,1,1,0],"Z":[14,169,1,1,1,1,0],"[":[7,63,1,1,1,1,0],"\\":[7,65,1,1,1,1,0],"]":[7,66,1,1,1,1,0],"^":[7,67,1,1,1,1,0],"_":[7,68,1,1,1,1,0],"`":[7,72,1,1,1,1,0],"a":[14,2,1,1,1,1,0],"b":[14,9,1,1,1,1,0],"c":[14,10,1,1,1,1,0],"d":[14,26,1,1,1,1,0],"e":[14,33,1,1,1,1,0],"f":[14,35,1,1,1,1,0],"g":[14,37,1,1,1,1,0],"h":[14,44,1,1,1,1,0],"i":[14,50,1,1,1,1,0],"j":[14,53,1,1,1,1,0],"k":[14,54,1,1,1,1,0],"l":[14,72,1,1,1,1,0],"m":[14,81,1,1,1,1,0],"n":[14,112,1,1,1,1,0],"o":[14,124,1,1,1,1,0],"p":[14,126,1,1,1,1,0],"q":[14,137,1,1,1,1,0],"r":[14,138,1,1,1,1,0],"s":[14,145,1,1,1,1,0],"t":[14,153,1,1,1,1,0],"u":[14,159,1,1,1,1,0],"v":[14,162,1,1,1,1,0],"w":[14,164,1,1,1,1,0],"x":[14,166,1,1,1,1,0],"y":[14,167,1,1,1,1,0],"z":[14,169,1,1,1,1,0],"{":[7,74,1,1,1,1,0],"|":[7,76,1,1,1,1,0],"}":[7,78,1,1,1,1,0],"~":[7,80,1,1,1,1,0],"\u007f":[1,1,1,1,255,255,29,18,0],"\u0080":[12,250,1,29,1,1,1,0],"\u0081":[12,250,1,30,1,1,1,0],"\u0082":[12,250,1,31,1,1,1,0],"\u0083":[12,250,1,32,1,1,1,0],"\u0084":[12,250,1,33,1,1,1,0],"\u0085":[12,250,1,34,1,1,1,0],"\u0086":[12,250,1,35,1,1,1,0],"\u0087":[12,250,1,36,1,1,1,0],"\u0088":[12,250,1,37,1,1,1,0],"\u0089":[12,250,1,38,1,1,1,0],"\u008a":[12,250,1,39,1,1,1,0],"\u008b":[12,250,1,40,1,1,1,0],"\u008c":[12,250,1,41,1,1,1,0],"\u008d":[12,250,1,42,1,1,1,0],"\u008e":[12,250,1,43,1,1,1,0],"\u008f":[12,250,1,44,1,1,1,0],"\u0090":[12,250,1,45,1,1,1,0],"\u0091":[12,250,1,46,1,1,1,0],"\u0092":[12,250,1,47,1,1,1,0],"\u0093":[12,250,1,48,1,1,1,0],"\u0094":[12,250,1,49,1,1,1,0],"\u0095":[12,250,1,50,1,1,1,0],"\u0096":[12,250,1,51,1,1,1,0],"\u0097":[12,250,1,52,1,1,1,0],"\u0098":[12,250,1,53,1,1,1,0],"\u0099":[12,250,1,54,1,1,1,0],"\u009a":[12,250,1,55,1,1,1,0],"\u009b":[12,250,1,56,1,1,1,0],"\u009c":[12,250,1,57,1,1,1,0],"\u009d":[12,250,1,58,1,1,1,0],"\u009e":[12,250,1,59,1,1,1,0],"\u009f":[12,250,1,60,1,1,1,0],"\u00a0":[7,4,1,1,1,1,0],"\u00a1":[7,81,1,1,1,1,0],"\u00a2":[7,151,1,1,1,1,0],"\u00a3":[7,152,1,1,1,1,0],"\u00a4":[7,153,1,1,1,1,0],"\u00a5":[7,154,1,1,1,1,0],"\u00a6":[7,82,1,1,1,1,0],"\u00a7":[10,6,1,1,1,1,0],"\u00a8":[7,83,1,1,1,1,0],"\u00a9":[10,7,1,1,1,1,0],"\u00aa":[14,2,1,3,1,6,1,1,0],"\u00ab":[8,24,1,1,1,1,0],"\u00ac":[10,8,1,1,1,1,0],"\u00ad":[1,1,1,1,0],"\u00ae":[10,9,1,1,1,1,0],"\u00af":[7,84,1,1,1,1,0],"\u00b0":[10,10,1,1,1,1,0],"\u00b1":[8,23,1,1,1,1,0],"\u00b2":[13,28,1,1,6,1,1,0],"\u00b3":[13,30,1,1,6,1,1,0],"\u00b4":[7,85,1,1,1,1,0],"\u00b5":[10,11,1,1,1,1,0],"\u00b6":[10,12,1,1,1,1,0],"\u00b7":[10,13,1,1,1,1,0],"\u00b8":[7,86,1,1,1,1,0],"\u00b9":[13,26,1,1,6,1,1,0],"\u00ba":[14,124,1,3,1,6,1,1,0],"\u00bb":[8,26,1,1,1,1,0],"\u00bc":[13,13,1,1,1,1,0],"\u00bd":[13,17,1,1,1,1,0],"\u00be":[13,21,1,1,1,1,0],"\u00bf":[7,87,1,1,1,1,0],"\u00c0":[14,2,1,15,1,1,1,0],"\u00c1":[14,2,1,14,1,1,1,0],"\u00c2":[14,2,1,18,1,1,1,0],"\u00c3":[14,2,1,25,1,1,1,0],"\u00c4":[14,2,1,19,1,1,1,0],"\u00c5":[14,2,1,26,1,1,1,0],"\u00c6":[14,2,14,33,1,1,1,1,0],"\u00c7":[14,10,1,28,1,1,1,0],"\u00c8":[14,33,1,15,1,1,1,0],"\u00c9":[14,33,1,14,1,1,1,0],"\u00ca":[14,33,1,18,1,1,1,0],"\u00cb":[14,33,1,19,1,1,1,0],"\u00cc":[14,50,1,15,1,1,1,0],"\u00cd":[14,50,1,14,1,1,1,0],"\u00ce":[14,50,1,18,1,1,1,0],"\u00cf":[14,50,1,19,1,1,1,0],"\u00d0":[14,26,1,104,1,1,1,0],"\u00d1":[14,112,1,25,1,1,1,0],"\u00d2":[14,124,1,15,1,1,1,0],"\u00d3":[14,124,1,14,1,1,1,0],"\u00d4":[14,124,1,18,1,1,1,0],"\u00d5":[14,124,1,25,1,1,1,0],"\u00d6":[14,124,1,19,1,1,1,0],"\u00d7":[8,28,1,1,1,1,0],"\u00d8":[14,124,1,33,1,1,1,0],"\u00d9":[14,159,1,15,1,1,1,0],"\u00da":[14,159,1,14,1,1,1,0],"\u00db":[14,159,1,18,1,1,1,0],"\u00dc":[14,159,1,19,1,1,1,0],"\u00dd":[14,167,1,14,1,1,1,0],"\u00de":[14,153,14,44,1,1,1,1,0],"\u00df":[14,145,14,145,1,1,1,1,0],"\u00e0":[14,2,1,15,1,1,1,0],"\u00e1":[14,2,1,14,1,1,1,0],"\u00e2":[14,2,1,18,1,1,1,0],"\u00e3":[14,2,1,25,1,1,1,0],"\u00e4":[14,2,1,19,1,1,1,0],"\u00e5":[14,2,1,26,1,1,1,0],"\u00e6":[14,2,14,33,1,1,1,1,0],"\u00e7":[14,10,1,28,1,1,1,0],"\u00e8":[14,33,1,15,1,1,1,0],"\u00e9":[14,33,1,14,1,1,1,0],"\u00ea":[14,33,1,18,1,1,1,0],"\u00eb":[14,33,1,19,1,1,1,0],"\u00ec":[14,50,1,15,1,1,1,0],"\u00ed":[14,50,1,14,1,1,1,0],"\u00ee":[14,50,1,18,1,1,1,0],"\u00ef":[14,50,1,19,1,1,1,0],"\u00f0":[14,26,1,104,1,1,1,0],"\u00f1":[14,112,1,25,1,1,1,0],"\u00f2":[14,124,1,15,1,1,1,0],"\u00f3":[14,124,1,14,1,1,1,0],"\u00f4":[14,124,1,18,1,1,1,0],"\u00f5":[14,124,1,25,1,1,1,0],"\u00f6":[14,124,1,19,1,1,1,0],"\u00f7":[8,29,1,1,1,1,0],"\u00f8":[14,124,1,33,1,1,1,0],"\u00f9":[14,159,1,15,1,1,1,0],"\u00fa":[14,159,1,14,1,1,1,0],"\u00fb":[14,159,1,18,1,1,1,0],"\u00fc":[14,159,1,19,1,1,1,0],"\u00fd":[14,167,1,14,1,1,1,0],"\u00fe":[14,153,14,44,1,1,1,1,0],"\u00ff":[14,167,1,19,1,1,1,0]}'''
    
    # ChatGPT suggestion from highest to lowest top 20: Default.aspx, Index.aspx, Home.aspx, Default2.aspx, Default3.aspx, Start.aspx, Welcome.aspx, Main.aspx, DefaultPage.aspx, DefaultHome.aspx, Landing.aspx, MainPage.aspx, Portal.aspx, DefaultIndex.aspx, StartPage.aspx, Dashboard.aspx, Overview.aspx, Entry.aspx, Intro.aspx, DefaultView.aspx

    default_pages_large_set = ["default.aspx", "index.aspx", "home.aspx", "default2.aspx", "default3.aspx", "start.aspx", "welcome.aspx", "main.aspx", "landing.aspx" , "mainpage.aspx", "portal.aspx", "startpage.aspx", "dashboard.aspx", "overview.aspx", "entry.aspx", "defaultview.aspx", "defaultpage.aspx", "defaulthome.aspx", "defaultindex.aspx" , "intro.aspx", "index2.aspx", "default", "index", "home", "default2", "start", "welcome", "main", "landing" , "mainpage", "portal", "startpage", "dashboard", "overview", "entry", "defaultview", "defaultpage", "defaulthome", "defaultindex" , "intro", "index2", "welcomepage.aspx"]

    # Including my top 12 in case we need more performance than findings!
    default_pages = ["default.aspx", "index.aspx", "home.aspx", "default2.aspx", "default3.aspx", "start.aspx", "welcome.aspx", "main.aspx", "landing.aspx" , "mainpage.aspx","error.aspx","CustomError.aspx"]

    default_pages_small_set = ["default.aspx", "index.aspx", "home.aspx", "main.aspx"]

    common_pages = ["default.aspx", "index.aspx", "error.aspx", "errors.aspx","errorpage.aspx","errorpages.aspx","404.aspx","500.aspx","CustomError.aspx","NotFound.aspx", "generic.aspx", "genericerror.aspx", "accessdenied.aspx", "denied.aspx", "nopermission.aspx", "notallowed.aspx", "restricted.aspx", "unauthorized.aspx", "unauthorised.aspx", "unavailable.aspx","forbidden.aspx","error404.aspx","error500.aspx","errorpage404.aspx","errorpage500.aspx", "logon.aspx", "login.aspx", "signin.aspx", "signon.aspx","sso.aspx","ssoerror.aspx","samlerror.aspx", "report.aspx", "reports.aspx", "article.aspx", "articles.aspx", "cms.aspx", "admin.aspx", "administrator.aspx", "header.aspx", "footer.aspx", "ApplicationErrorsViewer.aspx", "ErrorsViewer.aspx", "ApplicationErrors.aspx","ApplicationErrorViewer.aspx", "ErrorViewer.aspx", "ApplicationError.aspx", "Application.aspx", "App.aspx","mobile.aspx","mobilepage.aspx","browser.aspx","privacy.aspx","compatiblity.aspx"]

    common_directories = ["","page","pages","error", "errors", "content", "contents", "errorpage", "errorpages", "404", "500", "customerror", "notfound" ,"report", "reports", "arcticle", "articles", "cms", "portal", "admin", "administrator", "login", "signin", "signon", "blog", "www", "wwwroot", "web", "website", "site", "sites", "view", "views", "ui", "ux", "user", "title", "titles", "dashboard", "welcome", "webui", "application", "app", "applications", "apps", "secure", "protected", "safe" , "restricted", "m", "mobile","mobilepages"]

    verified_path = None
    verified_apppath = None

    # verified_potential_apppaths can be useful when we have a way to verify which path is an application path (actively or passively)
    verified_potential_apppaths = set()
    generators = []

    def __init__(self, url, generator="00000000", findviewstatepage=False, calculate_generator=True, is_debug=False):
        self.is_debug = is_debug
        self.url = self.clean_aspx_path(self.normalize_path_in_url(self.remove_cookieless_if_needed(url)))
        self.findviewstatepage = findviewstatepage
        self.db = json.loads(self.JSON_DB)
        self.calculate_generator = calculate_generator

        if generator != "00000000":
            self.generators = [generator]
            #self.default_pages = self.default_pages_large_set
            self.verified_path, self.verified_apppath = self.find_valid_path_params_by_generator(generator)
            if not (self.verified_path and self.verified_apppath):
                # Generator does not match the path, we are not doing well here!
                if self.is_debug:
                    print(f"Warning: __VIEWSTATEGENERATOR ({generator}) does not match the tested paths!")
                pass
            else:
                self.verified_potential_apppaths.add(self.verified_apppath)
                if self.is_debug:
                    print("Verified path: ", self.verified_path)
                    print("Verified apppath: ", self.verified_apppath)
                self.calculate_generator = False
        elif self.calculate_generator:
            if self.is_debug:
                print("Calculating possible generator values using a small set...")
            self.default_pages = self.default_pages_small_set
            self.generators = self.calculate_potential_viewstate_generators()

    def calculate_potential_viewstate_generators(self):
        str_path, iis_apps_in_path = self.extract_all_from_url(self.url)
        
        temp_str_paths = []
        if not ".aspx" in str_path.lower() and self.findviewstatepage:
            # We need to add .aspx to the end of the path if we have a page and not a folder
            if not str_path.endswith("/"):
                temp_str_paths.append(str_path + ".aspx")
            # We need to add the default .aspx pages to the end of the path
            for default_page in self.default_pages:
                if str_path.endswith("/"):
                    temp_str_paths.append(str_path + default_page)
                else:
                    temp_str_paths.append(str_path + "/" + default_page)
        else:
            temp_str_paths.append(str_path)
        
        generators = []
        for str_path in temp_str_paths:
            for app_path in iis_apps_in_path:
                generators.append(self.calculate_generator_value(str_path, app_path))

        return generators

    def simulate_template_source_directory(self, str_path):
        #str_path = str_path.rsplit("/", 1)[0] or "/"
        path_parts = str_path.split("/")
        str_path = "/".join(path_parts[:-1]) if "." in path_parts[-1] else str_path
        str_path = self.remove_slash_from_path_if_needed(str_path)
        return str_path if str_path else "/"

    def remove_cookieless_if_needed(self, path):
        # Regular expression to match cookieless values in the URL
        cookieless_pattern = re.compile(r'/\([A-Z]\([A-Za-z0-9_]+\)\)/')
        # Remove all occurrences of the cookieless pattern
        cleaned_url = re.sub(cookieless_pattern, '/', path)
        return cleaned_url

    def clean_aspx_path(self, path):
        # Find the position of '.aspx' in the path
        aspx_pos = path.lower().find('.aspx')
        # If '.aspx' is found and there is a '/' after it, truncate the path
        if aspx_pos != -1:
            slash_pos = path.find('/', aspx_pos)
            if slash_pos != -1:
                path = path[:aspx_pos + 5]  # Include '.aspx' in the result
        return path

    def normalize_path_in_url(self, url):
        parsed_url = urlparse(url)
        path = parsed_url.path.replace('\\', '/')
        path = re.sub(r'/+', '/', path)
        return parsed_url._replace(path=path).geturl()

    def remove_slash_from_path_if_needed(self, path):
        return path[:-1] if path and path.endswith("/") else path

    def simulate_get_type_name(self, str_path, iis_app_in_path, add_default_pages=True):
        iis_app_in_path = (
            "/" + iis_app_in_path.lower() if not iis_app_in_path.lower().startswith("/") else iis_app_in_path.lower()
        )
        if add_default_pages:
            str_path = str_path + "/default.aspx" if not str_path.lower().endswith(".aspx") else str_path

        iis_app_in_path = iis_app_in_path + "/" if not iis_app_in_path.endswith("/") else iis_app_in_path
        str_path = str_path.lower().split(iis_app_in_path, 1)[1] if iis_app_in_path in str_path.lower() else str_path
        str_path = str_path[1:] if str_path.startswith("/") else str_path
        str_path = str_path.replace(".", "_").replace("/", "_")
        str_path = self.remove_slash_from_path_if_needed(str_path)
        return str_path

    def extract_from_url(self, url):
        parsed_url = urlparse(url)
        str_path = parsed_url.path
        str_path = str_path if str_path.startswith("/") else "/" + str_path
        iis_app_in_path = str_path.rsplit("/", 1)[0] or "/"
        return str_path, iis_app_in_path
    
    def get_specific_purposes(self):
        str_path, iis_app_in_path = self.extract_from_url(self.url)
        template_source = self.simulate_template_source_directory(str_path)
        gettype = self.simulate_get_type_name(str_path, iis_app_in_path, True)
        specificPurposes = []
        specificPurposes.append(f"TemplateSourceDirectory: {template_source.upper()}")
        specificPurposes.append(f"Type: {gettype.upper()}")
        return specificPurposes
    
    def get_directories(self, path):
        # Remove any trailing slash
        path = path.rstrip('/')
        # Split the path into parts, ignoring the first empty string from the leading '/'
        parts = path.split('/')[1:]
        
        # Check if the last part is likely a file (contains a dot)
        if '.' in parts[-1]:
            parts = parts[:-1]
        
        # Build up each directory level
        directories = []
        current_path = ""
        for part in parts:
            current_path += "/" + part
            directories.append(current_path)
        return directories
    
    def any_directory_in_url(self , url):
        str_path, iis_apps_in_path = self.extract_all_from_url(url)
        return len(iis_apps_in_path) > 1
    
    def any_directory_in_url(self):
        str_path, iis_apps_in_path = self.extract_all_from_url(self.url)
        return len(iis_apps_in_path) > 1
    
    def extract_all_from_path(self, path):
        str_path = path
        str_path = str_path if str_path.startswith("/") else "/" + str_path

        iis_apps_in_path = ["/"]
        if str_path != "/":
            if "." in str_path.rsplit("/", 1)[-1]:
                path = str_path.rsplit("/", 1)[0].strip("/").split("/")
                if path != "":
                    iis_apps_in_path.extend(self.get_directories(str_path))
            else:
                path = str_path.rsplit("/", 1)[0].strip("/").split("/")
                if path != "":
                    iis_apps_in_path.extend(self.get_directories(str_path))

        str_path = re.sub(r'/+', '/', str_path)
        iis_apps_in_path = [re.sub(r'/+', '/', path) for path in iis_apps_in_path]

        # Ensure iis_apps_in_path contains unique values
        iis_apps_in_path = list(set(iis_apps_in_path))

        return str_path, iis_apps_in_path
    
    def extract_all_from_url(self, url):
        parsed_url = urlparse(url)
        str_path = parsed_url.path
        return self.extract_all_from_path(str_path)
    
    def simulate_get_all_type_name(self, str_path, iis_apps_in_path):
        type_names = []

        # adding more default pages increase the testing time signaficantly so we need to limit ourselves
        if not self.findviewstatepage:
            self.default_pages = ["default.aspx"]
        
        temp_str_paths = []
        if str_path:
            temp_str_paths.append(str_path)
            if not ".aspx" in str_path.lower():
                # We need to add .aspx to the end of the path if we have a page and not a folder
                if not str_path.endswith("/"):
                    temp_str_paths.append(str_path + ".aspx")
                # We need to add the default .aspx pages to the end of the path
                for default_page in self.default_pages:
                    if str_path.endswith("/"):
                        temp_str_paths.append(str_path + default_page)
                    else:
                        temp_str_paths.append(str_path + "/" + default_page)
        else:
            # we don't have str_path so we need to add the default .aspx pages to the path
            for default_page in self.default_pages:
                temp_str_paths.append("/" + default_page)

        for app_path in iis_apps_in_path:
            app_path = "/" + app_path.lower() if not app_path.lower().startswith("/") else app_path.lower()
            app_path = app_path + "/" if not app_path.endswith("/") else app_path
            for temp_str_path in temp_str_paths:
                temp_str_path = temp_str_path.lower().split(app_path, 1)[1] if app_path in temp_str_path.lower() else temp_str_path
                temp_str_path = temp_str_path[1:] if temp_str_path.startswith("/") else temp_str_path
                temp_str_path = self.normalize_path_in_url(temp_str_path)
                temp_str_path = temp_str_path.replace(".", "_").replace("/", "_")
                temp_str_path = self.remove_slash_from_path_if_needed(temp_str_path)
                type_names.append(temp_str_path)
        
        # We return unique values    
        return list(set(type_names))
    
    def get_all_specific_purposes(self):
        if not self.verified_path or not self.verified_apppath:
            str_path, potential_apps_in_path = self.extract_all_from_url(self.url)
            if len(self.verified_potential_apppaths) > 0:
                potential_apps_in_path = list(self.verified_potential_apppaths)
        else:
            str_path = self.verified_path
            potential_apps_in_path = [self.verified_apppath]
        
        template_source = self.simulate_template_source_directory(str_path)
        gettypes = self.simulate_get_all_type_name(str_path, potential_apps_in_path)
        all_specific_purposes = []
        
        for gettype in gettypes:
            specificPurposes = []
            specificPurposes.append(f"TemplateSourceDirectory: {template_source.upper()}")
            specificPurposes.append(f"Type: {gettype.upper()}")
            all_specific_purposes.append(specificPurposes)
        
        return all_specific_purposes
    
    def canonical(self, ch):
        """
        For alphabetic characters, prioritize the lowercase form.
        If ch.lower() exists in the mapping, return that.
        Otherwise, if ch.upper() exists, return that.
        For non-alphabetic characters, return as-is.
        """
        if ch.isalpha():
            low = ch.lower()
            if low in self.db:
                return low
            up = ch.upper()
            if up in self.db:
                return up
            raise ValueError(f"Alphabetic character {repr(ch)} not found in mapping (tried {repr(low)} and {repr(up)})")
        return ch
    
    def get_sort_key(self, s):
        # --- Step 0. Validate and normalize ---
        for ch in s:
            # Reject control characters (code points 0x00-0x1F or 0x7F)
            if (0 <= ord(ch) < 32) or (ord(ch) == 127):
                raise ValueError(f"Control character {repr(ch)} (code {ord(ch)}) not supported.")
        # Convert alphabetic characters to lowercase (if available)
        proc = "".join(self.canonical(ch) for ch in s)
        
        main_result = []
        
        # --- Step 1. First pass: process each character ---
        for i, ch in enumerate(proc):
            if ch not in self.db:
                raise ValueError(f"Character {repr(ch)} not found in mapping.")
            mapping = self.db[ch]
            # Always add the first two bytes.
            main_result.extend(mapping[0:2])
            # For non-last characters, add bytes until (but not including) the first 1.
            # For the last character, add bytes until (and including) the first 1.
            if i < len(proc) - 1:
                for byte in mapping[2:]:
                    if byte == 1:
                        break
                    main_result.append(byte)
            else:
                for byte in mapping[2:]:
                    main_result.append(byte)
                    if byte == 1:
                        break
        # Only append an extra 1 if the header does not already end with 1.
        if not main_result or main_result[-1] != 1:
            main_result.append(1)
        
        # --- Step 2. Second pass: build the temporary array ---
        temp = []
        for ch in proc:
            mapping = self.db[ch]
            # Skip the first two bytes; iterate over the rest.
            for idx, byte in enumerate(mapping[2:]):
                if byte == 1:
                    rem = mapping[2:]
                    if idx + 1 < len(rem):
                        next_byte = rem[idx + 1]
                        if next_byte == 1:
                            temp.append(2)
                        else:
                            temp.append(next_byte)
                    break  # Only consider the first occurrence of 1.
        
        # --- Step 3. Process the temp array ---
        # Remove all 2's that occur after the last number greater than 2.
        last_gt_index = None
        for i, val in enumerate(temp):
            if val > 2:
                last_gt_index = i
        if last_gt_index is not None:
            filtered_temp = temp[:last_gt_index+1] + [val for val in temp[last_gt_index+1:] if val != 2]
        else:
            # If no value > 2 exists, discard the temp array.
            filtered_temp = []
        
        # --- Step 4. Build final result ---
        if filtered_temp:
            main_result.extend(filtered_temp)
        # Append termination sequence.
        main_result.extend([1,1,1,0])
        
        return main_result

    def legacy_hash_sort_key(self, sort_key: bytes) -> int:
        """
        Compute the legacy (non-randomized) hash from a sort key.
        
        The algorithm:
        1. Initialize two accumulators to 0x1505 (5381 decimal).
        2. Process the sort key bytes in pairs:
            acc1 = (acc1 * 33) XOR first_byte,
            if a second byte is present and nonzero:
                acc2 = (acc2 * 33) XOR second_byte.
        3. Combine as: hash = (acc2 * 0x5d588b65) + acc1 (modulo 2^32).
        """
        initial_value = 0x1505  # 5381 in decimal
        acc1 = initial_value
        acc2 = initial_value
        i = 0
        n = len(sort_key)
        
        while i < n and sort_key[i] != 0:
            acc1 = (acc1 * 33) ^ sort_key[i]
            
            if i + 1 >= n or sort_key[i + 1] == 0:
                break
            
            acc2 = (acc2 * 33) ^ sort_key[i + 1]
            i += 2
            
        hash_val = (acc2 * 0x5d588b65) + acc1
        return hash_val & 0xFFFFFFFF  # ensure 32-bit result

    def simulate_GetNonRandomizedStringComparerHashCode(self, str):
        sk = self.get_sort_key(str)
        #print("Sort key stsd: ", sk)
        h = self.legacy_hash_sort_key(sk)
        return h

    def get_apppaths_hashcodes(self):
        if(self.verified_apppath):
            return [self.simulate_GetNonRandomizedStringComparerHashCode(self.verified_apppath)]
        elif(len(self.verified_potential_apppaths) > 0):
            hashcodes = []
            for app_path in self.verified_potential_apppaths:
                hashcodes.append(self.simulate_GetNonRandomizedStringComparerHashCode(app_path))
            return hashcodes
        else:
            str_path, potential_apps_in_path = self.extract_all_from_url(self.url)
            hashcodes = []
            for app_path in potential_apps_in_path:
                hashcodes.append(self.simulate_GetNonRandomizedStringComparerHashCode(app_path))
            return hashcodes


    # This creates the __VIEWSTATEGENERATOR value
    def calculate_generator_value(self, path, apppath):
        stsd = self.simulate_template_source_directory(path)
        sgtn = self.simulate_get_type_name(path, apppath, False)
        #print("stsd: ", stsd)
        #print("sgtn: ", sgtn)
        h1 = self.simulate_GetNonRandomizedStringComparerHashCode(stsd)
        h2 = self.simulate_GetNonRandomizedStringComparerHashCode(sgtn)
        h = (h1 + h2) & 0xFFFFFFFF # To fix the modulus of 2^32 to simulate uint in .NET
        #print("Calculated pageHashCode in uint: ", h1)
        result = format(h, '08x').upper()
        #print("Calculated Generator in Hex: ", result)
        return result

    def find_valid_path_params_by_generator(self, generator):
        str_path, potential_apps_in_path = self.extract_all_from_url(self.url)
        temp_str_paths = []
        if not ".aspx" in str_path.lower():
            # We need to add .aspx to the end of the path if we have a page and not a folder
            if not str_path.endswith("/"):
                temp_str_paths.append(str_path)
                temp_str_paths.append(str_path + ".aspx")
            else:
                temp_str_paths.append(str_path.rstrip('/'))
        else:
            temp_str_paths.append(str_path)
       
        # We need to consider all cases if one of the subdirs is actually a page!
        for apppath in potential_apps_in_path:
            if apppath != "/":
                temp_str_paths.append(apppath)
                temp_str_paths.append(apppath + ".aspx")
        
        # Ensure temp_str_paths contains unique values
        temp_str_paths = list(set(temp_str_paths))
        # Ensure potential_apps_in_path contains unique values
        potential_apps_in_path = list(set(potential_apps_in_path))
        
        # Track unique combinations of path and apppath
        seen_combinations = set()
        
        for str_path in temp_str_paths:
            for apppath in potential_apps_in_path:
                combination = (str_path, apppath)
                if combination in seen_combinations:
                    continue
                seen_combinations.add(combination)
                
                if generator.upper() == self.calculate_generator_value(str_path, apppath):
                    return str_path, apppath

        # We need to add the default .aspx pages to the end of the path
        for apppath in potential_apps_in_path:
            for common_dirs in self.common_directories:
                for default_page in self.default_pages_large_set:
                    default_path = f"/{apppath}/{common_dirs}/{default_page}"
                    default_path, temp_app_paths = self.extract_all_from_path(default_path)
                    for temp_apppath in temp_app_paths:
                        combination = (default_path, temp_apppath)
                        if combination in seen_combinations:
                            continue
                        seen_combinations.add(combination)
                        
                        if generator.upper() == self.calculate_generator_value(default_path, temp_apppath):
                            return default_path, temp_apppath

        combined_common_pages = self.common_pages + self.default_pages_large_set
        # Now considering a transfer to error pages
        for common_dirs in self.common_directories:
            for common_page in combined_common_pages:
                common_path = f"/{common_dirs}/{common_page}"
                common_path, temp_app_paths = self.extract_all_from_path(common_path)
                for apppath in temp_app_paths:
                    combination = (common_path, apppath)
                    if combination in seen_combinations:
                        continue
                    seen_combinations.add(combination)
                    
                    if generator.upper() == self.calculate_generator_value(common_path, apppath):
                        return common_path, apppath
        
        return None, None
    
    # based on https://soroush.me/blog/2019/07/iis-application-vs-folder-detection-during-blackbox-testing/
    def find_all_apppaths_actively(self, client):
        """Find all IIS application paths by making requests to common ASP.NET endpoints"""

        if not client:
            return None
        
        parsed_url = urlparse(self.url)
        urlbase = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Get all possible paths from the URL
        str_path, unverified_apppaths = self.extract_all_from_url(self.url)

        # Common ASP.NET endpoints that can reveal if a path is an application
        test_suffixes = [
            "/profile_json_appservice.axd/js"
        ]

        verified_apppaths = set()
        try:
            # Test each potential path with each suffix
            for path in unverified_apppaths:
                if not path.startswith("/"):
                    path = "/" + path
                
                if path == "/":
                    # Root path is always an application
                    verified_apppaths.add(path)
                    continue

                for suffix in test_suffixes:
                    test_url = urlbase + re.sub(r'/+', '/', path + suffix)
                    try:
                        res = client.get(test_url, follow_redirects=False, timeout=30)
                        
                        # Various indicators that this is an application path
                        if any([
                            # Profile service returns Type.registerNamespace
                            (suffix == "/profile_json_appservice.axd/js" and res.status_code == 200
                             and "Type.registerNamespace" in res.text)
                        ]):
                            verified_apppaths.add(path)
                            if self.is_debug:
                                print(f"Found application path: {path} using {suffix}")
                            break   
                    except (httpx.RequestError, httpx.TimeoutException) as e:
                        if self.is_debug:
                            print(f"Error testing {test_url}: {str(e)}")
                        continue
            if verified_apppaths:
                return list(verified_apppaths)
                
        except Exception as e:
            if self.is_debug:
                print(f"Error in find_all_apppaths: {str(e)}")
            pass
            
        return None
    