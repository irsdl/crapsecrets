import struct
from datetime import datetime, timedelta

# --- Global state (to hold type and string references) ---
global_type_list = []
global_string_list = []

def initialize_deserializer():
    global global_type_list, global_string_list
    global_type_list = []
    global_string_list = []

# --- Exception for viewstate parsing errors ---
class ViewStateException(Exception):
    pass

# --- Helper functions ---

def read_7bit_encoded_int(b):
    """Reads a 7-bit encoded integer and returns (value, remaining_bytes)."""
    n = 0
    shift = 0
    i = 0
    while True:
        if i >= len(b):
            raise ViewStateException("Unexpected end of data while reading 7-bit encoded int")
        tmp = b[i]
        i += 1
        n |= (tmp & 0x7F) << shift
        if not (tmp & 0x80):
            break
        shift += 7
    return n, b[i:]

def read_int16(b):
    if len(b) < 2:
        raise ViewStateException("Not enough bytes for int16")
    val = int.from_bytes(b[:2], byteorder='little', signed=True)
    return val, b[2:]

def read_int32(b):
    if len(b) < 4:
        raise ViewStateException("Not enough bytes for int32")
    val = int.from_bytes(b[:4], byteorder='little', signed=False)
    return val, b[4:]

def read_int64(b):
    if len(b) < 8:
        raise ViewStateException("Not enough bytes for int64")
    val = int.from_bytes(b[:8], byteorder='little', signed=False)
    return val, b[8:]

def read_double(b):
    if len(b) < 8:
        raise ViewStateException("Not enough bytes for double")
    val = struct.unpack('<d', b[:8])[0]
    return val, b[8:]

def read_float(b):
    if len(b) < 4:
        raise ViewStateException("Not enough bytes for float")
    val = struct.unpack('<f', b[:4])[0]
    return val, b[4:]

def parse_dotnet_datetime(ticks):
    # This function is invalid, but we don't need its actual value in this context.
    """Converts .NET ticks (100-nanosecond intervals since 0001-01-01) to a datetime."""
    return datetime(1, 1, 1) # + timedelta(microseconds=ticks // 10)

# --- Parser infrastructure using a metaclass ---

class ParserMeta(type):
    def __init__(cls, name, bases, namespace):
        super(ParserMeta, cls).__init__(name, bases, namespace)
        if not hasattr(cls, "registry"):
            cls.registry = {}
        if hasattr(cls, "marker"):
            marker = getattr(cls, "marker")
            if type(marker) not in (tuple, list):
                marker = [marker]
            for m in marker:
                cls.registry[m] = cls

class Parser(metaclass=ParserMeta):
    @staticmethod
    def parse(b):
        if not b:
            raise ViewStateException("No data to parse")
        marker = b[0]
        try:
            parser_cls = Parser.registry[marker]
        except KeyError:
            raise ViewStateException("Unknown marker 0x{:02x}".format(marker))
        return parser_cls.parse(b)

# --- Parsers for constant values ---

class Noop(Parser):
    marker = 0x01 # Int16?
    @staticmethod
    def parse(b):
        # Consume marker 0x01; returns None.
        return None, b #read_int16(b[1:])

class Const(Parser):
    @classmethod
    def parse(cls, b):
        return cls.const, b[1:]

class NoneConst(Const):
    marker = 0x64
    const = None

class EmptyConst(Const):
    marker =0x65
    const = ""

class ZeroConst(Const):
    marker = 0x66
    const = 0

class TrueConst(Const):
    marker = 0x67
    const = True

class FalseConst(Const):
    marker = 0x68
    const = False

# --- Parsers for basic numeric and character types ---

class Integer(Parser):
    marker = (0x02, 0x2B)
    @staticmethod
    def parse(b):
        # Consume marker 0x02
        if b[0] != 0x02 and b[0] != 0x2B:
            raise ViewStateException("Invalid marker for Integer")
        b = b[1:]
        n = 0
        shift = 0
        i = 0
        while True:
            if i >= len(b):
                raise ViewStateException("Unexpected end of data while parsing integer")
            tmp = b[i]
            i += 1
            n |= (tmp & 0x7F) << shift
            if not (tmp & 0x80):
                break
            shift += 7
        return n, b[i:]

class ByteValue(Parser):
    marker = 0x03
    @staticmethod
    def parse(b):
        if b[0] != 0x03:
            raise ViewStateException("Invalid marker for Byte")
        return b[1], b[2:]

class CharValue(Parser):
    marker = 0x04
    @staticmethod
    def parse(b):
        if b[0] != 0x04:
            raise ViewStateException("Invalid marker for Char")
        return chr(b[1]), b[2:]

class StringValue(Parser):
    marker = (0x05, 0x2A, 0x29)
    @staticmethod
    def parse(b, parsed=False):
        if not parsed:
            if b[0] != 0x05 and b[0] != 0x2A and b[0] != 0x29:
                raise ViewStateException("Invalid marker for String")
            b = b[1:]
        n, b = read_7bit_encoded_int(b)
        if n < 0:
            raise ViewStateException("Invalid string length")
        if n == 0:
            return "", b
        if len(b) < n:
            raise ViewStateException("Not enough bytes for string")
        s = b[:n].decode('utf-8', errors='replace')
        return s, b[n:]

# --- Parsers for more complex types ---

class DateTimeValue(Parser):
    marker = 0x06
    @staticmethod
    def parse(b):
        if b[0] != 0x06:
            raise ViewStateException("Invalid marker for DateTime")
        b = b[1:]
        ticks, b = read_int64(b)
        dt = parse_dotnet_datetime(ticks)
        return dt, b

class DoubleValue(Parser):
    marker = 0x07
    @staticmethod
    def parse(b):
        if b[0] != 0x07:
            raise ViewStateException("Invalid marker for Double")
        b = b[1:]
        val, b = read_double(b)
        return val, b

class FloatValue(Parser):
    marker = 0x08
    @staticmethod
    def parse(b):
        if b[0] != 0x08:
            raise ViewStateException("Invalid marker for Float")
        b = b[1:]
        val, b = read_float(b)
        return val, b

class RGBA(Parser):
    marker = 0x09
    @staticmethod
    def parse(b):
        if b[0] != 0x09:
            raise ViewStateException("Invalid marker for RGBA")
        b = b[1:]
        val, b = read_int32(b)
        a = (val >> 24) & 0xFF
        r = (val >> 16) & 0xFF
        g = (val >> 8) & 0xFF
        blue = val & 0xFF
        return "RGBA({}, {}, {}, {})".format(r, g, blue, a), b

class KnownColor(Parser):
    marker = 0x0A
    @staticmethod
    def parse(b):
        if b[0] != 0x0A:
            raise ViewStateException("Invalid marker for KnownColor")
        b = b[1:]
        color_index, b = read_7bit_encoded_int(b)
        try:
            color = COLORS[color_index % len(COLORS)] # A hack - of course this is not the colour!!!
        except KeyError:
            color = "Unknown"
        return "KnownColor: {}".format(color), b

# Define a simple COLORS mapping (extend as needed)
COLORS = {
    0: "Black",
    1: "White",
    2: "Red",
    3: "Green",
    4: "Blue",
}

class EnumValue(Parser):
    marker = 0x0B
    @staticmethod
    def parse(b):
        if b[0] != 0x0B:
            raise ViewStateException("Invalid marker for Enum")
        b = b[1:]
        type_ref, b = TypeValue.parse(b, True)
        enum_val, b = read_7bit_encoded_int(b)
        return "Enum({}, {})".format(type_ref, enum_val), b

class ColorEmpty(Parser):
    marker = 0x0C
    @staticmethod
    def parse(b):
        if b[0] != 0x0C:
            raise ViewStateException("Invalid marker for Color.Empty")
        return "Color.Empty", b[1:]

class PairValue(Parser):
    marker = 0x0F
    @staticmethod
    def parse(b):
        if b[0] != 0x0F:
            raise ViewStateException("Invalid marker for Pair")
        b = b[1:]
        first, b = Parser.parse(b)
        second, b = Parser.parse(b)
        return (first, second), b

class TripletValue(Parser):
    marker = 0x10
    @staticmethod
    def parse(b):
        if b[0] != 0x10:
            raise ViewStateException("Invalid marker for Triplet")
        b = b[1:]
        first, b = Parser.parse(b)
        second, b = Parser.parse(b)
        third, b = Parser.parse(b)
        return (first, second, third), b

class TypedArray(Parser):
    marker = 0x14
    @staticmethod
    def parse(b):
        if b[0] != 0x14:
            raise ViewStateException("Invalid marker for TypedArray")
        b = b[1:]
        type_ref, b = Parser.parse(b)
        length, b = read_7bit_encoded_int(b)
        arr = []
        for _ in range(length):
            val, b = Parser.parse(b)
            arr.append(val)
        return arr, b

class StringArray(Parser):
    marker = 0x15
    @staticmethod
    def parse(b):
        if b[0] != 0x15:
            raise ViewStateException("Invalid marker for StringArray")
        b = b[1:]
        n, b = read_7bit_encoded_int(b)
        arr = []
        for _ in range(n):
            s, b = StringValue.parse(b, True)
            arr.append(s)
        return arr, b

class ListValue(Parser):
    marker = 0x16
    @staticmethod
    def parse(b):
        if b[0] != 0x16:
            raise ViewStateException("Invalid marker for List")
        b = b[1:]
        n, b = read_7bit_encoded_int(b)
        lst = []
        for _ in range(n):
            val, b = Parser.parse(b)
            lst.append(val)
        return lst, b

class DictValue(Parser):
    marker = (0x17, 0x18)
    @staticmethod
    def parse(b):
        # Both HybridDictionary (0x17) and Hashtable (0x18) are handled the same.
        marker = b[0]
        b = b[1:]
        n, b = read_7bit_encoded_int(b)
        d = {}
        for _ in range(n):
            key, b = Parser.parse(b)
            value, b = Parser.parse(b)
            d[key] = value
        return d, b

class TypeValue(Parser):
    marker = 0x19
    @staticmethod
    def parse(b, parsed=False):
        if not parsed:
            if b[0] != 0x19:
                raise ViewStateException("Invalid marker for Type")
            b = b[1:]
        if b[0] == 0x2B:
            b = b[1:]
            idx, b = read_7bit_encoded_int(b)
            try:
                # we are not interested to have the real value for badsecrets
                type_ref = idx
                #type_ref = global_type_list[idx]
            except IndexError:
                raise ViewStateException("Invalid type reference index")
            return type_ref, b
        else:
            # 0x29 == Token_TypeRefAdd
            # 0x2A == Token_TypeRefAddLocal
            b = b[1:]
            type_name, b = StringValue.parse(b, True)
            global_type_list.append(type_name)
            return type_name, b

class UnitValue(Parser):
    marker = 0x1B
    @staticmethod
    def parse(b):
        if b[0] != 0x1B:
            raise ViewStateException("Invalid marker for Unit")
        b = b[1:]
        dbl, b = read_double(b)
        int_val, b = read_int32(b)
        return "Unit({}, {})".format(dbl, int_val), b

class UnitEmpty(Parser):
    marker = 0x1C
    @staticmethod
    def parse(b):
        if b[0] != 0x1C:
            raise ViewStateException("Invalid marker for Unit.Empty")
        return "Unit(0, 0)", b[1:]

class EventValidationStore(Parser):
    marker = 0x1D
    @staticmethod
    def parse(b):
        if b[0] != 0x1D:
            raise ViewStateException("Invalid marker for EventValidationStore")
        b = b[1:]
        version = b[0]
        if version != 0:
            raise ViewStateException("Invalid version for EventValidationStore")
        b = b[1:]
        num_entries = read_7bit_encoded_int(b)
        b = b[1:]
        lst = []
        for _ in range(num_entries):
            entry = b[:16]
            b = b[16:]
            lst.append(entry)
        return lst, b

class IndexedString(Parser):
    marker = (0x1E, 0x1F)
    @staticmethod
    def parse(b):
        token = b[0]
        b = b[1:]
        if token == 0x1F:
            if not b:
                raise ViewStateException("No data for IndexedString reference")
            idx = b[0]
            b = b[1:]
            try:
                # we are not interested to have the real value for badsecrets
                s = idx
                # s = global_string_list[idx]
            except IndexError:
                raise ViewStateException("Invalid string reference index")
            return s, b
        else:  # token == 0x1E
            s, b = StringValue.parse(b,True)
            global_string_list.append(s)
            return s, b

class FormattedString(Parser):
    marker = 0x28
    @staticmethod
    def parse(b):
        if b[0] != 0x28:
            raise ViewStateException("Invalid marker for FormattedString")
        b = b[1:]
        type_ref, b = Parser.parse(b)
        s, b = StringValue.parse(b, True)
        if type_ref is not None:
            return "SerialisedObject({})".format(s), b
        else:
            return None, b

class BinaryFormatted(Parser):
    marker = 0x32
    @staticmethod
    def parse(b):
        if b[0] != 0x32:
            raise ViewStateException("Invalid marker for BinaryFormatted")
        b = b[1:]
        n, b = read_7bit_encoded_int(b)
        if n > len(b):
            raise ViewStateException("Not enough data for binary formatted object")
        val = b[:n]
        return "BinaryFormatted({})".format(val), b[n:]

class SparseArray(Parser):
    marker = 0x3C
    @staticmethod
    def parse(b):
        if b[0] != 0x3C:
            raise ViewStateException("Invalid marker for SparseArray")
        b = b[1:]
        type_ref, b = Parser.parse(b)
        length, b = read_7bit_encoded_int(b)
        num_non_null, b = read_7bit_encoded_int(b)
        arr = [None] * length
        for _ in range(num_non_null):
            idx, b = read_7bit_encoded_int(b)
            if idx < 0 or idx >= length:
                raise ViewStateException("Invalid index in sparse array")
            val, b = Parser.parse(b)
            arr[idx] = val
        return arr, b

# --- Top-level viewstate parser ---

def parse_viewstate(b):
    """
    Parses the given viewstate byte array.
    The stream must start with 0xff, 0x01.
    After parsing the main value, trailing bytes indicate if MAC is enabled.
    """
    if len(b) < 2 or b[0] != 0xff or b[1] != 0x01:
        raise ViewStateException("Not a valid ASP.NET 2.0 LOS stream")
    # Initialize global state for type and string references.
    initialize_deserializer()
    # Skip header bytes
    b = b[2:]
    value, remain = Parser.parse(b)
    if len(remain) == 0:
        macEnabled = False
    elif len(remain) in (20, 32):
        macEnabled = True
    else:
        raise ViewStateException("Invalid trailing bytes length: {}".format(len(remain)))
    return {"value": value, "macEnabled": macEnabled, "raw": b}

# --- Example usage ---
if __name__ == "__main__":
    # For testing, we create a dummy viewstate payload:
    # header (0xff, 0x01) followed by an EmptyConst token (0x65)

    sample = bytes([0xff, 0x01, 0x65])
    try:
        result = parse_viewstate(sample)
        print("Parsed viewstate:", result)
    except ViewStateException as e:
        print("Error parsing viewstate:", e)
