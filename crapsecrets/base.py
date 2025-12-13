import re
import os
import gzip
import base64
import hashlib
import binascii
import httpx
import crapsecrets.errors
from abc import abstractmethod
import zlib, bz2, lzma
from enum import Enum, auto
import traceback

generic_base64_regex = re.compile(
    r"^(?:[A-Za-z0-9+\/]{4}){8,}(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
)

class Section(Enum):
    BODY = auto()
    COOKIES = auto()
    HEADERS = auto()

class CrapsecretsBase:
    supported_sections = frozenset({Section.BODY, Section.COOKIES, Section.HEADERS})
    identify_regex = re.compile(r".+")
    description = {"product": "Undefined", "secret": "Undefined", "severity": "Undefined"}

    hash_sizes = {"SHA1": 20, "MD5": 16, "SHA256": 32, "SHA384": 48, "SHA512": 64}
    hash_algs = {
        "SHA1": hashlib.sha1,
        "MD5": hashlib.md5,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "AES": hashlib.sha1,
        "3DES": hashlib.sha1,
    }

    x = None # This is a placeholder for the current product being checked
    
    check_secret_args = 1

    product_group_number_in_carve = 0

    def __init__(self, custom_resource=None, **kwargs):
        self.custom_resource = custom_resource

        if self.custom_resource:
            if not os.path.exists(self.custom_resource):
                raise crapsecrets.errors.LoadResourceException(
                    f"Custom resource [{self.custom_resource}] does not exist"
                )

    @abstractmethod
    def check_secret(self, secret):
        raise NotImplementedError

    @staticmethod
    def attempt_decompress(value):
        try:
            raw = base64.b64decode(value)
        except binascii.Error:
            return False

        # Mapping of magic headers to their decompression functions.
        # Note: The zlib header can vary, so here we check only for the common first byte.
        decompressors = [
            (b'\x1f\x8b', gzip.decompress),        # gzip: header starts with 0x1f 0x8b
            (b'\x78', zlib.decompress),             # zlib: header usually starts with 0x78
            (b'BZh', bz2.decompress),               # bz2: header starts with 'BZh'
            (b'\xfd7zXZ\x00', lzma.decompress),      # lzma/xz: header starts with 0xfd 37 7a 58 5a 00
            (b'\x5d\x10\x00', lambda data: lzma.decompress(data, format=lzma.FORMAT_ALONE)) # lzma FORMAT_ALONE: usually starts with "XQAA" in Base64
        ]

        # First, check if the raw data has a recognized header.
        for header, decompress_fn in decompressors:
            if raw.startswith(header):
                try:
                    return decompress_fn(raw)
                except Exception:
                    continue

        # Fallback: try each decompressor until one works.
        for decompress_fn in (gzip.decompress, zlib.decompress, bz2.decompress, lzma.decompress):
            try:
                return decompress_fn(raw)
            except Exception:
                continue

        return False

    @classmethod
    def get_description(self):
        return self.description

    def get_product_from_carve(self, regex_search):
        global x
        target = 0
        if x.product_group_number_in_carve and isinstance(x.product_group_number_in_carve, list):
            for target in x.product_group_number_in_carve:
                if(len(regex_search.groups()) < target + 1):
                    target = 0
                    break
                elif regex_search.groups()[target]:
                    break
        elif x.product_group_number_in_carve:
            target = x.product_group_number_in_carve
        product = regex_search.groups()[target]
        if product == None:
            product = "Unknown"
        return product

    def get_hashcat_commands(self, s):
        return None

    def load_resources(self, resource_list, is_custom=False):
        filepaths = []
        if self.custom_resource:
            filepaths.append(self.custom_resource)
        if is_custom:
            for r in resource_list:
                filepaths.append(r)
        else:
            for r in resource_list:
                filepaths.append(f"{os.path.dirname(os.path.abspath(__file__))}/resources/{r}")
        for filepath in filepaths:
            with open(filepath, encoding="utf-8") as r:
                for l in r.readlines():
                    if len(l) > 0:
                        yield l

    def carve_to_check_secret(self, s, **kwargs):
        global x
        target = 0
        if x.product_group_number_in_carve:
            target = x.product_group_number_in_carve
        if s.groups():
            r = self.check_secret(s.groups()[target])
            return r

    @abstractmethod
    def carve_regex(self):
        return None

    def carve(self, body=None, cookies=None, headers=None, requests_response=None, **kwargs):
        global x
        results = []
        if not body and not cookies and not headers and requests_response == None:
            raise crapsecrets.errors.CarveException("Either body/headers/cookies or requests_response required")

        if requests_response != None:
            if body or cookies or headers:
                raise crapsecrets.errors.CarveException("Body/cookies/headers and requests_response cannot both be set")

            # Update type check for httpx Response
            if isinstance(requests_response, httpx.Response):
                body = requests_response.text
                # Properly convert cookies using items() method and handle potential errors
                try:
                    cookies = dict(requests_response.cookies.items()) if hasattr(requests_response.cookies, 'items') else {}
                except Exception as e:
                    cookies = {}
                # headers in httpx are case-insensitive Headers object, convert to dict
                try:
                    headers = dict(requests_response.headers.items()) if hasattr(requests_response.headers, 'items') else dict(requests_response.headers)
                except Exception as e:
                    headers = {}
            else:
                raise crapsecrets.errors.CarveException("requests_response must be a httpx.Response object")
        
        if cookies and Section.COOKIES in self.supported_sections:
            if type(cookies) != dict:
                raise crapsecrets.errors.CarveException("Header argument must be type dict")
            for k, v in cookies.items():
                r = self.check_secret(v)
                if r:
                    r["type"] = "SecretFound"
                    r["product"] = v
                    r["location"] = "cookies"
                    results.append(r)
        
        if headers and Section.HEADERS in self.supported_sections:
            for header_value in headers.values():
                # Check if we have a match outright
                r = self.check_secret(header_value)
                if r:
                    r["type"] = "SecretFound"
                    r["product"] = header_value
                    r["location"] = "headers"
                    results.append(r)
                # If we dont, we will only be able to add context if we have a match with carve_regex()
                elif self.carve_regex():
                    s = re.search(self.carve_regex(), header_value)
                    if s:
                        r = self.carve_to_check_secret(s)
                        if r:
                            r["type"] = "SecretFound"
                        # the carve regex hit but no secret was found
                        else:
                            r = {"type": "IdentifyOnly"}
                            target = 0
                            if x.product_group_number_in_carve:
                                target = x.product_group_number_in_carve
                            r["hashcat"] = self.get_hashcat_commands(s.groups()[target])
                        if "product" not in r.keys():
                            r["product"] = self.get_product_from_carve(s)
                        r["location"] = "headers"
                        results.append(r)
    
        if body and Section.BODY in self.supported_sections:
            if type(body) != str:
                raise crapsecrets.errors.CarveException("Body argument must be type str")
            if self.carve_regex():
                s = re.search(self.carve_regex(), body)
                if s:
                    res = self.carve_to_check_secret(s, url=kwargs.get("url", None), requests_response=requests_response, isFromBody=True, client=kwargs.get("client", None), commandargs=kwargs.get("commandargs", None))
                    if isinstance(res, dict):
                        res = [res]
                    if res:
                        for r in res:
                            if r:
                                r["type"] = "SecretFound"
                            else:
                                r = {"type": "IdentifyOnly"}
                                r["hashcat"] = self.get_hashcat_commands(self.get_product_from_carve(s))
                            if "product" not in r.keys():
                                temp_product = self.get_product_from_carve(s)
                                if len(temp_product) > 200:
                                    r["product"] = temp_product[:100] + "..." + temp_product[-10:]
                                else:
                                    r["product"] = temp_product
                            r["location"] = "body"
                            if kwargs.get("url"):
                                r["location"] += " - URL: " + kwargs.get("url")
                            results.append(r)
    
        for r in results:
            r["description"] = self.get_description()
    
        # Don't report an IdentifyOnly result if we have a SecretFound result for the same 'product'
        secret_found_results = set(d["product"] for d in results if d["type"] == "SecretFound")
        return [d for d in results if not (d["type"] == "IdentifyOnly" and d["product"] in secret_found_results)]

    @classmethod
    def identify(self, product):
        if re.match(self.identify_regex, product):
            return True
        return False

    @staticmethod
    def search_dict(d, query):
        items = [key for key, value in d.items() if query == value]
        if items:
            return items


def hashcat_all_modules(product, detecting_module=None, *args):
    global x
    hashcat_candidates = []
    for m in CrapsecretsBase.__subclasses__():
        if detecting_module == m.__name__ or detecting_module == None:
            x = m()
            if x.identify(product):
                hashcat_commands = x.get_hashcat_commands(product)
                if hashcat_commands:
                    for hcc in hashcat_commands:
                        z = {
                            "detecting_module": m.__name__,
                            "hashcat_command": hcc["command"],
                            "hashcat_description": hcc["description"],
                        }
                        hashcat_candidates.append(z)
    return hashcat_candidates


def check_all_modules(*args, **kwargs):
    global x
    for m in CrapsecretsBase.__subclasses__():
        x = m(custom_resource=kwargs.get("custom_resource", None))
        r = x.check_secret(*args[0 : x.check_secret_args])
        if r:
            r["detecting_module"] = m.__name__
            r["description"] = x.get_description()

            # allow the module to provide an amended product, if needed
            if "product" not in r.keys():
                r["product"] = args[0]
            r["location"] = "manual"
            return r
    return None


def carve_all_modules(**kwargs):
    global x
    results = []
    for m in CrapsecretsBase.__subclasses__():
        try:
            x = m(custom_resource=kwargs.get("custom_resource", None))
            r_list = x.carve(**kwargs)
            if len(r_list) > 0:
                for r in r_list:
                    r["detecting_module"] = m.__name__
                    results.append(r)
        except Exception as e:
            print(f"An error occurred in module {m.__name__}: {e}")
            traceback.print_exc()
    if results:
        return results