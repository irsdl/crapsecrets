import json
import re
import hmac
import struct
import base64
import hashlib
import binascii
import traceback
import httpx
from Crypto.Cipher import AES, DES, DES3
from libs.viewstate.viewstate import ViewState
from contextlib import suppress
from urllib.parse import urlsplit, urljoin
from crapsecrets.helpers import Viewstate_Helpers, unpad, sp800_108_derivekey, sp800_108_get_key_derivation_parameters, Purpose, matchLooseBase64RegEx, isolate_app_process
from crapsecrets.base import CrapsecretsBase, Section, generic_base64_regex
import concurrent.futures
from threading import Event
from enum import Enum

class DotNetMode(Enum):
    DOTNET45 = "DOTNET45"
    DOTNET40_LEGACY = "DOTNET40 (legacy)"

class ASPNET_Viewstate(CrapsecretsBase):
    is_debug = False
    supported_sections = frozenset({Section.BODY})
    check_secret_args = 3
    product_group_number_in_carve = [9,13,15] # This is probably wrong to use a RegEx in this - we will have some unknown products!
    identify_regex = generic_base64_regex
    description = {"product": "ASP.NET Viewstate", "secret": "ASP.NET MachineKey", "severity": "CRITICAL"}
    requests_response = None
    client = None
    all_viewstate_keys = False
    find_viewstate_page = False
    find_decryption_key_without_validation_key = False
    find_app_path_proactively = True
    test_IsolateApps = True
    continue_without_valid_path = False
    is_from_body = False
    thread_number = 1
    machinekeyfile = ["./crapsecrets/resources/aspnet_machinekeys.txt"]
    validation_keys = []
    decryption_keys = []

    def carve_regex(self):
        # Using RegEx is bad here as the viewstate can be split into multiple fields
        # We also need processing based on the final value
        return re.compile(
            r'(<form[^>]+action=["\']([^"\']+)["\'][^>]*>[\S\s]+?)?'
            r'((' # This is a special case where the viewstate is split into multiple fields
            r'<input[^>]+(__VIEWSTATEFIELDCOUNT[\"\']\svalue=[\"\'][^\"\']+[\"\'])[\S\s]+?'
            r'((<input[^>]+__VIEWSTATE[\"\'\d]+\svalue=[\"\'][^\"\']+[\"\'][\S\s]+?)+)'
            r'<input[^>]+__VIEWSTATEGENERATOR[\"\']\svalue=[\"\']([^\"\']+)[\"\']'
            r')|(' # This is the normal aspx Page class with __VIEWSTATE and __VIEWSTATEGENERATOR
            r'<input[^>]+__VIEWSTATE[\"\']\svalue=[\"\']([^\"\']+)[\"\'][\S\s]+?'
            r'<input[^>]+__VIEWSTATEGENERATOR[\"\']\svalue=[\"\']([^\"\']+)[\"\']'
            r')|(' # This is an aspx without __VIEWSTATEGENERATOR - we still can't handle this when not encrypted as hashcode hasn't been implemented
            # I haven't added __VSTATE here just because we have another module for it and I am not sure how its encryption work!
            r'<input[^>]+(__VIEWSTATE|__VSTATE)[\"\']\svalue=[\"\']([^\"\']*)[\"\'][\S\s]+?'
            r')|(' # This is an aspx with an empty __VIEWSTATE and a non-empty __EVENTVALIDATION
            r'<input[^>]+(__EVENTVALIDATION)[\"\']\svalue=[\"\']([^\"\']+)[\"\'][\S\s]+?'
            r'))'
        , re.DOTALL | re.IGNORECASE)

    def carve_to_check_secret(self, s, url=None, requests_response=None, isFromBody=False, client=None, commandargs=None):
        self.is_debug = False
        if commandargs:
            if commandargs.debug:
                self.is_debug = True

        self.requests_response = requests_response
        self.is_from_body = isFromBody
        self.cookies = None
        self.body = None

        if requests_response:
            self.cookies = requests_response.cookies
            self.body = requests_response.text

        self.client = client

        self.commandargs = commandargs

        self.all_viewstate_keys = False
        if commandargs:
            if commandargs.allviewstatekeys:
                self.all_viewstate_keys = True
        
        self.find_viewstate_page = False
        if commandargs:
            if commandargs.findviewstatepage:
                self.find_viewstate_page = True

        self.machinekeyfile = ["./crapsecrets/resources/aspnet_machinekeys.txt"]
        if commandargs:
            if commandargs.machinekeyfile:
                self.machinekeyfile = self.commandargs.machinekeyfile

        self.find_decryption_key_without_validation_key = False
        if commandargs:
            if commandargs.enable_viewstate_decryption:
                self.find_decryption_key_without_validation_key = True

        self.thread_number = 1
        if commandargs:
            if commandargs.num_threads and commandargs.num_threads > 0:
                self.thread_number = commandargs.num_threads

        self.find_app_path_proactively = True
        if commandargs:
            if commandargs.disable_active_path_check:
                self.find_app_path_proactively = False

        if len(s.groups()) >= 3:
            r = self.check_secret(s.groups()[2], s.groups(), url)
            return r

    def resolve_args(self, args):
        actionPage = ""
        generatorHex = "00000000"
        url = None
        viewstate_B64 = ""

        if len(args) == 2 and len(args[0]) >= 3:
            url = args[1]
            actionPage = args[0][1]
            
            if "__VIEWSTATEFIELDCOUNT" not in args[0][2].upper():
                viewstate_B64 = args[0][9]
                generatorHex = args[0][10]
                if generatorHex == None:
                    # MobilePage class doesn't have __VIEWSTATEGENERATOR
                    # Those pages messing with the viewstate don't have it either sometimes... bad developers!
                    # Maybe when dinasaur roamed the earth, they didn't have it either!
                    # Anyway, we can't check it in python yet because I am a lame reverser to see what hashcode does! Not just because I am lazy!
                    viewstate_B64 = args[0][13]
                    generatorHex = "00000000"
            else:
                # This is a special case where the viewstate is split into multiple fields
                generatorHex = args[0][7]
                fieldCount_pattern = re.compile(r'__VIEWSTATEFIELDCOUNT["\']\s*value=["\'](\d+)["\']', re.IGNORECASE)
                fieldCount = int(fieldCount_pattern.search(args[0][4]).groups()[0])
                for i in range(fieldCount):
                    if(i==0):
                        viewstate_pattern = re.compile(r'__VIEWSTATE["\']\s*value=["\']([^"\']+)["\']', re.IGNORECASE)
                        viewstate_B64 += viewstate_pattern.search(args[0][5]).groups()[0]
                    else:
                        viewstate_pattern = re.compile(r'__VIEWSTATE'+str(i)+r'["\']\s*value=["\']([^"\']+)["\']', re.IGNORECASE)
                        viewstate_B64 += viewstate_pattern.search(args[0][5]).groups()[0]
        else:
            # This is to pass the tests from badsecrets!
            url_pattern = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
            generator_pattern = re.compile(r"^[A-F0-9]{8}$")
            for arg in args:
                if arg:
                    if generator_pattern.match(arg):
                        generatorHex = arg
                    elif url_pattern.match(arg):
                        url = arg
        
        # If __VIEWSTATEGENERATOR or __VIEWSTATE has not been found, we will try to dig deeper as combined RegEx is not really ideal
        # An example is https://www.skype.com/en/404.aspx where the values are in different forms with wrong order!
        # We also want to find __EVENTVALIDATION without use of a predefined badsecrets RegEx
        eventvalidation_base64 = ""
        if self.requests_response and self.is_from_body:
            body = self.requests_response.text
            if not viewstate_B64 or viewstate_B64.strip() == "":
                viewstate_pattern = re.compile(r'<input[^>]+(VIEWSTATE)[\"\']\svalue=[\"\']([^\"\']+)[\"\'][\S\s]+?', re.IGNORECASE)
                viewstate_match = viewstate_pattern.search(body)
                if viewstate_match:
                    viewstate_B64 = viewstate_match.group(2)
            
            if not generatorHex or generatorHex.strip() == "" or generatorHex == "00000000":
                generator_pattern = re.compile(r'<input[^>]+(VIEWSTATEGENERATOR)[\"\']\svalue=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)             
                generator_match = generator_pattern.search(body)
                if generator_match:
                    generatorHex = generator_match.group(2)
            
            if not eventvalidation_base64 or eventvalidation_base64.strip() == "":
                eventvalidation_pattern = re.compile(r'<input[^>]+(EVENTVALIDATION)[\"\']\svalue=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)
                eventvalidation_match = eventvalidation_pattern.search(body)
                if eventvalidation_match:
                    eventvalidation_base64 = eventvalidation_match.group(2)

        return actionPage, viewstate_B64, eventvalidation_base64, generatorHex, url

    def check_secret(self, viewstate_B64_init, *args):
        actionPage, viewstate_B64, eventvalidation_base64, generatorHex, origUrl = self.resolve_args(args)
        
        # This happens during tests!
        if not viewstate_B64 and viewstate_B64_init and matchLooseBase64RegEx(viewstate_B64_init):
            viewstate_B64 = viewstate_B64_init
        
        # If we don't have viewstate but we have eventvalidation, we will use it instead
        if not viewstate_B64 and eventvalidation_base64 and matchLooseBase64RegEx(eventvalidation_base64):
            signed_maybe_encrypted_B64 = eventvalidation_base64
            main_purpose = Purpose.WebForms_ClientScriptManager_EventValidation.value
        else:
            signed_maybe_encrypted_B64 = viewstate_B64
            main_purpose = Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value

        # This is useful if we have followed the redirection
        finalUrl = ""
        if hasattr(self, 'requests_response') and self.requests_response is not None:
                finalUrl = str(self.requests_response.url)
        
        if finalUrl == "" and origUrl != None and origUrl != "":
            finalUrl = origUrl
        elif finalUrl == "":
            # This is a test!
            finalUrl = "http://example.local/"
            origUrl = "http://example.local/"
         
        # Fixing the url if it uses Response.Transfer to load another page!
        if actionPage and actionPage != "":
            finalUrl = urljoin(finalUrl, actionPage)
        
        # Remove query string from the URL, if any
        url = urlsplit(finalUrl)._replace(query="").geturl()

        results = None
        macEnableCheckOnly = False
        if not self.identify(signed_maybe_encrypted_B64):
            if '"__VIEWSTATE" value=""' in signed_maybe_encrypted_B64:
                # we have a case where the viewstate is empty
                # we can still check actively to see if MAC is enabled
                print("Empty viewstate found! Find another page with viewstate or send requests with viewstate signed with different keys!")
                macEnableCheckOnly = True
            else:
                return None

        temp_product = signed_maybe_encrypted_B64
        if len(temp_product) > 200:
            temp_product = temp_product[:100] + "..." + temp_product[-10:]
        else:
            temp_product = temp_product

        # This is to increase performance by parsing the viewstate early and only once
        # This saves time when viewstate is large and we have to check multiple keys
        signature_by_parser = None
        if not macEnableCheckOnly:
            if self.valid_preamble(base64.b64decode(signed_maybe_encrypted_B64)):
                # Very low chance that a string is encrypted and has a valid preamble
                encrypted = False
                try:
                    vs = ViewState(signed_maybe_encrypted_B64)
                    vs.decode()
                    signature_by_parser = vs.signature

                    # Early detection of MAC enabled viewstate
                    if signature_by_parser == None or signature_by_parser == b"":
                        validationAlgo = "MAC_DISABLED"
                        return {
                            "secret": "No secret, use LosFormatter from YSoSerial.Net",
                            "product": f"{temp_product}",
                            "details": f"{validationAlgo}\nURL: [{url}]"
                        }
                except Exception as e:
                    if self.is_debug:
                        print(f"Error in parsing viewstate or a similar object: {e}")
                        traceback.print_exc()

                    print("Error parsing the ViewState. It is likely encrypted.")
                    encrypted = True
            else:
                encrypted = True

            # we don't need to do this in a loop to increase performance
            viewstate_helpers = Viewstate_Helpers(url, generatorHex, findviewstatepage=self.find_viewstate_page, calculate_generator=True, is_debug=self.is_debug)
            
            # Shall we send some requests to the server to find the application paths?
            if self.find_app_path_proactively and not viewstate_helpers.verified_apppath and viewstate_helpers.any_directory_in_url():
                # We now have permission to send requests to the target URL to see whether we can find all paths which are application paths
                # This is to reduce the number of keys to check as they are based on apppath
                potential_apppaths = viewstate_helpers.find_all_apppaths_actively(self.client)
                if potential_apppaths and len(potential_apppaths) > 0:
                    viewstate_helpers.verified_potential_apppaths = potential_apppaths
            
            all_specific_purposes = viewstate_helpers.get_all_specific_purposes()

            generatorsHexList = []
            if generatorHex == "00000000":
                # __VIEWSTATEGENERATOR is missing in the response
                # We need to calculate it ourselves to check the keys
                # This can occur in a MobilePage class as an example
                generatorsHexList = viewstate_helpers.generators
            else:
                generatorsHexList.append(generatorHex)

            # ViewStateUserKey will be ignored when it is NULL but empty string is valid
            all_viewstate_userkeys = [None, "", "mono"]
            public_ip = self.get_public_ip()
            if hasattr(self, 'cookies') and self.cookies:
                for cookie in self.cookies:
                    if cookie.lower() in ["asp.net_sessionid", "__antixsrftoken","__antixsrfusername"]:
                        all_viewstate_userkeys.append(self.cookies[cookie])
                        if public_ip:
                            all_viewstate_userkeys.append(f"{self.cookies[cookie]}_{public_ip}")
                            all_viewstate_userkeys.append(f"{public_ip}_{self.cookies[cookie]}")
                    elif re.match(r'^[a-z0-5]{24}$', self.cookies[cookie]):
                        all_viewstate_userkeys.append(self.cookies[cookie])
            
            if hasattr(self, 'body') and self.body:
                viewstate_key_pattern = re.compile(r'__VIEWSTATE_KEY["\']\s*value=["\']([^"\']+)["\']', re.IGNORECASE)
                viewstate_key_match = viewstate_key_pattern.search(self.body)
                if viewstate_key_match:
                    all_viewstate_userkeys.append(viewstate_key_match.group(1))
            
            apppaths_hashcodes = [None]
            if self.test_IsolateApps:
                # This is to test the IsolateApps feature
                apppaths_hashcodes = [None] + viewstate_helpers.get_apppaths_hashcodes()
                pass
            
            # Little performance tweak to check the modes in a specific order
            if encrypted:
                modes = [DotNetMode.DOTNET45, DotNetMode.DOTNET40_LEGACY]
            else:
                # DOTNET45 is always encrypted
                modes = [DotNetMode.DOTNET40_LEGACY]
            
            if (all_specific_purposes == None):
                # We cannot do DOTNET45 without all_specific_purposes
                modes = [DotNetMode.DOTNET40_LEGACY]
            
            if generatorHex != "00000000" and not viewstate_helpers.verified_apppath:    
                if not self.continue_without_valid_path:
                    # __VIEWSTATEGENERATOR does not match the path and apppath. Continuing is likely pointless with DOTNET45 as we have not managed to guess the right values either.
                    modes = [DotNetMode.DOTNET40_LEGACY]
            
            # Override for testing purposes
            # modes = [ViewStateMode.DOTNET45, ViewStateMode.DOTNET40_LEGACY]
            
            if self.is_debug:
                print(f"Modes to be tested based on the situation: {modes}")
            
            results = self.process_keys(encrypted, signed_maybe_encrypted_B64, generatorsHexList, url, modes, all_viewstate_userkeys, main_purpose, all_specific_purposes, signature_by_parser, apppaths_hashcodes)
            if results and isinstance(results, list) and len(results) > 0:
                return results
        
        if (macEnableCheckOnly or encrypted) and self.client != None:
            try:
                # validationAlgo is None, but the viewstate is encrypted
                # We need to check if MAC is not enabled as there is still a chance
                # See https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
                
                # Sending a request to the target URL with a dummy __VIEWSTATE and the correct __VIEWSTATEGENERATOR
                # will return a 500 error if MAC is enabled, and a 200 if it is not.

                # This is to ensure we have the right URL even after a redirect
                url_with_query = finalUrl + ("&" if "?" in finalUrl else "?") + "__VIEWSTATE=/wEPDwUKMDAwMDAwMDAwMGRk&__VIEWSTATEGENERATOR=" + generatorHex
                res = self.client.get(url_with_query, follow_redirects=False, timeout=30)
                
                # Viewstate is invalid ("k" has been replaced with "A" at the end of the viewstate)
                dummy_url_with_query = finalUrl + ("&" if "?" in finalUrl else "?") + "__VIEWSTATE=/wEPDwUKMDAwMDAwMDAwMGRA&__VIEWSTATEGENERATOR=" + generatorHex
                dummy_res = self.client.get(dummy_url_with_query, follow_redirects=False, timeout=30)

                # Get the content length of the responses
                res_content_length = len(res.content)
                dummy_res_content_length = len(dummy_res.content)

                # Calculate the difference in content length
                content_length_diff = abs(res_content_length - dummy_res_content_length)

                # Check if the difference is more than 10 characters and more than 90%
                if res.status_code != dummy_res.status_code or (content_length_diff > 10 and content_length_diff / res_content_length > 0.9):
                    self.description["severity"] = "CRITICAL"
                    return {"secret": "MAC_DISABLED", "product": f"Viewstate: /wEPDwUKMDAwMDAwMDAwMGRk", "details": f"MAC is disabled, use LosFormatter from YSoSerial.Net\nURL: [{finalUrl}]"}
            except (httpx.RequestError, httpx.TimeoutException) as e:
                print(f"Error connecting to dummy URLs for viewstate - {str(e)}")
                pass
        
        # If we are here then we don't have good results! We might have a partial results though!
        if results != None:
            self.description["severity"] = "INFO"
            temp_product = signed_maybe_encrypted_B64
            if len(temp_product) > 200:
                temp_product = temp_product[:100] + "..." + temp_product[-10:]
            else:
                temp_product = temp_product
            #return "Crapsecrets was unable to crack __VIEWSTATE!"
            #return {"type":"IdentifyOnly", "secret": "Crapsecrets was unable to crack __VIEWSTATE!", "product": f"Viewstate: {temp_product}", "details": f"URL: [{finalUrl}]"}
            return [None]
        
        return None
    
    # Get the public IP address
    def get_public_ip(self):
        try:
            response = self.client.get('https://api.ipify.org?format=json')
            response.raise_for_status()
            ip_data = response.json()
            return ip_data['ip']
        except Exception as e:
            print(f"Error fetching public IP: {e}")
            return None
        
    # Returns list of results
    def process_keys(self, encrypted, signed_maybe_encrypted_B64, generatorHexList, url, modes, all_viewstate_userkeys=[None], main_purpose=Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value, all_specific_purposes=None, signature_by_parser=None, apppaths_hashcodes=[None]):
        
        results = []      

        # Get lines from the file(s) using your load_resources function
        lines = self.load_resources(self.machinekeyfile, True)

        # Use a set to store unique lines after stripping and filtering
        unique_lines = set()
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#"):
                continue
            unique_lines.add(stripped_line)

        if(len(self.validation_keys) == 0 or len(self.decryption_keys) == 0):
            # Initialize lists for validation and decryption keys
            validation_keys = []
            decryption_keys = []

            # Process each unique line
            for line in unique_lines:
                try:
                    # Split only at the first comma in case keys contain commas
                    validation, decryption = line.split(",", 1)
                    validation_keys.append(validation.strip())
                    decryption_keys.append(decryption.strip())
                except ValueError:
                    #print(f"Skipping malformed line: {line}")
                    pass
            
            
            if self.all_viewstate_keys:
                # Combine both lists and remove duplicate keys
                validation_keys = list(set(validation_keys + decryption_keys))
                # Make sure it does not contain empty or white space strings
                validation_keys = [key for key in validation_keys if key.strip()]
                decryption_keys = validation_keys
                
            self.validation_keys = validation_keys
            self.decryption_keys = decryption_keys
        else:
            validation_keys = self.validation_keys
            decryption_keys = self.decryption_keys  

        if len(validation_keys) == 0:
            print("No keys found in the resource file(s) for the ViewState module! Checks will be incomplete.")
        else:
            print(f"Found {len(validation_keys)} keys in the resource file(s) for the ViewState module.")
        
        validation_algo = None
        specific_purpose = None
        viewstate_userkey = None
        generator = "00000000"
        
        # Event to signal when a valid key is found to stop other threads
        validation_stop_event = Event()

        # Split candidates into chunks to reduce thread contention
        def chunks(lst, n):
            for i in range(0, len(lst), n):
                yield lst[i:i + n]
                    
        chunk_size = max(10, len(validation_keys) // self.thread_number)
        chunked_validation_keys = list(chunks(validation_keys, chunk_size))

        def check_validation_key_chunk(chunk):
            # Each chunk gets its own local tested set
            local_tested = set()
            local_results = []
            
            # Check stop event first
            if validation_stop_event.is_set():
                return None
                    
            for vkey in chunk:
                try:
                    # Skip keys which have been tested before to increase performance
                    if vkey in local_tested:
                        continue
                    local_tested.add(vkey)

                    if vkey.lower() == "autogenerate":
                        continue

                    # Each thread gets its own local variables
                    local_validation_algo = None
                    local_specific_purpose = None 
                    local_viewstate_userkey = None

                    original_key = vkey
                    for apppath_hashcode in apppaths_hashcodes:
                        for mode in modes:
                            if validation_stop_event.is_set():
                                return None
  
                            if apppath_hashcode and mode == DotNetMode.DOTNET40_LEGACY:
                                vkey = isolate_app_process(vkey, apppath_hashcode)
                                if not vkey:
                                    continue
                            elif apppath_hashcode and mode == DotNetMode.DOTNET45:
                                # IsolateApps won't work with DOTNET45
                                continue
                            
                            for generatorHex in generatorHexList:
                                generator = struct.pack("<I", int(generatorHex, 16))
                                local_validation_algo, local_specific_purpose, local_viewstate_userkey, process_validationkey_result = self.process_validationkey(
                                    vkey, mode, encrypted, signed_maybe_encrypted_B64, generator, all_viewstate_userkeys, main_purpose, all_specific_purposes, signature_by_parser,original_key
                                )
                                
                                if local_validation_algo:
                                    # Return tuple with all relevant data
                                    local_results.append((original_key, mode, local_validation_algo, local_specific_purpose, 
                                                    local_viewstate_userkey, process_validationkey_result, generatorHex))
                                    
                                    # Early exit if not in guess mode
                                    if local_validation_algo != "guess":
                                        return local_results                          
                except Exception as e:
                    if self.is_debug:
                        print(f"Error processing key {vkey}: {str(e)}")
                    continue
            return local_results if local_results else None

        # Process completed futures
        confirmed_validation_algo = None
        confirmed_specific_purpose = None
        confirmed_viewstate_userkey = None
        confirmed_generatorHex = None
        interim_result = ""
        interim_result_additional_info = ""
        selected_decryption_keys = decryption_keys
        # Use ThreadPoolExecutor to process chunks in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_number) as executor:
            # Submit all chunk checking tasks
            futures = [executor.submit(check_validation_key_chunk, chunk) 
                      for chunk in chunked_validation_keys]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    chunk_results = future.result()
                    if chunk_results:
                        for vkey, mode, validation_algo, specific_purpose, viewstate_userkey, process_validationkey_result, generatorHex in chunk_results:
                            # Set stop event to halt other threads if we have a successful validation
                            if validation_algo:
                                validation_stop_event.set()
                                confirmed_validation_algo = validation_algo
                                confirmed_specific_purpose = specific_purpose
                                confirmed_viewstate_userkey = viewstate_userkey
                                confirmed_generatorHex = generatorHex
                                # narrow down the modes to the one that has been confirmed
                                modes = [mode]
                                interim_result = process_validationkey_result
                                interim_result_additional_info = f" Mode: {mode} URL: [{url}]"
                            
                                if not self.all_viewstate_keys:
                                    # Narrow down the keys to the one that has been confirmed
                                    selected_decryption_keys = [
                                        decryption_keys[j] for j in range(len(validation_keys))
                                        if validation_keys[j] == vkey
                                    ]
                            
                                if not encrypted or mode == DotNetMode.DOTNET40_LEGACY:
                                    results.append({
                                        "secret": interim_result,
                                        "details": f"Mode: {mode}\nURL: [{url}]"
                                    })

                                # We have found the decryption key
                                # Otherwise, this might be a potential as several keys in different modes can create the same preamble
                                break
                        if validation_stop_event.is_set():
                            break
                except Exception as e:
                    if self.is_debug:
                        print(f"Error processing validation chunk: {str(e)}")
                        traceback.print_exc()
                    continue
        
        if confirmed_validation_algo == None and encrypted and self.find_decryption_key_without_validation_key:
            # We are here because we couldn't find the validation key
            # However, we can still try to find the decryption key as find_decryption_key_without_validation_key is set
            confirmed_validation_algo = "guess"
        
        # Process decryption if needed
        if encrypted and (self.find_decryption_key_without_validation_key or (confirmed_validation_algo and confirmed_validation_algo != "")):
            if confirmed_viewstate_userkey:
                all_viewstate_userkeys = [confirmed_viewstate_userkey]
            if confirmed_specific_purpose:
                all_specific_purposes = [confirmed_specific_purpose]

            # Split decryption keys into chunks
            chunk_size = max(10, len(selected_decryption_keys) // self.thread_number)
            chunked_decryption_keys = list(chunks(selected_decryption_keys, chunk_size))
            decryption_stop_event = Event()

            def check_decryption_key_chunk(chunk):
                # Each chunk gets its own local tested set
                local_tested = set()
                local_results = []
                # Check stop event first
                if decryption_stop_event.is_set():
                    return None

                for dkey in chunk:
                    # Skip keys which have been tested before
                    if dkey in local_tested:
                        continue
                    local_tested.add(dkey)
                    
                    if dkey.lower() == "autogenerate":
                        continue
                    
                    original_key = dkey
                    for apppath_hashcode in apppaths_hashcodes:
                        for mode in modes:
                            if decryption_stop_event.is_set():
                                return None
                        
                            try:
                                if apppath_hashcode and mode == DotNetMode.DOTNET40_LEGACY:
                                    dkey = isolate_app_process(dkey, apppath_hashcode)
                                    if not dkey:
                                        continue
                                elif apppath_hashcode and mode == DotNetMode.DOTNET45:
                                    # IsolateApps won't work with DOTNET45
                                    continue
                                
                                result = self.process_decryption_keys(
                                    confirmed_validation_algo, dkey, mode, encrypted, signed_maybe_encrypted_B64,
                                    all_viewstate_userkeys, main_purpose, all_specific_purposes, original_key
                                )
                                
                                if result:
                                    local_results.append((mode, result))
                                    
                                    # Early exit if not in guess mode
                                    if not (self.all_viewstate_keys or validation_algo == "guess"):
                                        return local_results
                            except Exception as e:
                                if self.is_debug:
                                    print(f"Error processing decryption key {dkey}: {str(e)}")
                                continue

                return local_results if local_results else None

            # Process decryption keys in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_number) as executor:
                # Submit all chunk checking tasks 
                futures = [executor.submit(check_decryption_key_chunk, chunk)
                          for chunk in chunked_decryption_keys]
                
                # Process completed futures
                for future in concurrent.futures.as_completed(futures):
                    try:
                        chunk_results = future.result()
                        if chunk_results:
                            for mode, result in chunk_results:
                                if len(results) == 1:
                                    # Read the validation key from interim result
                                    interim_validation_key = re.search(r'ValidationKey: \[([A-F0-9]+)\]', interim_result)
                                    # If it was already in the results, remove results[0]
                                    if interim_validation_key and interim_validation_key.group(1) in result[0]:
                                        results.pop(0)
                                    
                                results.append({
                                    "secret": interim_result + result,
                                    "details": f"Mode: {mode}\nURL: [{url}]"
                                })
                                
                                if not (self.all_viewstate_keys or validation_algo == "guess"):
                                    decryption_stop_event.set()
                                    break
                            
                            if decryption_stop_event.is_set():
                                break
                                
                    except Exception as e:
                        if self.is_debug:
                            print(f"Error processing decryption chunk: {str(e)}")
                            traceback.print_exc()
                        continue

        temp_product = signed_maybe_encrypted_B64
        if len(temp_product) > 200:
            temp_product = temp_product[:100] + "..." + temp_product[-10:]
        else:
            temp_product = temp_product

        if main_purpose == Purpose.WebForms_ClientScriptManager_EventValidation.value:
            product_string = f"EventValidation: {temp_product}"
        else:
            product_string = f"Viewstate: {temp_product}"
        
        if confirmed_generatorHex:
            product_string += f" Generator: {confirmed_generatorHex.upper()}"
        elif generator != "00000000":
            product_string += f" Generator: {generator[::-1].hex().upper()}"

        unique_results = []
        is_critical = False
        if interim_result and not results:
            results = [{"secret": interim_result + " EncryptionKey: UNKNOWN (unexploitable)", "details": interim_result_additional_info}]

        if results:
            seen = set()
            for result in results:
                result["product"] = product_string
                result_tuple = tuple(result.items())
                if result_tuple not in seen:
                    if "validationkey" in result["secret"].lower() and not "unexploitable" in result["secret"].lower():
                        is_critical = True
                    if "potential" in result["secret"].lower():
                        result["details"] += "\nNote: This result includes a potential decryption key. For confirmation, please rerun the tool and verify if the same result is consistently produced."
                    seen.add(result_tuple)
                    unique_results.append(result)
        
        if is_critical:
            self.description["severity"] = "CRITICAL"
        else:
            self.description["severity"] = "INFO"
        return unique_results #unique_results

    
    # Returns validation_algo, specific_purpose, viewstate_userkey, result in string
    def process_validationkey(self, vkey, mode, encrypted, viewstate_B64, generator, all_viewstate_userkeys=[None], main_purpose=Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value, all_specific_purposes=None, signature_by_parser=None,original_key=None):
        specific_purpose = None
        validation_algo = None
        viewstate_userkey = None
        result = ""
        if not original_key:
            original_key = vkey
        
        try:
            validation_algo, specific_purpose, viewstate_userkey = self.viewstate_validate_check(
                binascii.unhexlify(vkey), encrypted, viewstate_B64, generator, mode, all_viewstate_userkeys, main_purpose, all_specific_purposes, signature_by_parser
            )
        except binascii.Error as e:
            # This is to see invalid keys in the file
            #print("Invalid key in the resource file: " + vkey)
            pass
            
        if not validation_algo:
            return None, None, None, None
        
        if validation_algo != "guess":
            if validation_algo == "MAC_DISABLED":
                return "MAC_DISABLED", None, None, "MAC is disabled, use LosFormatter from YSoSerial.Net"            
            
            # Build the result string
            algo_display = ( "SHA1 or 3DES or AES" 
                            if validation_algo == "SHA1" and mode == DotNetMode.DOTNET40_LEGACY and encrypted 
                            else validation_algo )

            if original_key != vkey:
                result = f"ValidationKey: [{original_key},IsolateApps] ValidationAlgo: [{algo_display}]"
            else:
                result = f"ValidationKey: [{original_key}] ValidationAlgo: [{algo_display}]"

            if isinstance(specific_purpose, list) and len(specific_purpose) >= 2:
                path, apppath = self.get_paths_from_specific_purpose(
                    specific_purpose[0].split(' ')[1], specific_purpose[1].split(' ')[1]
                )
                result += f" Path: [{path}] AppPath: [{apppath}]"
                # We have confirmed specific_purpose (just need to add the ViewStateUserKey to it if it exists)

            if viewstate_userkey:
                # We have confirmed ViewStateUserKey
                result += f" ViewStateUserKey: [{viewstate_userkey}]"
                
        return validation_algo, specific_purpose, viewstate_userkey, result
    
    def process_decryption_keys(self, validation_algo, dkey, mode, encrypted, viewstate_B64, all_viewstate_userkeys=[None], main_purpose=Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value, all_specific_purposes=None, original_key=None):
        # Simplified to handle single key check
        result = ""
        if not original_key:
            original_key = dkey

        if encrypted:
            try:
                candidate_bytes = binascii.unhexlify(dkey)
                decryption_algo = self.viewstate_decrypt_check(
                    candidate_bytes, validation_algo, viewstate_B64, mode, all_viewstate_userkeys, main_purpose, all_specific_purposes
                )
                if decryption_algo:
                    if self.all_viewstate_keys or validation_algo == "guess":
                        if original_key != dkey:
                            result = f" (Potential EncryptionKey: [{original_key},IsolateApps] with DecryptionAlgo: [{decryption_algo}])"
                        else:
                            result = f" (Potential DecryptionKey: [{original_key}] DecryptionAlgo: [{decryption_algo}])"
                    else:
                        if original_key != dkey:
                            result = f" EncryptionKey: [{original_key},IsolateApps] with DecryptionAlgo: [{decryption_algo}]"
                        else:
                            result = f" EncryptionKey: [{original_key}] EncryptionAlgo: [{decryption_algo}]"
            except binascii.Error:
                pass

        if result != "":
            return result
        return None

    @staticmethod
    def valid_preamble(sourcebytes):
        if sourcebytes[0:2] == b"\xff\x01":
            return True
        return False

    # Return hash algorithm, specific purpose, and ViewStateUserKey if successful
    # In case MAC validation is not enabled, it will return "MAC is not enabled!"
    def viewstate_validate_check(self, vkey_bytes, encrypted, viewstate_B64, generator, mode, all_viewstate_userkeys=[None], main_specific_purpose=Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value, all_specific_purposes=None, signature_by_parser=None):
        shortest_encrypted = 8
        is_valid = True

        if viewstate_B64 == None or len(viewstate_B64) < shortest_encrypted:
            is_valid = False
        
        if all_specific_purposes == None and mode == DotNetMode.DOTNET45:
            is_valid = False
        
        if encrypted and mode == DotNetMode.DOTNET40_LEGACY:
            # ASP.NET ignores "modifier" if it is encrypted in the legacy mode!
            # So Viewstatekey is ineffective to prevent anti-xsrf attacks in DOTNET40 when encrypted!!
            all_viewstate_userkeys = [None]

        if is_valid:
            original_vkey_bytes = vkey_bytes
            viewstate_bytes = base64.b64decode(viewstate_B64)

            if encrypted:
                candidate_hash_algs = list(self.hash_sizes.keys())
            else:               
                # We are doing this again just in case this function is called directly
                if signature_by_parser == None or signature_by_parser == b"":
                    return "MAC_DISABLED", None, None
                
                signature_len = len(signature_by_parser)
                candidate_hash_algs = self.search_dict(self.hash_sizes, signature_len)
            
            for hash_alg in candidate_hash_algs:
                for viewstate_userkey in all_viewstate_userkeys:
                    vkey_bytes = original_vkey_bytes
                    viewstate_data = viewstate_bytes[: -self.hash_sizes[hash_alg]]
                    vs_data_bytes = viewstate_data
                    if not encrypted and generator:
                        vs_data_bytes += generator
                    signature = viewstate_bytes[-self.hash_sizes[hash_alg] :]
                    if mode == DotNetMode.DOTNET45:
                        for specific_purpose in all_specific_purposes:
                            tempSpecific_purpose = specific_purpose.copy()
                            if viewstate_userkey is not None:
                                # Adding potential ViewStateUserKey
                                tempSpecific_purpose.append(f"ViewStateUserKey: {viewstate_userkey}")
                            
                            label, context = sp800_108_get_key_derivation_parameters(
                                main_specific_purpose, tempSpecific_purpose
                            )
                            derived_vkey_bytes = sp800_108_derivekey(vkey_bytes, label, context, (len(vkey_bytes) * 8))
                            h = hmac.new(
                                derived_vkey_bytes,
                                vs_data_bytes,
                                self.hash_algs[hash_alg],
                            ).digest()
                            # This is dirty to have this check here but we are in a loop for the paths (all_specific_purposes) so we need to speed up!
                            if h == signature:
                                return hash_alg, specific_purpose, viewstate_userkey
                    elif hash_alg == "MD5" and mode == DotNetMode.DOTNET40_LEGACY:
                        # The HashDataUsingNonKeyedAlgorithm function in ASP.NET has a bug overwriting the modifier if shorter than validation key! 
                        # So having just 0s will do!
                        vs_length = len(viewstate_data)
                        
                        if viewstate_userkey is not None:
                            modifier = generator + viewstate_userkey.encode("utf-16-le")
                        else:
                            modifier = generator

                        if encrypted:
                            # No modifier is used in encrypted mode in the legacy mode
                            totalLength = vs_length + len(vkey_bytes)
                            b_all = bytearray(totalLength)
                            b_all[0:vs_length] = viewstate_data
                            b_all[vs_length:vs_length+len(vkey_bytes)] = vkey_bytes
                        else:
                            totalLength = vs_length + len(vkey_bytes) + len(modifier)
                            b_all = bytearray(totalLength)
                            b_all[0:vs_length] = viewstate_data
                            b_all[vs_length:vs_length+len(modifier)] = modifier
                            b_all[vs_length:vs_length+len(vkey_bytes)] = vkey_bytes
        
                        h = hashlib.md5(b_all).digest()
                    else:
                        if viewstate_userkey is not None:
                            vs_data_bytes += viewstate_userkey.encode("utf-16-le")
                        
                        h = hmac.new(
                            vkey_bytes,
                            vs_data_bytes,
                            self.hash_algs[hash_alg],
                        ).digest()

                    if h == signature:
                        return hash_alg, None, viewstate_userkey
        
        return None, None, None

    # Return the decryption algorithm if successful
    def viewstate_decrypt_check(self, ekey_bytes, hash_alg, viewstate_B64, mode, all_viewstate_userkeys=[None], main_specific_purpose=Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value, all_specific_purposes=None):
        # 8 is the shortest ViewState I have found and 16 is the shortest hash size which will increae 4/3 in base64
        shortest_encrypted = int((8 + 16 * 4/3) + 0.5)
        is_valid = True
        if viewstate_B64 == None or len(viewstate_B64) < shortest_encrypted:
            is_valid = False
        
        if all_specific_purposes == None and mode == DotNetMode.DOTNET45:
            is_valid = False
        
        if mode == DotNetMode.DOTNET40_LEGACY:
            # We are here as we know the parameter has been encrypted
            # ASP.NET ignores "modifier" if it is encrypted in the legacy mode!
            # So Viewstatekey is ineffective to prevent anti-xsrf attacks in DOTNET40 when encrypted!!
            all_viewstate_userkeys = [None]

        if is_valid:
            viewstate_bytes = base64.b64decode(viewstate_B64)
            vs_size = len(viewstate_bytes)
            block_size = None
            cipher = None

            if hash_alg.lower() == "guess":
                hash_algs = self.hash_sizes.keys()
            else:
                hash_algs = [hash_alg]

            for hash_alg in hash_algs:
                for viewstate_userkey in all_viewstate_userkeys:
                    dec_algos = set()
                    hash_size = self.hash_sizes[hash_alg]

                    if (vs_size - hash_size) % AES.block_size == 0:
                        dec_algos.add("AES")
                    if (vs_size - hash_size) % DES.block_size == 0:
                        dec_algos.add("DES")
                        dec_algos.add("3DES")
                    for dec_algo in list(dec_algos):
                        with suppress(ValueError):
                            if mode == DotNetMode.DOTNET45:
                                for specific_purpose in all_specific_purposes:
                                    # this is for AES and 3DES
                                    tempSpecific_purpose = specific_purpose.copy()
                                    if viewstate_userkey is not None:
                                        # Adding potential ViewStateUserKey
                                        tempSpecific_purpose.append(f"ViewStateUserKey: {viewstate_userkey}")
                                    
                                    label, context = sp800_108_get_key_derivation_parameters(
                                        main_specific_purpose, tempSpecific_purpose
                                    )
                                    derived_ekey_bytes = sp800_108_derivekey(ekey_bytes, label, context, (len(ekey_bytes) * 8))
                                    if dec_algo == "AES":
                                        block_size = AES.block_size
                                        iv = viewstate_bytes[0:block_size]
                                        cipher = AES.new(derived_ekey_bytes, AES.MODE_CBC, iv)
                                        blockpadlen_raw = len(derived_ekey_bytes) % AES.block_size
                                        if blockpadlen_raw == 0:
                                            blockpadlen = block_size
                                        else:
                                            blockpadlen = blockpadlen_raw
                                    elif dec_algo == "3DES":
                                        block_size = DES3.block_size
                                        iv = viewstate_bytes[0:block_size]
                                        cipher = DES3.new(derived_ekey_bytes, DES3.MODE_CBC, iv)
                                        blockpadlen_raw = len(derived_ekey_bytes) % DES3.block_size
                                        if blockpadlen_raw == 0:
                                            blockpadlen = block_size
                                        else:
                                            blockpadlen = blockpadlen_raw
                                    else:
                                        # we don't use DES in DOTNET45
                                        continue
                            else:
                                # This for DOTNET40 and legacy mode
                                if dec_algo == "AES":
                                    block_size = AES.block_size
                                    iv = viewstate_bytes[0:block_size]
                                    cipher = AES.new(ekey_bytes, AES.MODE_CBC, iv)
                                    blockpadlen_raw = len(ekey_bytes) % block_size
                                    if blockpadlen_raw == 0:
                                        blockpadlen = block_size
                                    else:
                                        blockpadlen = blockpadlen_raw
                                elif dec_algo == "3DES":
                                    block_size = DES3.block_size
                                    iv = viewstate_bytes[0:block_size]
                                    cipher = DES3.new(ekey_bytes[:24], DES3.MODE_CBC, iv)
                                    blockpadlen_raw = len(ekey_bytes) % block_size
                                    if blockpadlen_raw == 0:
                                        blockpadlen = block_size
                                    else:
                                        blockpadlen = blockpadlen_raw
                                elif dec_algo == "DES":
                                    block_size = DES.block_size
                                    iv = viewstate_bytes[0:block_size]
                                    cipher = DES.new(ekey_bytes[:8], DES.MODE_CBC, iv)
                                    # Not sure why we are not fixing the padding here!
                                    blockpadlen = 0

                            if block_size and cipher:
                                encrypted_raw = viewstate_bytes[block_size:-hash_size]
                                decrypted_raw = cipher.decrypt(encrypted_raw)

                                with suppress(TypeError):
                                    if mode == DotNetMode.DOTNET45:
                                        decrypt = unpad(decrypted_raw)
                                    else:
                                        decrypt = unpad(decrypted_raw[blockpadlen:])

                                    if self.valid_preamble(decrypt):
                                        # This is not the best way as a badly decrypted viewstate can still have a valid preamble
                                        return dec_algo
                                    else:
                                        continue
        return None

    def get_paths_from_specific_purpose(self, template_source_directory: str, type_str: str):
        # Determine apppath by checking if parts of TemplateSourceDirectory appear in Type
        template_parts = template_source_directory.strip("/").split("/")
        type_parts = type_str.split("_")

        # Selecting the last part first
        appPath = template_parts[-1]
        if appPath == "": # if the last part is empty, then we need to select the second last part
            appPath = "/"

        if template_source_directory.endswith("/"):
            origPath = template_source_directory + type_str
        else:
            origPath = template_source_directory + "/" + type_str
        for i in range(0, len(template_parts), 1):
            if template_parts[i] == type_parts[0]:
                if i == 0:
                    appPath = "/"
                else:
                    appPath = f"/{template_parts[i-1]}/"
                
                if len(template_parts) > i:
                    # we still have some elements after the app path which needs to be removed from the type
                    padding = "_".join(template_parts[i:]) + "_"
                    if type_str.startswith(padding):
                        origPath = template_source_directory + "/" + type_str.replace(padding, "", 1)
                break
        
        origPath = origPath.replace("_", ".")

        return origPath, appPath