import re
import hmac
import base64
import hashlib
import binascii
import traceback
from Crypto.Cipher import AES, DES, DES3
from contextlib import suppress
from urllib.parse import urljoin, urlsplit
from crapsecrets.helpers import Viewstate_Helpers, isolate_app_process, unpad, sp800_108_derivekey, sp800_108_get_key_derivation_parameters, Purpose, aspnet_resource_b64_to_standard_b64, matchLooseBase64RegEx
from crapsecrets.base import CrapsecretsBase, Section, generic_base64_regex
import concurrent.futures
from threading import Event
from enum import Enum
from crapsecrets.modules.aspnet_viewstate import DotNetMode

class ASPNET_Resource(CrapsecretsBase):
    is_debug = False
    supported_sections = frozenset({Section.BODY})
    check_secret_args = 2
    product_group_number_in_carve = [1,3] # This is probably wrong to use a RegEx in this - we will have some unknown products!
    identify_regex = generic_base64_regex
    description = {"product": "ASP.NET Resource", "secret": "ASP.NET MachineKey", "severity": "HIGH"}
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
            r'(' # This is when we have WebResource.axd?d=
            r'"[^"]*WebResource\.axd\?d=([^&"]+)[\S\s]+?'
            r')|(' # This is when everything else is missing but we have ScriptResource.axd?d=
            r'"[^"]*ScriptResource\.axd\?d=([^&"]+)[\S\s]+?'
            r')'
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
        url = None
        actionPage = ""
        web_resource_b64 = ""
        script_resource_b64 = ""
        generatorHex = "00000000"

        if len(args) == 2 and len(args[0]) >= 3:
            url = args[1]
            if args[0][1]:
                web_resource_b64 = aspnet_resource_b64_to_standard_b64(args[0][1])
            if not web_resource_b64:
                script_resource_b64 = aspnet_resource_b64_to_standard_b64(args[0][3])
        else:
            # This is to pass the tests from badsecrets!
            url_pattern = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
            generator_pattern = re.compile(r"^[A-F0-9]{8}$")
            for arg in args:
                if arg:
                    if url_pattern.match(arg):
                        url = arg
                    elif matchLooseBase64RegEx(aspnet_resource_b64_to_standard_b64(arg)):
                        web_resource_b64 = arg
        
        # If __VIEWSTATEGENERATOR or __VIEWSTATE has not been found, we will try to dig deeper as combined RegEx is not really ideal
        # An example is https://www.skype.com/en/404.aspx where the values are in different forms with wrong order!
        # We also want to find __EVENTVALIDATION without use of a predefined badsecrets RegEx
        if self.requests_response and self.is_from_body:
            body = self.requests_response.text
            
            if not web_resource_b64 or web_resource_b64.strip() == "":
                web_resource_pattern = re.compile(r'"[^"]*WebResource\.axd\?d=([^&"]+)[\S\s]+?', re.IGNORECASE)
                web_resource_match = web_resource_pattern.search(body)
                if web_resource_match:
                    web_resource_b64 = aspnet_resource_b64_to_standard_b64(web_resource_match.group(1))

            if not script_resource_b64 or script_resource_b64.strip() == "":
                script_resource_pattern = re.compile(r'"[^"]*ScriptResource\.axd\?d=([^&"]+)[\S\s]+?', re.IGNORECASE)
                script_resource_match = script_resource_pattern.search(body)
                if script_resource_match:
                    script_resource_b64 = aspnet_resource_b64_to_standard_b64(script_resource_match.group(1))
            
            # The rest is useful only if we have the ",IsolateApps" in the MachineKey
            if not generatorHex or generatorHex.strip() == "" or generatorHex == "00000000":
                generator_pattern = re.compile(r'<input[^>]+(VIEWSTATEGENERATOR)[\"\']\svalue=[\"\']([^\"\']+)[\"\']', re.IGNORECASE)             
                generator_match = generator_pattern.search(body)
                if generator_match:
                    generatorHex = generator_match.group(2)

            if not actionPage or actionPage.strip() == "":
                action_pattern = re.compile(r'<form[^>]+action=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                action_match = action_pattern.search(body)
                if action_match:
                    actionPage = action_match.group(1)            

        return actionPage, web_resource_b64, script_resource_b64, generatorHex, url

    def check_secret(self, web_resource_b64_init, *args):
        actionPage, web_resource_b64, script_resource_b64, generatorHex, origUrl = self.resolve_args(args)
        
        # This happens during tests!
        if not web_resource_b64 and web_resource_b64_init and matchLooseBase64RegEx(web_resource_b64_init):
            web_resource_b64 = web_resource_b64_init
        
        signed_encrypted_B64 = ""

        # If we don't have viewstate but we have eventvalidation, we will use it instead
        if web_resource_b64 and matchLooseBase64RegEx(web_resource_b64):
            signed_encrypted_B64 = web_resource_b64
            main_purpose = Purpose.AssemblyResourceLoader_WebResourceUrl.value
        else:
            signed_encrypted_B64 = script_resource_b64
            main_purpose = Purpose.ScriptResourceHandler_ScriptResourceUrl.value


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

        temp_product = signed_encrypted_B64
        if len(temp_product) > 200:
            temp_product = temp_product[:100] + "..." + temp_product[-10:]
        else:
            temp_product = temp_product

        modes = [DotNetMode.DOTNET45, DotNetMode.DOTNET40_LEGACY]

        apppaths_hashcodes = [None]
        if self.test_IsolateApps and generatorHex and generatorHex != "00000000":
            # we don't need to do this in a loop to increase performance
            viewstate_helpers = Viewstate_Helpers(url, generatorHex, findviewstatepage=self.find_viewstate_page, calculate_generator=True, is_debug=self.is_debug)
            # Shall we send some requests to the server to find the application paths?
            if self.find_app_path_proactively and not viewstate_helpers.verified_apppath and viewstate_helpers.any_directory_in_url():
                # We now have permission to send requests to the target URL to see whether we can find all paths which are application paths
                # This is to reduce the number of keys to check as they are based on apppath
                potential_apppaths = viewstate_helpers.find_all_apppaths_actively(self.client)
                if potential_apppaths and len(potential_apppaths) > 0:
                    viewstate_helpers.verified_potential_apppaths = potential_apppaths
            

            apppaths_hashcodes = [None] + viewstate_helpers.get_apppaths_hashcodes()
            
        results = self.process_keys(signed_encrypted_B64, url, modes, main_purpose, apppaths_hashcodes)
        if results and isinstance(results, list) and len(results) > 0:
            return results
    
        # If we are here then we don't have good results! We might have a partial results though!
        if results != None:
            self.description["severity"] = "INFO"
            temp_product = signed_encrypted_B64
            if len(temp_product) > 200:
                temp_product = temp_product[:100] + "..." + temp_product[-10:]
            else:
                temp_product = temp_product
            #return "Crapsecrets was unable to crack __VIEWSTATE!"
            #return {"type":"IdentifyOnly", "secret": "Crapsecrets was unable to crack __VIEWSTATE!", "product": f"Viewstate: {temp_product}", "details": f"URL: [{finalUrl}]"}
            return [None]
        
        return None
    
    # Returns list of results
    def process_keys(self, signed_encrypted_B64, url, modes, main_purpose=Purpose.AssemblyResourceLoader_WebResourceUrl.value, apppaths_hashcodes=[None]):
        
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
                            
                            local_validation_algo, process_validationkey_result = self.process_validationkey(
                                vkey, mode, signed_encrypted_B64, main_purpose, original_key
                            )
                            
                            if local_validation_algo:
                                # Return tuple with all relevant data
                                local_results.append((vkey, mode, local_validation_algo, 
                                                process_validationkey_result))
                                
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
                        for vkey, mode, validation_algo, process_validationkey_result in chunk_results:
                            # Set stop event to halt other threads if we have a successful validation
                            if validation_algo:
                                validation_stop_event.set()
                                confirmed_validation_algo = validation_algo
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
        
        if confirmed_validation_algo == None and self.find_decryption_key_without_validation_key:
            # We are here because we couldn't find the validation key
            # However, we can still try to find the decryption key as find_decryption_key_without_validation_key is set
            confirmed_validation_algo = "guess"
        
        # Process decryption if needed
        if self.find_decryption_key_without_validation_key or (confirmed_validation_algo and confirmed_validation_algo != ""):
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
                                    confirmed_validation_algo, dkey, mode, signed_encrypted_B64,
                                    main_purpose, original_key
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

        temp_product = signed_encrypted_B64
        if len(temp_product) > 200:
            temp_product = temp_product[:100] + "..." + temp_product[-10:]
        else:
            temp_product = temp_product

        if main_purpose == Purpose.WebForms_ClientScriptManager_EventValidation.value:
            product_string = f"EventValidation: {temp_product}"
        elif main_purpose == Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value:
            product_string = f"Viewstate: {temp_product}"
        else:
            product_string = f"Resources: {temp_product}"

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
            self.description["severity"] = "HIGH"
        else:
            self.description["severity"] = "INFO"
        return unique_results #unique_results

    
    # Returns validation_algo, specific_purpose, viewstate_userkey, result in string
    def process_validationkey(self, vkey, mode, signed_encrypted_B64, main_purpose=Purpose.AssemblyResourceLoader_WebResourceUrl.value, original_key=None):
        validation_algo = None
        result = ""

        if not original_key:
            original_key = vkey
        
        try:
            validation_algo = self.resource_validate_check(
                binascii.unhexlify(vkey), signed_encrypted_B64, mode, main_purpose
            )
        except binascii.Error as e:
            # This is to see invalid keys in the file
            #print("Invalid key in the resource file: " + vkey)
            pass
            
        if not validation_algo:
            return None, None
        
        if validation_algo != "guess":
            if validation_algo == "MAC_DISABLED":
                return "MAC_DISABLED", "MAC is disabled, use LosFormatter from YSoSerial.Net"            
            
            # Build the result string
            algo_display = ( "SHA1 or 3DES or AES" 
                            if validation_algo == "SHA1" and mode == DotNetMode.DOTNET40_LEGACY 
                            else validation_algo )


            if original_key != vkey:
                result = f"ValidationKey: [{original_key},IsolateApps] ValidationAlgo: [{algo_display}]"
            else:
                result = f"ValidationKey: [{original_key}] ValidationAlgo: [{algo_display}]"

        return validation_algo, result
    
    def process_decryption_keys(self, validation_algo, dkey, mode, signed_encrypted_B64, main_purpose=Purpose.AssemblyResourceLoader_WebResourceUrl.value, original_key=None):
        # Simplified to handle single key check
        result = ""
        if not original_key:
            original_key = dkey

        try:
            candidate_bytes = binascii.unhexlify(dkey)
            decryption_algo = self.resource_decrypt_check(
                candidate_bytes, validation_algo, signed_encrypted_B64, mode, main_purpose
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

    # Return hash algorithm, specific purpose, and ViewStateUserKey if successful
    # In case MAC validation is not enabled, it will return "MAC is not enabled!"
    def resource_validate_check(self, vkey_bytes, signed_encrypted_B64, mode, main_specific_purpose=Purpose.AssemblyResourceLoader_WebResourceUrl.value):
        shortest_encrypted = 8
        is_valid = True

        if signed_encrypted_B64 == None or len(signed_encrypted_B64) < shortest_encrypted:
            is_valid = False
    
        if is_valid:
            original_vkey_bytes = vkey_bytes
            signed_encrypted_bytes = base64.b64decode(signed_encrypted_B64)
            candidate_hash_algs = list(self.hash_sizes.keys())

            for hash_alg in candidate_hash_algs:
                
                vkey_bytes = original_vkey_bytes
                signed_encrypted_data = signed_encrypted_bytes[: -self.hash_sizes[hash_alg]]
                signed_encrypted_data_copy = signed_encrypted_data

                signature = signed_encrypted_bytes[-self.hash_sizes[hash_alg] :]
                if mode == DotNetMode.DOTNET45:                   
                    label, context = sp800_108_get_key_derivation_parameters(
                        main_specific_purpose, []
                    )
                    derived_vkey_bytes = sp800_108_derivekey(vkey_bytes, label, context, (len(vkey_bytes) * 8))
                    h = hmac.new(
                        derived_vkey_bytes,
                        signed_encrypted_data_copy,
                        self.hash_algs[hash_alg],
                    ).digest()
                    # This is dirty to have this check here but we are in a loop for the paths (all_specific_purposes) so we need to speed up!
                    if h == signature:
                        return hash_alg
                elif hash_alg == "MD5" and mode == DotNetMode.DOTNET40_LEGACY:
                    # The HashDataUsingNonKeyedAlgorithm function in ASP.NET has a bug overwriting the modifier if shorter than validation key! 
                    # So having just 0s will do!
                    vs_length = len(signed_encrypted_data)
                    
                    # No modifier is used in encrypted mode in the legacy mode
                    totalLength = vs_length + len(vkey_bytes)
                    b_all = bytearray(totalLength)
                    b_all[0:vs_length] = signed_encrypted_data
                    b_all[vs_length:vs_length+len(vkey_bytes)] = vkey_bytes
                    
                    h = hashlib.md5(b_all).digest()
                else:
                    
                    h = hmac.new(
                        vkey_bytes,
                        signed_encrypted_data_copy,
                        self.hash_algs[hash_alg],
                    ).digest()

                if h == signature:
                    return hash_alg
        
        return None

    # Return the decryption algorithm if successful
    def resource_decrypt_check(self, ekey_bytes, hash_alg, signed_encrypted_B64, mode, main_specific_purpose=Purpose.AssemblyResourceLoader_WebResourceUrl.value):
        # 8 is just a good small number, and 16 is the shortest hash size which will increae 4/3 in base64
        shortest_encrypted = int((8 + 16 * 4/3) + 0.5)
        is_valid = True
        if signed_encrypted_B64 == None or len(signed_encrypted_B64) < shortest_encrypted:
            is_valid = False

        if is_valid:
            signed_encrypted_bytes = base64.b64decode(signed_encrypted_B64)
            vs_size = len(signed_encrypted_bytes)
            block_size = None
            cipher = None
            if hash_alg.lower() == "guess":
                hash_algs = self.hash_sizes.keys()
            else:
                hash_algs = [hash_alg]

            for hash_alg in hash_algs:
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
                            label, context = sp800_108_get_key_derivation_parameters(
                                main_specific_purpose, []
                            )
                            derived_ekey_bytes = sp800_108_derivekey(ekey_bytes, label, context, (len(ekey_bytes) * 8))
                            if dec_algo == "AES":
                                block_size = AES.block_size
                                iv = signed_encrypted_bytes[0:block_size]
                                cipher = AES.new(derived_ekey_bytes, AES.MODE_CBC, iv)
                                blockpadlen_raw = len(derived_ekey_bytes) % AES.block_size
                                if blockpadlen_raw == 0:
                                    blockpadlen = block_size
                                else:
                                    blockpadlen = blockpadlen_raw
                            elif dec_algo == "3DES":
                                block_size = DES3.block_size
                                iv = signed_encrypted_bytes[0:block_size]
                                cipher = DES3.new(derived_ekey_bytes, DES3.MODE_CBC, iv)
                                # blockpadlen_raw = len(derived_ekey_bytes) % DES3.block_size
                                # if blockpadlen_raw == 0:
                                #     blockpadlen = block_size
                                # else:
                                #     blockpadlen = blockpadlen_raw
                                blockpadlen = 16
                            else:
                                # we don't use DES in DOTNET45
                                continue
                        else:
                            # This for DOTNET40 and legacy mode
                            if dec_algo == "AES":
                                block_size = AES.block_size
                                iv = signed_encrypted_bytes[0:block_size]
                                cipher = AES.new(ekey_bytes, AES.MODE_CBC, iv)
                                blockpadlen_raw = len(ekey_bytes) % block_size
                                if blockpadlen_raw == 0:
                                    blockpadlen = block_size
                                else:
                                    blockpadlen = blockpadlen_raw
                            elif dec_algo == "3DES":
                                block_size = DES3.block_size
                                iv = signed_encrypted_bytes[0:block_size]
                                cipher = DES3.new(ekey_bytes[:24], DES3.MODE_CBC, iv)
                                blockpadlen = 16
                            elif dec_algo == "DES":
                                block_size = DES.block_size
                                iv = signed_encrypted_bytes[0:block_size]
                                cipher = DES.new(ekey_bytes[:8], DES.MODE_CBC, iv)
                                # Not sure why we are not fixing the padding here!
                                blockpadlen = 0

                        if block_size and cipher:
                            encrypted_raw = signed_encrypted_bytes[block_size:-hash_size]
                            decrypted_raw = cipher.decrypt(encrypted_raw)

                            with suppress(TypeError):
                                if mode == DotNetMode.DOTNET45:
                                    decrypt = unpad(decrypted_raw)
                                else:
                                    decrypt = unpad(decrypted_raw[blockpadlen:])

                                try:
                                    if len(decrypt) > 8 and all(32 <= ord(char) <= 126 for char in decrypt.decode('utf-8')):
                                        # This might not be the best way to check if the decrypted data is valid
                                        # We will nee the formula here to check if the decrypted data is valid
                                        if self.is_debug:
                                            print(f"Decrypted data: {decrypt}")
                                        return dec_algo
                                except Exception:
                                    continue

                                else:
                                    continue
        
        return None
