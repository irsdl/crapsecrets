#!/usr/bin/env python3
# badsecrets - command line interface
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

from crapsecrets.base import check_all_modules, carve_all_modules, hashcat_all_modules
from crapsecrets.helpers import print_status
from importlib.metadata import version, PackageNotFoundError
import httpx
import argparse
import sys
import os
import re
import toml
import ssl
import time
from urllib.parse import urljoin, urlparse

# Suppress SSL verification warnings in httpx
import warnings
import traceback
# Filter out deprecation warnings unless in debug mode
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
is_debug = False
client_kwargs = None

ascii_art_banner = r"""
░█▀▀█ █▀▀█ █▀▀█ █▀▀█ █▀▀ █▀▀ █▀▀ █▀▀█ █▀▀ ▀▀█▀▀ █▀▀ ▄▀▀▄ 
░█─── █▄▄▀ █▄▄█ █──█ ▀▀█ █▀▀ █── █▄▄▀ █▀▀ ──█── ▀▀█ ▄▀▀▄ 
░█▄▄█ ▀─▀▀ ▀──▀ █▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀─▀▀ ▀▀▀ ──▀── ▀▀▀ ▀▄▄▀ 
💩 Forked from Badsecrets - Maintained by Soroush Dalili (@irsdl) 🦄
"""

def print_version():
    try:
        dist_version = version("crapsecrets")
    except PackageNotFoundError:
        dist_version = "Version Unknown (Running w/poetry?)"
        try:
            # Load the pyproject.toml file
            pyproject_path = os.path.join(os.path.dirname(__file__), '../../pyproject.toml')
            with open(pyproject_path, 'r') as file:
                pyproject_data = toml.load(file)

            # Extract the version from the toml file
            dist_version = "v" + pyproject_data['tool']['poetry']['version']
        except (FileNotFoundError, KeyError):
            pass
    print(f"{dist_version}\n")


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        self.exit(1)


class BaseReport:
    def __init__(self, x):
        self.x = x

    def print_report(self, report_message):
        print(report_message)
        print(f"Detecting Module: {self.x['detecting_module']}\n")
        print(f"Product Type: {self.x['description']['product']}")
        print(f"Product: {self.x['product']}")
        print(f"Secret Type: {self.x['description']['secret']}")
        print(f"Location: {self.x['location']}")


class ReportSecret(BaseReport):
    def report(self):
        self.print_report(print_status("Known Secret Found!\n", color="green", passthru=True))
        print_status(f"Secret: {self.x['secret']}", color="green")
        severity = self.x["description"]["severity"]
        if severity in ["CRITICAL", "HIGH"]:
            severity_color = "red"
        elif severity in ["LOW", "MEDIUM"]:
            severity_color = "yellow"
        elif severity == "INFO":
            severity_color = "blue"
        print_status(f"Severity: {self.x['description']['severity']}", color=severity_color)
        print(f"Details: {self.x['details']}\n")


class ReportIdentify(BaseReport):
    def report(self):
        self.print_report(
            print_status("Cryptographic Product Identified (no vulnerability)\n", color="yellow", passthru=True)
        )
        if self.x["hashcat"] is not None:
            print_hashcat_results(self.x["hashcat"])


def validate_url(
    arg_value,
    pattern=re.compile(
        r"^https?://((?:[A-Z0-9_]|[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_])[\.]?)+(?:[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_]|[A-Z0-9_])(?::[0-9]{1,5})?.*$",
        re.IGNORECASE,
    ),
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError(print_status("URL is not formatted correctly", color="red"))
    return arg_value


def validate_file(file):
    if not os.path.exists(file):
        raise argparse.ArgumentTypeError(print_status(f"The file {file} does not exist!", color="red"))
    if not os.path.isfile(file):
        raise argparse.ArgumentTypeError(print_status(f"{file} is not a valid file!", color="red"))
    if os.path.getsize(file) > 100 * 1024 * 1024:  # size in bytes
        raise argparse.ArgumentTypeError(
            print_status(f"The file {file} exceeds the maximum limit of 100MB!", color="red")
        )
    return file


def print_hashcat_results(hashcat_candidates):
    if hashcat_candidates:
        print_status("\nPotential matching hashcat commands:\n", color="yellow")
        for hc in hashcat_candidates:
            print(
                f"Module: [{hc['detecting_module']}] {hc['hashcat_description']} Command: [{hc['hashcat_command']}]\n"
            )


def main():
    global colorenabled, client_kwargs
    colorenabled = False
    color_parser = argparse.ArgumentParser(add_help=False)

    color_parser.add_argument(
        "-nc",
        "--no-color",
        action="store_true",
        help="Disable color message in the console",
    )

    args, unknown_args = color_parser.parse_known_args()
    colorenabled = not args.no_color

    parser = CustomArgumentParser(
        description="Check cryptographic products against crapsecrets library", parents=[color_parser]
    )

    if colorenabled:
        print_status(ascii_art_banner, color="green")

    else:
        print(ascii_art_banner)
    print_version()

    parser.add_argument(
        "-u",
        "--url",
        type=validate_url,
        help="Use URL Mode. Specified the URL of the page to access and attempt to check for secrets",
    )

    parser.add_argument(
        "-nh",
        "--no-hashcat",
        action="store_true",
        help="Skip the check for compatible hashcat commands when secret isn't found",
    )

    parser.add_argument(
        "-c",
        "--custom-secrets",
        type=validate_file,
        help="Include a custom secrets file to load along with the default secrets",
    )

    parser.add_argument("product", nargs="*", type=str, help="Cryptographic product to check for known secrets")

    parser.add_argument(
        "-p",
        "--proxy",
        help="In URL mode, Optionally specify an HTTP proxy",
    )

    parser.add_argument(
        "-a",
        "--user-agent",
        help="In URL mode, Optionally set a custom user-agent",
    )

    parser.add_argument(
        "-r",
        "--allow-auto-redirects",
        action="store_true",
        help="Optionally follow HTTP redirects automatically. Off by default",
    )

    parser.add_argument(
        "-rm",
        "--allow-manual-redirects",
        action="store_true",
        help="Optionally follow HTTP redirects manually (set --max-redirect-depth to 5 unless given separately). Overrides --allow-auto-redirects. Off by default",
    )

    parser.add_argument(
        "-mrd",
        "--max-redirect-depth", type=int, default=0,
        help="Maximum depth to follow redirects manually. Overrides --allow-auto-redirects. Default is 0 (no manual redirects)."
    )

    parser.add_argument(
        "-mkf",
        "--machinekeyfile",
        action="append",
        type=validate_file,
        help="Specify one or more custom file paths for aspnet machinekeys. Can be used multiple times.",
    )

    parser.add_argument(
        "-avsk",
        "--allviewstatekeys",
        action="store_true",
        help="Check all strings in aspnet_machinekeys.txt once as a validation key and once as a decryption key",
    )

    parser.add_argument(
        "-evsd",
        "--enable-viewstate-decryption",
        action="store_true",
        help="Enable viewstate decryption checks even when the validation key has not been found",
    )

    parser.add_argument(
        "-fvsp",
        "--findviewstatepage",
        action="store_true",
        help="Try to find the ASPX page with the viewstate when .aspx is missing from the path. This may have a performance hit.",
    )

    parser.add_argument(
        "-dap",
        "--disable-active-path-check",
        action="store_true",
        help="Disable checking for application paths proactively by sending additional web requests to the server (only applicable for the viewstate module).",
    )

    parser.add_argument(
        "-nt",
        "--num-threads",
        type=int,
        default=1,
        help="Specify the number of threads to use (only applicable for the viewstate module). Default is 1.",
    )

    parser.add_argument(
            '-H', '--header', action='append', type=str,
            help="Custom headers, e.g., 'Name: Value'. Can be used multiple times."
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Set the request timeout in seconds (default is 10 seconds)",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode to print detailed error messages",
    )

    args = parser.parse_args(unknown_args)
    if args.debug:
        global is_debug
        is_debug = True
        # Re-enable warnings in debug mode
        warnings.resetwarnings()
    
    if not args.url and not args.product:
        parser.error(
            print_status(
                "Either supply the product as a positional argument (supply all products for multi-product modules), use --hashcat followed by the product as a positional argument, or use --url mode with a valid URL",
                color="red",
            )
        )
        return

    if args.url and args.product:
        parser.error(print_status("In --url mode, no positional arguments should be used", color="red"))
        return

    allow_auto_redirects = False
    if args.allow_auto_redirects:
        allow_auto_redirects = True

    allow_manual_redirects = False
    max_redirect_depth = 0
    if args.allow_manual_redirects:
        allow_auto_redirects = False
        allow_manual_redirects = True
        args.max_redirect_depth = 5
        max_redirect_depth = 5

    if args.max_redirect_depth > 0:
        allow_auto_redirects = False
        allow_manual_redirects = False
        args.allow_manual_redirects = True
        max_redirect_depth = args.max_redirect_depth

    proxy = None
    if args.proxy:
        if not args.proxy.startswith("http://") and not args.proxy.startswith("https://"):
            proxy = "http://" + args.proxy
        elif args.proxy.startswith("http:") and not args.proxy.startswith("http://"):
            proxy = "http://" + args.proxy[5:]
        elif args.proxy.startswith("https:") and not args.proxy.startswith("https://"):
            proxy = "https://" + args.proxy[6:]
        else:
            proxy = args.proxy

    custom_resource = None
    if args.custom_secrets:
        custom_resource = args.custom_secrets
        print_status(f"Including custom secrets list [{custom_resource}]\n", color="yellow")

    if args.url:
        
        # Parse the custom headers into a dictionary
        headers = parse_headers(args.header) if args.header else {}
        if "Accept" not in headers:
            headers["Accept"] = "*/*"
        if "Accept-Language" not in headers:
            headers["Accept-Language"] = "en-US;q=0.9,en;q=0.8"
        if "Connection" not in headers:
            headers["Connection"] = "close"

        if args.user_agent:
            headers["User-agent"] = args.user_agent
        else:
            headers["User-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.3"


        # accepting insecure certs
        try:
            # Create the most permissive context possible
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Explicitly enable all protocols - don't use the negation approach
            # as it can cause the "no protocols available" error
            ssl_context = ssl._create_unverified_context()
            
            # Set most permissive ciphers
            ssl_context.set_ciphers('DEFAULT:ALL:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA:@SECLEVEL=0')
            
            # Disable hostname verification at the transport level too
            client_kwargs = {
                "headers": headers,
                "verify": False,
                "http2": False,
                "follow_redirects": False,
                "trust_env": False,
                "timeout": httpx.Timeout(
                    connect=args.timeout,
                    read=args.timeout,
                    write=args.timeout,
                    pool=args.timeout
                ),
                "limits": httpx.Limits(
                    max_keepalive_connections=1,
                    max_connections=5,
                    keepalive_expiry=1
                )
            }
            
            # Use a transport that doesn't verify SSL
            client_kwargs["transport"] = httpx.HTTPTransport(
                retries=2,
                verify=False
            )

        except Exception as e:
            if is_debug:
                print(f"Warning: Error configuring SSL context: {str(e)}")
            # Fallback to the most basic unverified context
            ssl_context = ssl._create_unverified_context()
            client_kwargs["verify"] = False

        # Update client configuration
        client_kwargs.update({
            "headers": headers,
            "verify": False,
            "http2": False,
            "follow_redirects": False,
            "trust_env": False,
            "timeout": httpx.Timeout(
                connect=args.timeout,
                read=args.timeout,
                write=args.timeout,
                pool=args.timeout
            ),
            "limits": httpx.Limits(
                max_keepalive_connections=1,
                max_connections=5,
                keepalive_expiry=1
            ),
            "transport": httpx.HTTPTransport(
                retries=3,
                local_address="0.0.0.0",
                verify=ssl_context  # Use our custom SSL context
            )
        })

        # Add proxy configuration if provided
        if proxy:
            client_kwargs["proxy"] = proxy
        

        print_status(f"Target: {args.url}", color="yellow")

        client = httpx.Client(**client_kwargs)

        result_list = send_requests(args.url, args.timeout, allow_auto_redirects, max_redirect_depth, custom_resource, client, args)
        
        if result_list:
            for r in result_list:
                if r["type"] == "SecretFound":
                    report = ReportSecret(r)
                else:
                    if not args.no_hashcat and r["product"]:
                        hashcat_candidates = hashcat_all_modules(r["product"], detecting_module=r["detecting_module"])
                        if hashcat_candidates:
                            r["hashcat"] = hashcat_candidates
                    report = ReportIdentify(r)
                report.report()
        else:
            print_status("No secrets found :(", color="red")

    else:
        x = check_all_modules(*args.product, custom_resource=custom_resource)
        if x:
            report = ReportSecret(x)
            report.report()
        else:
            print_status("No secrets found :(", color="red")
            if not args.no_hashcat:
                hashcat_candidates = hashcat_all_modules(*args.product)
                if hashcat_candidates:
                    print_hashcat_results(hashcat_candidates)

def parse_headers(header_list):
    headers = {}
    for header in header_list:
        try:
            name, value = header.split(":", 1)
            headers[name.strip()] = value.strip()
        except ValueError:
            print(f"Invalid header format: {header}. Must be 'Name: Value'.")
    return headers

def send_requests(url, timeout, allow_auto_redirects, max_redirect_depth=0, custom_resource=None, client=None, commandargs=None):
    result_list = []
    depth = 0

    if max_redirect_depth > 0:
        allow_auto_redirects = False
    
    visited_counts = {}  # Track how many times each URL is visited
    max_visits_per_url = 3  # Allow each URL to be revisited at most three times

    while client and depth <= max_redirect_depth:
        try:        
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    if retry_count > 0:
                        # Create fresh connection on retry
                        client.close()
                        client = httpx.Client(**client_kwargs)
                    
                    response = client.get(
                        url, 
                        follow_redirects=allow_auto_redirects,
                        timeout=timeout
                    )
                    result = carve_all_modules(requests_response=response, custom_resource=custom_resource, url=url, client=client, commandargs=commandargs)
                    if result:
                        result_list += result
                    break  # Success - exit retry loop
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        raise
                    if is_debug:
                        print(f"Connection attempt {retry_count} failed, retrying in 2s... ({str(e)})")
                    time.sleep(2)
  
            # If the status code is a redirect (3xx)
            if 300 <= response.status_code < 400 and 'Location' in response.headers:
                # Get the Location header with the redirect URL
                location = response.headers['Location']
                
                # Check if the Location is an absolute URL or relative
                parsed_location = urlparse(location)
                if parsed_location.scheme in ['http', 'https']:
                    # Absolute URL, use it as is
                    new_url = location
                else:
                    # Relative URL, resolve it against the current URL
                    new_url = urljoin(url, location)
                
                # Track the number of visits for the new URL
                if new_url in visited_counts:
                    if visited_counts[new_url] >= max_visits_per_url:
                        # Stop following this redirect if we've already visited this URL enough times
                        break
                    else:
                        visited_counts[new_url] += 1
                else:
                    visited_counts[new_url] = 1

                # Update the URL and increase the depth
                url = new_url
                depth += 1
                
                # Update the Referer header before redirecting
                client.headers["Referer"] = url
                # Process cookies from the response
                
                client.cookies.update(response.cookies)
                #print(f"Redirecting to: {url} (Depth: {depth})")
            else:
                # If it's not a redirect, break the loop
                #print(f"Final URL: {url} (Depth: {depth})")
                break
        except (httpx.RequestError, httpx.TimeoutException, ssl.SSLError) as e:
            print_status(f"Error connecting to URL: [{url}] , redirect-depth: [{max_redirect_depth}] - {str(e)}", color="red")
            if is_debug:
                traceback.print_exc()
            break
    
    return result_list

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("Exiting...", color="red")
        sys.exit(0)
    except Exception as e:
        if is_debug:
            print_status(f"Error: {str(e)}")
            traceback.print_exc()  
        else:
            print_status(f"An error has occured. Please use --debug to see the details.")
