### Forked originally from badsecrets 0.7.0
### Synced occasionally until March 2025!
### > Outdated with some modules and test cases are not up2date!
### > Good for ASP.NET compromised Machine Key testing!
###
### This is Crap(Bad)Secrets

```
mkdir -p ~/ctools/
cd ~/ctools/
git clone https://github.com/irsdl/crapsecrets/
cd ~/ctools/crapsecrets
pip3 install -r requirements.txt
export PYTHONPATH=$(pwd):$PYTHONPATH
python3 ./crapsecrets/examples/cli.py -u http://update.microsoft.com/ -r
python3 ./crapsecrets/examples/cli.py -u http://update.microsoft.com/ -mrd 5
python3 ./crapsecrets/examples/cli.py -mrd 5 -avsk -fvsp -u http://update.microsoft.com/
python3 ./crapsecrets/examples/cli.py -mrd 5 -avsk -fvsp -mkf ./local/aspnet_machinekeys_local.txt -u http://192.168.6.22:8080/
python3 ./crapsecrets/examples/cli.py -mrd 5 -avsk -fvsp -mkf ./local/aspnet_machinekeys_local.txt -mkf ./crapsecrets/resources/aspnet_machinekeys.txt -u http://192.168.6.22:8080/a1/b/c1/

```

## Tips for Viewstate
- Run the command using `-mrd 5` to allow analysis of long redirect responses.
- Use `--allviewstatekeys` or `-avsk` in order to try all the key combinations as validation and encryption keys 
- Use `--findviewstatepage` or `-fvsp` in order to try a set of default pages when .aspx is missing from the URL

## Generic Changes:
- Uses httpx instead of requests (changes mainly made by AI with minimal testing, so they might be incorrect).
- Adds depth to the redirection (the `--max-redirect-depth` argument for manual redirects).
- Supports additional headers.
- Request timeout can be set using the `--timeout` or `-t` argument

## Viewstate Changes:
- Contains more machine keys and some logical changes.
- Shows a possibility for AES and 3DES for validation key in encrypted .NET 4.0 viewstates.
- Removes cookieless values from the path.
- Removes parameters after .aspx.
- Removes multiple slash and backslash characters.
- Improves .NET4.5 logic to use application names in subdirectories.
- Detects when "MAC is not enabled".
- Handles long redirection when there is a response (this is when -r to follow redirect is NOT used).
- Handles redirection to another ASPX page (this is when -r to follow redirect is used).
- Handles when Server.Transfer is used instead of a redirect (generator is different than the target).
- Detects when MaxPageStateFieldLength is used and we have __VIEWSTATEFIELDCOUNT.
- Supports a few predefined ViewStateUserKey in addition to checking the asp.net_sessionid and __antixsrftoken cookies in the response.
- It detects decryption keys for 3DES in ASPNET4.5 properly
- Adding an option to check all strings in aspnet_machinekeys.txt once as a validation key and once as decryption key. When we use the `--allviewstatekeys` flag, the tool attempts to find all Potential EncryptionKeys and tries each one in a random order to decrypt the data. Because so many keys are tested, there is a chance of hitting an invalid key on any single run. However, the tool will list every possible key it detects. By running the tool twice, you significantly increase the likelihood of finding a valid encryption key, since seeing the same key appear in both runs is nearly a 100% guarantee that it is correct.
- Using an array of default pages when .aspx is not included in the given URL: `["default.aspx", "index.aspx", "main.aspx", "home.aspx" , "start.aspx", "welcome.aspx", "default2.aspx"]` - This increases the testing time significantly but can potentially lead to more findings
- It can use `-mkf` or `--machinekeyfile` as a resource file for machinekeys so we can use a local version if it contains sensitive keys
- It is using a customised version of python viewstate library to support more objects when parsing viewstate
- Added the `-evsd` or `--enable-viewstate-decryption` argument to check for the decryption key even when the validation key has not been found. This can be useful when the validation key is slightly different from the original one in the list.
- Calculates the `__VIEWSTATEGENERATOR` by identifying its hash code. It also tries to find the actual path and app path early if `__VIEWSTATEGENERATOR` and URL have been provided. This can potentially increase performance, especially when an identifiable default ASPX page is missing from the URL.
- Users can specify the number of threads to use with the `-nt` or `--num-threads` option (only applicable for the viewstate module). The default is 1 which is surprisingly fater than 10 in most cases!
- It should support files with no extensions but we will need to fix errors as they are being reported.
- It suppors IsolateApps (useful for .NET40 legacy). This is when we have ",IsolateApps" after the validation or decryption keys.
- It reduces number of apppaths by actively testing for it based on https://soroush.me/blog/2019/07/iis-application-vs-folder-detection-during-blackbox-testing/. It can be disabled by `-dap` or `--disable-active-path-check`
- Check for __VIEWSTATE_KEY in the response body and use it as a viewstatekey too
- Add public IP address to viewstate key based on session ID or then anti-XSRF token
- It uses __EVENTVALIDATION when __VIEWSTATE is missing
- It uses the encrypted resource values from `/WebResource.axd?d=` or `/ScriptResource.axd?d=` under a new module called "aspnet_resource.py". It also supports IsolateApps feature there too. This is useful when __VIEWSTATE and __EVENTVALIDATION are missing.

## TODO:
- add client IP addresses to the potential viewstate keys
- add a dictionary for common pages and directories when calculating viewstate
- Implement support for IsolateByAppId (probably impossible as it requires a secret from registry which we shouldn't have!)
- Add support for retry when there is an error.
- Test errors due to replacing requests with httpx.
- There are some failed tests due to the conversion from requests to httpx and the use of AI. They can be seen by running `pytest` in the root of the project. Although some of them have been fixed, there are still some errors in the tests that need addressing in the future. I also need to run pytest on the original repo to compare!

```
FAILED tests/all_modules_test.py::test_carve_all_cookies - AssertionError: assert 2 == 7
FAILED tests/examples_blacklist3r_test.py::test_examples_blacklist3r_offline - AssertionError: assert 'Did not find viewstate in repsonse from URL' in 'Did not find viewstate in response...
FAILED tests/examples_cli_test.py::test_example_cli_hashcat_telerikhashkey - AssertionError: assert 'Module: [Te...ture Command' not in '\x1b[32m\n ...y_file>]\n\n'
FAILED tests/examples_cli_test.py::test_example_cli_hashcat_telerikhashkey_invalid2 - AssertionError: assert 'Known Secret Found!' in '\x1b[32m\n __ )              |                            ...
FAILED tests/examples_symfony_signedurl_test.py::test_symfony_brute_success - AssertionError: assert 'Found Symfony Secret! [50c8215b436ebfcc1d568effb624a40e]' in 'Target appears to be ...
FAILED tests/examples_telerik_knownkey_test.py::test_fullrun_PBKDF2 - KeyError: "'additional_matcher' is not a valid Pattern"
FAILED tests/examples_telerik_knownkey_test.py::test_badoutput_PBKDF1_MS - KeyError: "'additional_matcher' is not a valid Pattern"
FAILED tests/examples_telerik_knownkey_test.py::test_fullrun_asyncupload_earlydetection - KeyError: "'additional_matcher' is not a valid Pattern"
FAILED tests/examples_telerik_knownkey_test.py::test_fullrun_asyncupload_success - KeyError: "'additional_matcher' is not a valid Pattern"
FAILED tests/examples_telerik_knownkey_test.py::test_fullrun_asyncupload_PBKDF1_MS - KeyError: "'additional_matcher' is not a valid Pattern"
```

## Disclaimer 
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

This software is a personal project and not related to any companies, including the project owner's and contributors' employers.

# The original readme of badsecrets

<p align="left"><img width="300" height="300" src="https://user-images.githubusercontent.com/24899338/223151619-6859bc93-1fe2-47c7-86a6-ecaa6b495ece.png"></p>

[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
![License](https://img.shields.io/badge/license-GPLv3-f126ea.svg)
![Tests](https://github.com/blacklanternsecurity/badsecrets/actions/workflows/tests.yaml/badge.svg?branch=main)
[![codecov](https://codecov.io/gh/blacklanternsecurity/badsecrets/branch/main/graph/badge.svg?token=2PAE7NUM07)](https://codecov.io/gh/blacklanternsecurity/badsecrets)
[![Pypi Downloads](https://img.shields.io/pypi/dm/badsecrets)](https://pypi.org/project/badsecrets)


A pure python library for identifying the use of known or very weak cryptographic secrets across a variety of platforms. The project is designed to be both a repository of various "known secrets" (for example, ASP.NET machine keys found in examples in tutorials), and to provide a language-agnostic abstraction layer for identifying their use.  

Knowing when a 'bad secret' was used is usually a matter of examining some cryptographic product in which the secret was used: for example, a cookie which is signed with a keyed hashing algorithm. Things can get complicated when you dive into the individual implementation oddities each platform provides, which this library aims to alleviate. 

Check out our full [blog post](https://blog.blacklanternsecurity.com/p/introducing-badsecrets) on the Black Lantern Security blog!

Inspired by [Blacklist3r](https://github.com/NotSoSecure/Blacklist3r), with a desire to expand on the supported platforms and remove language and operating system dependencies. 

## Current Modules

| Name     | Description |
| ----------- | ----------- |
| ASPNET_Viewstate      | Checks the viewstate/generator against a list of known machine keys. |
| Telerik_HashKey   | Checks patched (2017+) versions of Telerik UI for a known Telerik.Upload.ConfigurationHashKey |
| Telerik_EncryptionKey   | Checks patched (2017+) versions of Telerik UI for a known Telerik.Web.UI.DialogParametersEncryptionKey |
| Flask_SignedCookies  | Checks for weak Flask cookie signing password. Wrapper for [flask-unsign](https://github.com/Paradoxis/Flask-Unsign) |
| Peoplesoft_PSToken  | Can check a peoplesoft PS_TOKEN for a bad/weak signing password |
| Django_SignedCookies   | Checks django's session cookies (when in signed_cookie mode) for known django secret_key |
| Rails_SecretKeyBase   | Checks Ruby on Rails signed or encrypted session cookies (from multiple major releases) for known secret_key_base |
| Generic_JWT | Checks JWTs for known HMAC secrets or RSA private keys |
| Jsf_viewstate | Checks Both Mojarra and Myfaces implimentations of Java Server Faces (JSF) for use of known or weak secret keys | 
| Symfony_SignedURL | Checks symfony "_fragment" urls for known HMAC key. Operates on Full URL, including hash |
| Express_SignedCookies_ES | Checks express.js express-session middleware for signed cookies and session cookies for known 'session secret' |
| Express_SignedCookies_CS | Checks express.js cookie-session middleware for signed cookies and session cookies for known secret |
| Laravel_SignedCookies | Checks 'laravel_session' cookies for known laravel 'APP_KEY' |
| ASPNET_Vstate      | Checks for a once popular custom compressed Viewstate [code snippet](https://blog.sorcery.ie/posts/higherlogic_rce/) vulnerable to RCE|
| Rack2_SignedCookies | Checks Rack 2.x signed cookies for known secret keys |

## Installation

We have a [pypi](https://pypi.org/project/badsecrets/) package, so you can just do `pip install badsecrets` to make use of the library.

## Simple Usage

The best way to use Badsecrets is by simply running `badsecrets` after doing a pip install:

```
pip install badsecrets
badsecrets eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo
```

Under the hood, it's using the  `cli.py` example. The CLI can also be accessed manually without a pip installation:


#### Without pip installation:
```bash
git clone https://github.com/blacklanternsecurity/badsecrets.git
cd badsecrets
python ./badsecrets/examples/cli.py eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo
```


## Examples

To use the examples, after doing the pip install just `git clone` the repo and `cd` into the `badsecrets` directory:

```
git clone https://github.com/blacklanternsecurity/badsecrets.git
cd badsecrets
```

The commands in the example section below assume you are in this directory.

If you are using the Badsecrets [BBOT](https://github.com/blacklanternsecurity/bbot) module, you don't need to do anything else - BBOT will install the package for you.


### cli.py

Bad secrets includes an [example CLI](https://github.com/blacklanternsecurity/badsecrets/blob/dev/badsecrets/examples/cli.py) for convenience when manually checking secrets. As mentioned above, it is also accessible by just executing `badsecrets`, after a successful pip install.

#### Usage

```
usage: badsecrets [-h] [-nc] [-u URL] [-nh] [-c CUSTOM_SECRETS] [-p PROXY] [-a USER_AGENT] [product ...]

Check cryptographic products against badsecrets library

positional arguments:
  product               Cryptographic product to check for known secrets

options:
  -h, --help            show this help message and exit
  -nc, --no-color       Disable color message in the console
  -u URL, --url URL     Use URL Mode. Specified the URL of the page to access and attempt to check for secrets
  -nh, --no-hashcat     Skip the check for compatable hashcat commands when secret isn't found
  -c CUSTOM_SECRETS, --custom-secrets CUSTOM_SECRETS
                        include a custom secrets file to load along with the default secrets
  -p PROXY, --proxy PROXY
                        In URL mode, Optionally specify an HTTP proxy
  -a USER_AGENT, --user-agent USER_AGENT
                        In URL mode, Optionally set a custom user-agent

```

* Basic usage - checking a crytographic product for a known secret (against all modules):

```bash
badsecrets eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo
```
It has a URL mode, which will connect to a target and attempt to carve for cryptographic products and check any it finds against all modules. 

* URL Mode

```bash
badsecrets --url http://example.com/contains_bad_secret.html
```

You can also set a custom user-agent with `--user-agent "user-agent string"` or a proxy with `--proxy http://127.0.0.1` in this mode.

Example output:

```bash
$ badsecrets eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo

 __ )              |                                |         
 __ \    _` |   _` |   __|   _ \   __|   __|   _ \  __|   __| 
 |   |  (   |  (   | \__ \   __/  (     |      __/  |   \__ \ 
____/  \__,_| \__,_| ____/ \___| \___| _|    \___| \__| ____/ 

v0.3.337

Known Secret Found!

Detecting Module: Generic_JWT

Product Type: JSON Web Token (JWT)
Product: eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo
Secret Type: HMAC/RSA Key
Location: manual
Secret: 1234
Details: {'Issuer': 'Issuer', 'Username': 'BadSecrets', 'exp': 1593133483, 'iat': 1466903083, 'jwt_headers': {'alg': 'HS256'}}
```

* Hashcat

By default, when a secret is NOT found, the provided product will be checked for potential hashcat matches. If there is a match, a nearly complete hashcat command will be produced (potentially) suitable for cracking the product via hashcat. This can let you get those keys that may not be known, but are weak and still crackable. Not all modules are capable of producing hashcat output. This behavior can be disabled with the `--no-hashcat` option.

```
badsecrets eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.qvkcSLMQPAQdEuRFv0h3aQIRpTfaI57GjXLOWI_6NaE
```

Example output:

```
 __ )              |                                |         
 __ \    _` |   _` |   __|   _ \   __|   __|   _ \  __|   __| 
 |   |  (   |  (   | \__ \   __/  (     |      __/  |   \__ \ 
____/  \__,_| \__,_| ____/ \___| \___| _|    \___| \__| ____/ 

v0.3.337

No secrets found :(

Potential matching hashcat commands:

Module: [Flask_SignedCookies] Flask Signed Cookie Command: [hashcat -m 29100 -a 0 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.qvkcSLMQPAQdEuRFv0h3aQIRpTfaI57GjXLOWI_6NaE <dictionary_file>]
Module: [Generic_JWT] JSON Web Token (JWT) Algorithm: HS256 Command: [hashcat -m 16500 -a 0 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.qvkcSLMQPAQdEuRFv0h3aQIRpTfaI57GjXLOWI_6NaE  <dictionary_file>]
```
* Custom Secret Lists

It is possible to specify a file containing additional secrets. These will be added to the default lists when the check is performed. This is accomplished with the `-c` / `--custom-secrets` flag. The provided value must be a valid file. There is a 100k size limit on the provided file.

```
badsecrets eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.vKxsE0u-TrpoMQ5zmBv1_I-NXSgouq6iZJWMHbHSmgY -c test.txt
```

Example output:

```
 __ )              |                                |         
 __ \    _` |   _` |   __|   _ \   __|   __|   _ \  __|   __| 
 |   |  (   |  (   | \__ \   __/  (     |      __/  |   \__ \ 
____/  \__,_| \__,_| ____/ \___| \___| _|    \___| \__| ____/ 

v0.3.337

Including custom secrets list [test.txt]

Known Secret Found!

Detecting Module: Generic_JWT

Product Type: JSON Web Token (JWT)
Product: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.vKxsE0u-TrpoMQ5zmBv1_I-NXSgouq6iZJWMHbHSmgY
Secret Type: HMAC/RSA Key
Location: manual
Secret: fake123
Details: {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022, 'jwt_headers': {'alg': 'HS256', 'typ': 'JWT'}}
```

### blacklist3r.py

*Note: This is now obsolete, since `cli.py` is now capable of handling machinekeys/generator values. It will remain included for reference.*
*Example: `badsecrets KLox5XeGYfb7Lo8zFzr1YepUagXuixcxX55lpFht+rrW6VGheZi831vdusH6DCMfxIhsLG1EPU3OuPvqN2XBc/fj0ew15TQ1zBmmKWJVns4= AAAAAAAA`*

Bad secrets includes a [fully functional CLI example](https://github.com/blacklanternsecurity/badsecrets/blob/dev/badsecrets/examples/blacklist3r.py) which replicates the functionality of [blacklist3r](https://github.com/NotSoSecure/Blacklist3r) in python badsecrets/examples/blacklist3r. 


```bash
python ./badsecrets/examples/blacklist3r.py --url http://vulnerablesite/vulnerablepage.aspx
python ./badsecrets/examples/blacklist3r.py --viewstate /wEPDwUJODExMDE5NzY5ZGQMKS6jehX5HkJgXxrPh09vumNTKQ== --generator EDD8C9AE
```

### telerik_knownkey.py

Fully functional CLI example for identifying known Telerik Hash keys (`Telerik.Upload.ConfigurationHashKey`) and Encryption keys (`Telerik.Web.UI.DialogParametersEncryptionKey`) used with Telerik DialogHandler instances for Post-2017 versions (those patched for CVE-2017-9248), and brute-forcing version / generating exploitation DialogParameters values.

Currently, this appears to be the only tool capable of building a working exploit URL for "patched" versions of Telerik.

```bash
python ./badsecrets/examples/telerik_knownkey.py --url http://vulnerablesite/Telerik.Web.UI.DialogHandler.aspx
```
Optionally include ASP.NET MachineKeys with --machine-keys (Will SIGNIFICANTLY increase brute-forcing time)

*Update: This utility will now, in addition to the `Telerik.Web.UI.DialogHandler.aspx` endpoint, also detect known `Telerik.AsyncUpload.ConfigurationEncryptionKey` keys in use via the `Telerik.Web.UI.WebResource.axd` endpoint.*

```bash
python ./badsecrets/examples/telerik_knownkey.py --url http://vulnerablesite/Telerik.Web.UI.WebResource.axd
```

*With a pip install, can now be run directly via the `telerik-knownkey` command*
```bash
python telerik-knownkey --url http://vulnerablesite/Telerik.Web.UI.WebResource.axd
```

### symfony_knownkey.py

Brute-force detection of Symfony known secret key when "\_fragment" URLs are enabled, even when no example URL containing a hash can be located. [Relevent Blog Post](https://www.ambionics.io/blog/symfony-secret-fragment).

```bash
python ./badsecrets/examples/symfony_knownkey.py --url https://localhost/
```

*With a pip install, can now be run directly via the `symfony-knownkey` command*
```bash
python symfony-knownkey --url http://vulnerablesite/Telerik.Web.UI.WebResource.axd
```

## BBOT Module

One of the best ways to use Badsecrets, especially for the `ASPNET_Viewstate` and `Jsf_viewstate` modules is with the Badsecrets [BBOT](https://github.com/blacklanternsecurity/bbot) module. This will allow you to easily check across thousands of systems in conjunction with subdomain enummeration. 

```
bbot -f subdomain-enum -m badsecrets -t evil.corp
```

![badsecrets](https://user-images.githubusercontent.com/24899338/227044294-59e0408e-c55f-481a-a494-7ee5dd0a39be.png)


### Basic library usage

#### check_secret

See if a token or other cryptographic product was produced with a known key

```python
from badsecrets import modules_loaded

Django_SignedCookies = modules_loaded["django_signedcookies"]
ASPNET_Viewstate = modules_loaded["aspnet_viewstate"]
Flask_SignedCookies = modules_loaded["flask_signedcookies"]
Peoplesoft_PSToken = modules_loaded["peoplesoft_pstoken"]
Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]
Rails_SecretKeyBase = modules_loaded["rails_secretkeybase"]
Generic_JWT = modules_loaded["generic_jwt"]
Jsf_viewstate = modules_loaded["jsf_viewstate"]
Symfony_SignedURL = modules_loaded["symfony_signedurl"]
Express_SignedCookies_ES = modules_loaded["express_signedcookies_es"]
Express_SignedCookies_CS = modules_loaded["express_signedcookies_cs"]
Laravel_SignedCookies = modules_loaded["laravel_signedcookies"]
ASPNET_Vstate = modules_loaded["aspnet_vstate"]
Rack2_SignedCookies = modules_loaded["rack2_signedcookies"]

x = ASPNET_Viewstate()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("AgF5WuyVO11CsYJ1K5rjyuLXqUGCITSOapG1cYNiriYQ6VTKochMpn8ws4eJRvft81nQIA==","EDD8C9AE")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Telerik_HashKey()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("vpwClvnLODIx9te2vO%2F4e06KzbKkjtwmNnMx09D1Dmau0dPliYzgpqB9MnEqhPNe3fWemQyH25eLULJi8KiYHXeHvjfS1TZAL2o5Gku1gJbLuqusRXZQYTNlU2Aq4twXO0o0CgVUTfknU89iw0ceyaKjSteOhxGvaE3VEDfiKDd8%2B9j9vD3qso0mLMqn%2Btxirc%2FkIq5oBbzOCgMrJjkaPMa2SJpc5QI2amffBJ%2BsAN25VH%2BwabEJXrjRy%2B8NlYCoUQQKrI%2BEzRSdBsiMOxQTD4vz2TCjSKrK5JEeFMTyE7J39MhXFG38Bq%2FZMDO%2FETHHdsBtTTkqzJ2odVArcOzrce3Kt2%2FqgTUPW%2BCjFtkSNmh%2FzlB9BhbxB1kJt1NkNsjywvP9j7PvNoOBJsa8OwpEyrPTT3Gm%2BfhDwtjvwpvN7l7oIfbcERGExAFrAMENOOt4WGlYhF%2F8c9NcDv0Bv3YJrJoGq0rRurXSh9kcwum9nB%2FGWcjPikqTDm6p3Z48hEnQCVuJNkwJwIKEsYxJqCL95IEdX3PzR81zf36uXPlEa3YdeAgM1RD8YGlwlIXnrLhvMbRvQW0W9eoPzE%2FjP68JGUIZc1TwTQusIWjnuVubFTEUMDLfDNk12tMwM9mfnwT8lWFTMjv9pF70W5OtO7gVN%2BOmCxqAuQmScRVExNds%2FF%2FPli4oxRKfgI7FhAaC%2Fu1DopZ6vvBdUq1pBQE66fQ9SnxRTmIClCpULUhNO90ULTpUi9ga2UtBCTzI8z6Sb6qyQ52NopNZMFdrn9orzdP8oqFeyYpF%2BQEtbp%2F5AMENkFkWUxHZn8NoSlO8P6G6ubSyDdY4QJPaFS4FxNhhm85WlZC9xfEZ1AGSSBOu9JJVYiKxXnL1yYLqrlWp5mfBHZeUBwEa%2FMjGxZEVYDhXo4PiU0jxN7fYmjaobp3DSgA5H3BcFuNG5d8CUnOlQcEie5b%2BUHOpI9zAk7qcuEUXbaZ5Mvh0t2jXCRALRKYDyBdbHlWAFo10dTIM6L3aSTM5uEz9%2FalXLXoWlMo7dTDpuO5bBfTq7YkoPExL3g3JJX47UhuLq85i3%2Bzxfvd7r%2Fmid69kbD3PnX%2Bj0QxaiShhyOZg6jl1HMeRRXvZap3FPCIfxbCf7j2TRqB5gYefBIIdGYjrdiL6HS8SbjXcROMwh2Fxnt505X4jmkmDcGmneU3z%2B84TSSFewcSpxGEGvHVkkU4OaT6vyFwsxCmdrR187tQZ7gn3ZkAiTps%2FfOPcL5QWXja06Z%2FHT3zboq6Hj9v9NBHzpC1eAK0YN8r4V2UMI3P0%2FsIPQYXhovoeLjJwq6snKZTX37ulE1mbS1uOY%2BZrvFYbLN5DdNL%2B%2Bl%2F%2BcWIpc0RSYBLo19xHpKeoeLjU2sxaYzK%2B92D4zKANdPPvsHPqJD1Y%2FBwCL%2FfZKaJfRK9Bj09ez1Z1ixTEKjIRCwuxijnJGq33faZchbwpMPpTfv43jEriGwXwoqOo9Mbj9ggPAil7O81XZxNT4vv4RoxXTN93V100rt3ClXauL%2BlNID%2BseN2CEZZqnygpTDf2an%2FVsmJGJJcc0goW3l43mhx2U79zeuT94cFPGpvITEbMtjmuNsUbOBuw6nqm5rAs%2FxjIsDRqfQxGQWfS0kuwuU6RRmiME2Ps0NrBENIbZzcbgw6%2BRIwClWkvEG%2BK%2FPdcAdfmRkAPWUNadxnhjeU2jNnzI1yYNIOhziUBPxgFEcAT45E7rWvf8ghT08HZvphzytPmD%2FxuvJaDdRgb6a30TjSpa7i%2BEHkIMxM5eH1kiwhN6xkTcBsJ87epGdFRWKhTGKYwCbaYid1nRs7%2BvQEU7MRYghok8KMTueELipohm3otuKo8V4a7w4TgTSBvPE%2BLPLJRwhM8KcjGlcpzF1NowRo6zeJJhbdPpouUH2NJzDcp7P4uUuUB9Cxt9B986My6zDnz1eyBvRMzj7TABfmfPFPoY3RfzBUzDm%2FA9lOGsM6d9WZj2CH0WxqiLDGmP1Ts9DWX%2FsYyqEGK5R1Xpnp7kRIarPtYliecp50ZIH6nqSkoCBllMCCE6JN%2BdoXobTpulALdmQV0%2Bppv%2FAjzIJrTHgX7jwRGEAeRgAxTomtemmIaH5NtV7xt8XS%2BqwghdJl1D06%2FWhpMtJ1%2FoQGoJ0%2F7ChYyefyAfsiQNWsO66UNVyl71RVPwATnbRO5K5mtxn0M2wuXXpAARNh6pQTcVX%2FTJ4jmosyKwhI6I870NEOsSaWlKVyOdb97C3Bt0pvzq8BagV5FMsNtJKmqIIM0HRkMkalIyfow9iS%2B5xGN5eKM8NE4E6hO4CvmpG%2BH2xFHTSNzloV0FjLdDmj5UfMjhUuEb3rkKK1bGAVaaherp6Ai6N4YJQzh%2FDdpo6al95EZN2OYolzxitgDgsWVGhMvddyQTwnRqRY04hdVJTwdhi4TiCPbLJ1Wcty2ozy6VDs4w77EOAQ5JnxUmDVPA3vXmADJZR0hIJEsuxXfYg%2BRIdV4fzGunV4%2B9jpiyM9G11iiesURK82o%2BdcG7FaCkkun2K2bvD6qGcL61uhoxNeLVpAxjrRjaEBrXsexZ9rExpMlFD8e3NM%2B0K0LQJvdEvpWYS5UTG9cAbNAzBs%3DpDsPXFGf2lEMcyGaK1ouARHUfqU0fzkeVwjXU9ORI%2Fs%3D")
if r:  
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Flask_SignedCookies()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Peoplesoft_PSToken()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABSpxUdcNT67zqSLW1wY5/FHQd1U6mgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Django_SignedCookies()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret(".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCIRIpvaTZRQMM3-UypscEN57ECtXis")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Rails_SecretKeyBase()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("dUEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWLS15L00xME1nVFp2ZTlmUWcxZVlpelpnPT0=--7efe7919a5210cfd1ac4c6228e3ff82c0600d841")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Generic_JWT()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")
    
    
x = Telerik_EncryptionKey()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("owOnMokk%2F4N7IMo6gznRP56OYIT34dZ1Bh0KBbXlFgztgiNNEBYrgWRYDBkDlX8BIFYBcBztC3NMwoT%2FtNF%2Ff2nCsA37ORIgfBem1foENqumZvmcTpQuoiXXbMWW8oDjs270y6LDAmHhCRsl4Itox4NSBwDgMIOsoMhNrMigV7o7jlgU16L3ezISSmVqFektKmu9qATIXme63u4IKk9UL%2BGP%2Fk3NPv9MsTEVH1wMEf4MApH5KfWBX96TRIc9nlp3IE5BEWNMvI1Gd%2BWXbY5cSY%2Buey2mXQ%2BAFuXAernruJDm%2BxK8ZZ09TNsn5UREutvNtFRrePA8tz3r7p14yG756E0vrU7uBz5TQlTPNUeN3shdxlMK5Qzw1EqxRZmjhaRpMN0YZgmjIpzFgrTnT0%2Bo0f6keaL8Z9TY8vJN8%2BEUPoq%2F7AJiHKm1C8GNc3woVzs5mJKZxMUP398HwGTDv9KSwwkSpHeXFsZofbaWyG0WuNldHNzM%2FgyWMsnGxY6S086%2F477xEQkWdWG5UE%2FowesockebyTTEn3%2B%2FqiVy%2FIOxXvMpvrLel5nVY%2FSouHp5n2URRyRsfo%2B%2BOXJZo7yxKQoYBSSkmxdehJqKJmbgxNp5Ew8m89xAS5g99Hzzg382%2BxFp8yoDVZMOiTEuw0J%2B4G6KizqRW9cis%2FELd0aDE1V7TUuJnFrX%2BlCLOiv100tKpeJ0ePMOYrmvSn0wx7JhswNuj%2BgdKqvCnMSLakGWiOHxu5m9Qqdm3s5sk7nsaxMkh8IqV%2BSzB9A2K1kYEUlY40II1Wun67OSdLlYfdCFQk4ED0N%2BV4kES%2F1xpGiaPhxjboFiiV%2BkvCyJfkuotYuN%2B42CqFyAyepXPA%2BR5jVSThT6OIN2n1UahUnrD%2BwKKGMA9QpVPTSiGLen2KSnJtXISbrl2%2BA2AnQNH%2BMEwYVNjseM0%2BAosbgVfNde2ukMyugo%2FRfrRM27cbdVlE0ms0uXhlgKAYJ2ZN54w1tPWhpGxvZtB0keWpZan0YPh8CBgzsAIMa04HMYLCtgUTqxKqANoKXSy7VIJUzg3fl%2F2WUELjpXK9gRcgexNWDNB1E0rHd9PUo0PvpB4fxSrRpb1LRryipqsuoJ8mrpOVrVMvjracBvtoykK3GrN%2FDUlXkSG%2FAeBQN7HwDJ9QPi3AtEOohp78Op3nmbItXo7IJUSjzBNzUYR8YPj6Ud7Fje9LZSwMBngvgx%2BOKy6HsV4ofOAU2%2FK1%2BfxI0KkCeoSso9NJHWgBD7ijfXUa1Hrc%2FuNU3mTlSSVp3VStQrJbQCkr4paaHYWeeO4pRZCDSBNUzs9qq3TDePwpEQc4QROrw5htdniRk26lFIFm%2Fzk2nC77Pg%2BrkRC1W%2BlRv0lyXsmXVBCe8F1szpWXHCxHNAJwKH%2FBb%2BV1k6AXFXVWPW5vADbXUvRu0s6KLaqu6a0KCB7dt3K2Ni%2FI6O%2FmISYXzknbMrwwakNfajbRF2ibodgR9R9xvoCoCXa3ka7%2Fejr%2BmsZ2HvPKUAffd2fNIWCQrejfpuIoOWiYx6ufN8E41HetCbYfvsI6JQfPOEdOYWI2px%2BLdfO3Nybq99%2BRSQOhjNZakBP54ozlCUfwgpLOmTBwsswZexv1RK5MIi8%2FWtjlJ%2FKjkYxdkFUlwggGS2xDwzcyl2%2FakNCQ5YmxjU8cRY7jZQRMo%2F8uTw5qa2MNZPaQGI18uRgr0i%2FTX3t57fJYCpMLXSaUKIdO7O%2FCQhIyGTS6KrPN%2B3%2FgUb%2BPQ1viGhpnWfGEYF9vhIlK57z8G8G82UQ3DpttD7M8mQ0KsmCOq75ECx9CWrWGk51vADlm%2BLEZ5oWjVMs%2FThki40B7tL7gzFrBuQksWXYeubMzZfFo4ZQ49di4wupHG5kRsyL2fJUzgpaLDP%2BSe6%2FjCnc52C7lZ3Ls0cHJVf9HRwDNXWM%2B4h8donNy5637QWK%2BV7mlH%2FL4xBZCfU9l6sIz%2FWHMtRaQprEem6a%2FRwPRDBiP65I2EwZLKGY8I%2F1uXJncwC8egLu82JY9maweI0VmJSmRcTf0evxqqe7vc9MqpsUlpSVNh4bFnxVIo5E4PGX70kVaTFe0vu1YdGKmFX5PLvkmWIf%2FnwfgPMqYsa0%2F09trboJ5LGDEQRXSBb7ldG%2FwLdOiqocYKAb91SMpn1fXVPBgkPM27QZxHnSAmWVbJR2%2FIhO%2BIVNzkgFAJlptiEPPPTxuBh%2BTT7CaIQE3oZbbJeQKvRkrt4bawTCOzciU%2F1zFGxubTJTSyInjQ8%2F1tVo7KjnxPKqGSfwZQN%2FeWL6R%2FpvCb%2BE6D4pdyczoJRUWsSNXNnA7QrdjgGNWhyOMiKvkDf3RD4mrXbul18WYVTsLyp0hvQsbdwBWOh7VlwfrWdy%2BklsttFi%2B%2BadKR7DbwjLTcxvdNpTx1WJhXROR8jwW26VEYSXPVqWnYvfyZo4DojKHMSDMbAakbuSJdkGP1d5w0AYbKlAcVQOqp9hbAvfwwLy4ErdIsOg0YEeCcnQVRAXwaCI9JvWWmM%2FzYJzE3X45A6lU9Pe7TAbft810MYh7lmV6Keb5HI6qXFiD%2B8khBZqi%2FsK6485k0a86aWLxOb4Eqnoc41x%2BYPv5CWfvP6cebsENo%3D%2BIUg0f64C4y77N4FZ6C82m5wMpvDQIHqx0ZFIHLhwMg%3D")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")
    
x = Jsf_viewstate()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RSCWwjtJcZNbWPcvPqL5zzfl03DoeMZfGGX7a9PSv+fUT8MAeKNouAGj1dZuO8srXt8xZIGg+wPCWWCzcX6IhWOtgWUwiXeSojCDTKXklsYt+kzlVbk5wOsXvb2lTJoO0Q==")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")


x = Symfony_SignedURL()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=Xnsvx/yLVQaimEd1CfepgH0rEXr422JnRSn/uaCE3gs=")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")


x = Express_SignedCookies_ES()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Express_SignedCookies_CS()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("foo=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==","zOQU7v7aTe_3zu7tnVuHi1MJ2DU")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")


x = Laravel_SignedCookies()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("eyJpdiI6IlhlNTZ2UjZUQWZKVHdIcG9nZFkwcGc9PSIsInZhbHVlIjoiRlUvY2grU1F1b01lSXdveXJ0T3N1WGJqeVVmZlNRQjNVOWxiSzljL1Z3RDhqYUdDbjZxMU9oSThWRzExT0YvUmthVzVKRE9kL0RvTEw1cFRhQkphOGw4S2loV1ZrMkkwTHd4am9sZkJQd2VCZ3R0VlFSeFo3ay9wTlBMb3lLSG8iLCJtYWMiOiJkMmU3M2ExNDc2NTc5YjAwMGMwMTdkYTQ1NThkMjRkNTY2YTE4OTg2MzY5MzE5NGZmOTM4YWVjOGZmMWU4NTk2IiwidGFnIjoiIn0%3D")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")


x = ASPNET_Vstate()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("H4sIAAAAAAAEAPvPyJ/Cz8ppZGpgaWpgZmmYAgAAmCJNEQAAAA==")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")

x = Rack2_SignedCookies()
print(f"###{str(x.__class__.__name__)}###")
r = x.check_secret("BAh7B0kiD3Nlc3Npb25faWQGOgZFVG86HVJhY2s6OlNlc3Npb246OlNlc3Npb25JZAY6D0BwdWJsaWNfaWRJIkU5YmI3ZDUyODUyNTAwMDYzMGE2NjMxYTA5MjBlMjYzMzFmOGE0MjBhNTdhYWIxNzVkZTFmM2FjMDQ3NmI1NDQzBjsARkkiCmNvdW50BjsARmkG--3a983fbc58911c5266d7748a6a55165f74d412f4")
if r:
    print(r)
else:
    print("KEY NOT FOUND :(")
```

#### Carve
An additional layer of abstraction above check_secret, which accepts a python httpx.response object or a string

```python
import httpx
from badsecrets import modules_loaded
Telerik_HashKey = modules_loaded["telerik_hashkey"]

x = Telerik_HashKey()

# Create an HTTP client that ignores certificate errors
with httpx.Client() as client:
    res = client.get("http://example.com/", verify=False)
    r_list = x.carve(requests_response=res)
    print(r_list)

telerik_dialogparameters_sample = """
Sys.Application.add_init(function() {
    $create(Telerik.Web.UI.RadDialogOpener, {"_dialogDefinitions":{"ImageManager":{"SerializedParameters":"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","Width":"770px","Height":"588px","Title":"Image Manager"}
"""
    
r_list = x.carve(body=telerik_dialogparameters_sample)
print(r_list)

```
### Check all modules at once

```python
from badsecrets.base import check_all_modules

tests = [
    "yJrdyJV6tkmHLII2uDq1Sl509UeDg9xGI4u3tb6dm9BQS4wD08KTkyXKST4PeQs00giqSA==",
    "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA",
    "vpwClvnLODIx9te2vO%2F4e06KzbKkjtwmNnMx09D1Dmau0dPliYzgpqB9MnEqhPNe3fWemQyH25eLULJi8KiYHXeHvjfS1TZAL2o5Gku1gJbLuqusRXZQYTNlU2Aq4twXO0o0CgVUTfknU89iw0ceyaKjSteOhxGvaE3VEDfiKDd8%2B9j9vD3qso0mLMqn%2Btxirc%2FkIq5oBbzOCgMrJjkaPMa2SJpc5QI2amffBJ%2BsAN25VH%2BwabEJXrjRy%2B8NlYCoUQQKrI%2BEzRSdBsiMOxQTD4vz2TCjSKrK5JEeFMTyE7J39MhXFG38Bq%2FZMDO%2FETHHdsBtTTkqzJ2odVArcOzrce3Kt2%2FqgTUPW%2BCjFtkSNmh%2FzlB9BhbxB1kJt1NkNsjywvP9j7PvNoOBJsa8OwpEyrPTT3Gm%2BfhDwtjvwpvN7l7oIfbcERGExAFrAMENOOt4WGlYhF%2F8c9NcDv0Bv3YJrJoGq0rRurXSh9kcwum9nB%2FGWcjPikqTDm6p3Z48hEnQCVuJNkwJwIKEsYxJqCL95IEdX3PzR81zf36uXPlEa3YdeAgM1RD8YGlwlIXnrLhvMbRvQW0W9eoPzE%2FjP68JGUIZc1TwTQusIWjnuVubFTEUMDLfDNk12tMwM9mfnwT8lWFTMjv9pF70W5OtO7gVN%2BOmCxqAuQmScRVExNds%2FF%2FPli4oxRKfgI7FhAaC%2Fu1DopZ6vvBdUq1pBQE66fQ9SnxRTmIClCpULUhNO90ULTpUi9ga2UtBCTzI8z6Sb6qyQ52NopNZMFdrn9orzdP8oqFeyYpF%2BQEtbp%2F5AMENkFkWUxHZn8NoSlO8P6G6ubSyDdY4QJPaFS4FxNhhm85WlZC9xfEZ1AGSSBOu9JJVYiKxXnL1yYLqrlWp5mfBHZeUBwEa%2FMjGxZEVYDhXo4PiU0jxN7fYmjaobp3DSgA5H3BcFuNG5d8CUnOlQcEie5b%2BUHOpI9zAk7qcuEUXbaZ5Mvh0t2jXCRALRKYDyBdbHlWAFo10dTIM6L3aSTM5uEz9%2FalXLXoWlMo7dTDpuO5bBfTq7YkoPExL3g3JJX47UhuLq85i3%2Bzxfvd7r%2Fmid69kbD3PnX%2Bj0QxaiShhyOZg6jl1HMeRRXvZap3FPCIfxbCf7j2TRqB5gYefBIIdGYjrdiL6HS8SbjXcROMwh2Fxnt505X4jmkmDcGmneU3z%2B84TSSFewcSpxGEGvHVkkU4OaT6vyFwsxCmdrR187tQZ7gn3ZkAiTps%2FfOPcL5QWXja06Z%2FHT3zboq6Hj9v9NBHzpC1eAK0YN8r4V2UMI3P0%2FsIPQYXhovoeLjJwq6snKZTX37ulE1mbS1uOY%2BZrvFYbLN5DdNL%2B%2Bl%2F%2BcWIpc0RSYBLo19xHpKeoeLjU2sxaYzK%2B92D4zKANdPPvsHPqJD1Y%2FBwCL%2FfZKaJfRK9Bj09ez1Z1ixTEKjIRCwuxijnJGq33faZchbwpMPpTfv43jEriGwXwoqOo9Mbj9ggPAil7O81XZxNT4vv4RoxXTN93V100rt3ClXauL%2BlNID%2BseN2CEZZqnygpTDf2an%2FVsmJGJJcc0goW3l43mhx2U79zeuT94cFPGpvITEbMtjmuNsUbOBuw6nqm5rAs%2FxjIsDRqfQxGQWfS0kuwuU6RRmiME2Ps0NrBENIbZzcbgw6%2BRIwClWkvEG%2BK%2FPdcAdfmRkAPWUNadxnhjeU2jNnzI1yYNIOhziUBPxgFEcAT45E7rWvf8ghT08HZvphzytPmD%2FxuvJaDdRgb6a30TjSpa7i%2BEHkIMxM5eH1kiwhN6xkTcBsJ87epGdFRWKhTGKYwCbaYid1nRs7%2BvQEU7MRYghok8KMTueELipohm3otuKo8V4a7w4TgTSBvPE%2BLPLJRwhM8KcjGlcpzF1NowRo6zeJJhbdPpouUH2NJzDcp7P4uUuUB9Cxt9B986My6zDnz1eyBvRMzj7TABfmfPFPoY3RfzBUzDm%2FA9lOGsM6d9WZj2CH0WxqiLDGmP1Ts9DWX%2FsYyqEGK5R1Xpnp7kRIarPtYliecp50ZIH6nqSkoCBllMCCE6JN%2BdoXobTpulALdmQV0%2Bppv%2FAjzIJrTHgX7jwRGEAeRgAxTomtemmIaH5NtV7xt8XS%2BqwghdJl1D06%2FWhpMtJ1%2FoQGoJ0%2F7ChYyefyAfsiQNWsO66UNVyl71RVPwATnbRO5K5mtxn0M2wuXXpAARNh6pQTcVX%2FTJ4jmosyKwhI6I870NEOsSaWlKVyOdb97C3Bt0pvzq8BagV5FMsNtJKmqIIM0HRkMkalIyfow9iS%2B5xGN5eKM8NE4E6hO4CvmpG%2BH2xFHTSNzloV0FjLdDmj5UfMjhUuEb3rkKK1bGAVaaherp6Ai6N4YJQzh%2FDdpo6al95EZN2OYolzxitgDgsWVGhMvddyQTwnRqRY04hdVJTwdhi4TiCPbLJ1Wcty2ozy6VDs4w77EOAQ5JnxUmDVPA3vXmADJZR0hIJEsuxXfYg%2BRIdV4fzGunV4%2B9jpiyM9G11iiesURK82o%2BdcG7FaCkkun2K2bvD6qGcL61uhoxNeLVpAxjrRjaEBrXsexZ9rExpMlFD8e3NM%2B0K0LQJvdEvpWYS5UTG9cAbNAzBs%3DpDsPXFGf2lEMcyGaK1ouARHUfqU0fzkeVwjXU9ORI%2Fs%3D",
    "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABRhZGwcBykRPNQv++kTK0KePPqVVGgAAAAFAFNkYXRhXHicHYc7DkBQAATnIUqVa3jxLRzApxJBrxA18bmdw1l2k9nZG/Bcxxjt4/An3NnYOVlZOMRL7ld0NAQ9IzUTMy0DeUpMqkYkso+ZGFNiKbRW//Pyb0Guzwtozw4Q",
    ".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCIRIpvaTZRQMM3-UypscEN57ECtXis",
    "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo",
    "dUEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWLS15L00xME1nVFp2ZTlmUWcxZVlpelpnPT0=--7efe7919a5210cfd1ac4c6228e3ff82c0600d841",
    "https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=Xnsvx/yLVQaimEd1CfepgH0rEXr422JnRSn/uaCE3gs=",
    "s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc"
]

for test in tests:
    r = check_all_modules(test)
    if r:
        print(r)
    else:
        print("Key not found!")
```


### Carve all modules at once
```python
import httpx
from badsecrets.base import carve_all_modules
    
### using python httpx response object

# Create an HTTP client that ignores certificate errors
with httpx.Client(verify=False) as client:
    res = client.get("http://example.com/")
    r_list = carve_all_modules(requests_response=res)
    print(r_list)

### Using string

carve_source_text = """
    <html>
<head>
<title>Test</title>
</head>
<body>
<p>Some text</p>
<div class="JWT_IN_PAGE">
<p>eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo</p>
</div>
</body>
</html>
"""

r_list = carve_all_modules(body=carve_source_text)
print(r_list)

```

### Contributions

Nothing would make us happier than getting a pull request with a new module! But the easiest way to contribute would be helping to populate our word lists! If you find publicly available keys help us make Badsecrets more useful by submitting a pull request to add them.

Requests for modules are always very welcome as well!

### Planned Modules and Future Development

- ~~Laravel~~
- ~~Express~~
- Research into network devices with default keys that are detectable via a cryptographic product (For example, Palo Alto Global Protect default masterkeys)

