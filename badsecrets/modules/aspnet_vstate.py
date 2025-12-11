import re
import base64
from crapsecrets.base import CrapsecretsBase
from crapsecrets.modules.aspnet_viewstate import ASPNET_Viewstate,Section
from libs.viewstate.viewstate.viewstate import ViewState

# Reference: https://blog.sorcery.ie/posts/higherlogic_rce/


class ASPNET_vstate(CrapsecretsBase):
    supported_sections = frozenset({Section.BODY})
    requests_response = None
    client = None
    isFromBody = False

    identify_regex = re.compile(r"^(H4sI|eJ(w|x)|QlpoOT|/Td6WFoA|XQAA)[a-zA-Z0-9_/+%=-]+$")
    description = {"product": "ASP.NET Compressed Vstate", "secret": "unprotected", "severity": "CRITICAL"}

    def carve_regex(self):
        return re.compile(r"<input[^>]+__VSTATE\"\s*value=\"([a-zA-Z0-9_/+%=-]+)\"")

    def carve_to_check_secret(self, s, url=None, requests_response=None, isFromBody=False, client=None, commandargs=None):
        self.requests_response = requests_response
        self.isFromBody = isFromBody
        self.cookies = None
        if requests_response:
            self.cookies = requests_response.cookies
        self.client = client
        self.commandargs = commandargs
        
        return self.check_secret(s.groups()[0], url, requests_response)

    def get_product_from_carve(self, regex_search):
        product = regex_search.groups()[0]
        if len(product) == 0:
            return "EMPTY '__VSTATE' FORM FIELD"
        return product

    def check_secret(self, vstate_value, *args):
        if not self.identify(vstate_value):
            return None

        uncompressed = self.attempt_decompress(vstate_value)
        temp_product = vstate_value
        if len(temp_product) > 200:
            temp_product = temp_product[:100] + "..." + temp_product[-10:]
        else:
            temp_product = temp_product

        finalUrl = ""
        if hasattr(self, 'requests_response') and self.requests_response is not None:
                finalUrl = str(self.requests_response.url)
        if uncompressed:
            if ASPNET_Viewstate.valid_preamble(uncompressed):
                is_confirmed = False
                try:
                    vs = ViewState(raw=uncompressed)
                    vs.decode()
                    signature_by_parser = vs.signature
                    if signature_by_parser == None or signature_by_parser == b"":
                        is_confirmed = True
                except:
                    pass
                
                if is_confirmed:
                    r = {"source": temp_product, "info": "ASP.NET Vstate (Confirmed Unprotected)", "URL": finalUrl}
                    self.description["severity"] = "CRITICAL"
                else:
                    r = {"source": temp_product, "info": "ASP.NET Vstate (Potential Unprotected)", "URL": finalUrl}
                    self.description["severity"] = "HIGH"

                return {"secret": "UNPROTECTED", "details": r}
            else:
                result = ASPNET_Viewstate.check_secret(base64.encode(uncompressed), *args)
                if result:
                    return result
                r = {"source": temp_product, "info": "ASP.NET Vstate (Unknown/Encrypted, Compressed)", "URL": finalUrl}
                self.description["severity"] = "INFO"
                return {"secret": "UNKNOWN/ENCRYPTED (compressed)", "details": r}
        else:
            try:
                result = ASPNET_Viewstate.check_secret(vstate_value, *args)
                if result:
                    return result
            except:
                pass

            r = {"source": temp_product, "info": "ASP.NET Vstate (Unknown)", "URL": finalUrl}
            self.description["severity"] = "INFO"
            return {"secret": "UNKNOWN", "details": r}