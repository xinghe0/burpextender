from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IScanIssue

import re
# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API

print '+--- by xinghe ---+'

class BurpExtender(IBurpExtender, IHttpListener):

    # define registerExtenderCallbacks: From IBurpExtender Interface 
    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # set our extension name that will display in Extender Tab
        self._callbacks.setExtensionName("Unauthorized Access Scan")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if messageIsRequest :
            newlen = ""
            request = messageInfo.getRequest()
            analyzedRequest = self._helpers.analyzeResponse(request) 
            headers = analyzedRequest.getHeaders()
            new_headers = []
            if "Cookie" in str(headers) :
                print("Found cokie")
                for header in headers:
                    if header.startswith("Cookie:"):
                        new_headers.append(header.replace(header,'Cookie: '))
                    else:
                        new_headers.append(header)
                #print(new_headers)
                newMessage = self._helpers.buildHttpMessage(new_headers, None)
                global res
                res = self._callbacks.makeHttpRequest(messageInfo.getHttpService(),newMessage)
                response = res.getResponse()
                analyze_response = self._helpers.analyzeResponse(response)
                len_responses = analyze_response.getHeaders()
                for len_response in len_responses:
                    if len_response.startswith("Content-Length:"):
                        global newlen
                        newlen = len_response
                        #print(len_response)
            else :
                print("no Found cookie")
                pass
        else :
            #print(newlen)
            oldrespons = messageInfo.getResponse()               
            oldanalyze_response = self._helpers.analyzeResponse(oldrespons)
            oldheaders = oldanalyze_response.getHeaders()
            for oldheader in oldheaders:
                if oldheader.startswith("Content-Length:"):
                    #print(newlen,request_content)
                    if oldheader == newlen:
                        print("Found vuln")
                        issue =  CustomScanIssue(messageInfo.getHttpService(),self._helpers.analyzeRequest(res).getUrl(),[self._callbacks.applyMarkers(res, None, None)],
                            "Unauthorized Access Scan",
                            'Unauthorized Access Vuln ',
                            "High")
                        self._callbacks.addScanIssue(issue)
                    else :
                        print("no Found vuln")


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getUrl() == newIssue.getUrl():
            return 0

        return 0


class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
                