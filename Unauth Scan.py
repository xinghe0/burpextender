from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
from array import array


class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        print("[+] by xinghe")
        print("[+] please start enjoy! ")
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Unauthorized Access Scan")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def doPassiveScan(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request) 
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
            res = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),newMessage)
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
        oldrespons = baseRequestResponse.getResponse()               
        oldanalyze_response = self._helpers.analyzeResponse(oldrespons)
        oldheaders = oldanalyze_response.getHeaders()
        for oldheader in oldheaders:
            if oldheader.startswith("Content-Length:"):
                #print(newlen,request_content)
                if oldheader == newlen:
                    print("Found vuln")
                    issue =  CustomScanIssue(baseRequestResponse.getHttpService(),self._helpers.analyzeRequest(res).getUrl(),[self._callbacks.applyMarkers(res, None, None)],
                        "Unauthorized Access Vuln",
                        'Please note that found Unauthorized Access Vuln! not cookie can access',
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
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
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
