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
        callbacks.setExtensionName("Url Location Scan")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def doPassiveScan(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()
        reqParameters = self._helpers.analyzeRequest(request).getParameters()
        for parameter in reqParameters:
            parameterName, parameterValue, parameterType = parameter.getName(), parameter.getValue(), parameter.getType()
            print(parameterName, parameterValue, parameterType)
            pyadload = "http://www.baidu.com"
            if parameterType != 2 :
                newParameter = self._helpers.buildParameter(parameterName, pyadload, parameterType)
                newRequest = self._helpers.updateParameter(request, newParameter)
                res = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),newRequest)
                response = res.getResponse()
                analyze_response = self._helpers.analyzeResponse(response)
                reheaders = analyze_response.getHeaders()
                for re_header in reheaders :
                    if re_header.startswith("location:") :
                        location = re_header
                st_code = analyze_response.getStatusCode()
                print(location)
                if st_code == 302 and "www.baidu.com" in str(location) :
                    issue =  CustomScanIssue(baseRequestResponse.getHttpService(),self._helpers.analyzeRequest(res).getUrl(),[self._callbacks.applyMarkers(res, None, None)],
                        "Url Location",
                        'Vuln Parameter is   {}  \n Recvieved data from: {}'.format(str(parameterName),str(pyadload)),
                        "High")
                    self._callbacks.addScanIssue(issue)

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
