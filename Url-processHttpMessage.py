from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue


class BurpExtender(IBurpExtender,IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        print('[+]  Url Location Scan')
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Url Location Scan')
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageinfo):
        if toolFlag == 4 :
            if messageIsRequest: 
                request = messageinfo.getRequest()
                reqParameters = self._helpers.analyzeRequest(request).getParameters()
                for parameter in reqParameters:
                    parameterName, parameterValue, parameterType = parameter.getName(), parameter.getValue(), parameter.getType()
                    print(parameterName, parameterValue, parameterType)
                    pyadload = "http://www.baidu.com"
                    if parameterType != 2 :
                        newParameter = self._helpers.buildParameter(parameterName, pyadload, parameterType)
                        newRequest = self._helpers.updateParameter(request, newParameter)
                        res = self._callbacks.makeHttpRequest(messageinfo.getHttpService(),newRequest)
                        response = res.getResponse()
                        analyze_response = self._helpers.analyzeResponse(response)
                        st_code = analyze_response.getStatusCode()
                        if st_code == 302:
                            issue =  CustomScanIssue(messageinfo.getHttpService(),self._helpers.analyzeRequest(res).getUrl(),[self._callbacks.applyMarkers(res, None, None)],
                                "Url Location",
                                'Vuln Parameter is   {}  \n Recvieved data from: {}'.format(str(parameterName),str(pyadload)),
                                "High")
                            self._callbacks.addScanIssue(issue)


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
