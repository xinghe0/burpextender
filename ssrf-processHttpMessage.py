from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue


class BurpExtender(IBurpExtender,IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        print('[+]  SSRF Scan')
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('SSRF DEBUG')
        # load Burp's CollaboratorClient, use generatePayload() method to creat a dnslog address
        self.collaboratorContext = callbacks.createBurpCollaboratorClientContext()
        self.payload = self.collaboratorContext.generatePayload(True)
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageinfo):
        if toolFlag == self._callbacks.TOOL_PROXY :
            if messageIsRequest: 
                request = messageinfo.getRequest()
                reqParameters = self._helpers.analyzeRequest(request).getParameters()
                for parameter in reqParameters:
                    parameterName, parameterValue, parameterType = parameter.getName(), parameter.getValue(), parameter.getType()
                    print(parameterName, parameterValue, parameterType)
                    parameterValueSSRF = 'http://'+ str(self.payload)
                    newParameter = self._helpers.buildParameter(parameterName, parameterValueSSRF, self._callbacks.TOOL_PROXY)
                    newRequest = self._helpers.updateParameter(request, newParameter)
                    res = self._callbacks.makeHttpRequest(messageinfo.getHttpService(),newRequest)
                    print(messageinfo.getHttpService(),self._helpers.analyzeRequest(res).getUrl())
                    if self.collaboratorContext.fetchCollaboratorInteractionsFor(self.payload):
                        issue =  CustomScanIssue(messageinfo.getHttpService(),self._helpers.analyzeRequest(res).getUrl(),[self._callbacks.applyMarkers(res, None, None)],
                            "SSRF TEST",
                            'Vuln Parameter is   {}  \n Recvieved data from: {}'.format(str(parameterName),str(parameterValueSSRF)),
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