import urllib2
from java.awt import BorderLayout
from java.awt import Component
from java.awt import Dimension
from java.util import ArrayList
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JTable
from javax.swing.table import DefaultTableModel
from burp import IBurpExtender
from burp import ITab
from burp import IScannerCheck

class BurpExtender(IBurpExtender, ITab, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     NacosScan")
        print("[+]     Author:   yangyanglo")
        print("[+] #####################################\r\n\r\n")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # set up extension
        callbacks.setExtensionName("NacosScan")
        callbacks.addSuiteTab(self)
        callbacks.registerScannerCheck(self)


    def getTabCaption(self):
        return "NacosScan"

    def getUiComponent(self):
        self._table = JTable(DefaultTableModel(["Index", "URL", "REALURL"], 0))
        # self._table.getModel().addRow([1, "test"])
        scroll_pane = JScrollPane(self._table)
        scroll_pane.setPreferredSize(Dimension(800, 400))

        self._main_panel = JPanel(BorderLayout())
        self._main_panel.add(scroll_pane, BorderLayout.CENTER)

        return self._main_panel

    def log(self, message):
        self._callbacks.printOutput(message + "\n")

    def scan(self, base_url):
        print("scan called!")
        url1 = str(base_url) + "nacos/"
        url2 = str(base_url) + "nacos"

        try:
            # self.log("Testing {0}".format(url))

            # send the request and obtain the response
            req1 = urllib2.urlopen(url1)
            if req1.getcode() == 200:
                print("addRow1")
                self._table.getModel().addRow([self._table.getRowCount(), url1, req1.geturl()])

            req2 = urllib2.urlopen(url2)
            if req2.getcode() == 200:
                print("addRow2")
                self._table.getModel().addRow([self._table.getRowCount(), url2, req2.geturl()])


        except Exception as e:
            self.log("Error: {0}".format(str(e)))
            pass

    def doPassiveScan(self, baseRequestResponse):
        # print("doPassiveScan called!")
        url = baseRequestResponse.getUrl()
        # print("Scanning URL: " + url.toString())
        if url.getPath() == "/":
            print(url)
            self.scan(url)
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0