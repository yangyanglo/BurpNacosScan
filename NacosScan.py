# -*- coding: utf-8 -*-
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
import datetime
from urlparse import urlparse

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
        self._table = JTable(DefaultTableModel(["Index", "URL", "statusCode", "REALURL", "startTime", "endTime"], 0))
        scroll_pane = JScrollPane(self._table)
        scroll_pane.setPreferredSize(Dimension(800, 400))

        self._main_panel = JPanel(BorderLayout())
        self._main_panel.add(scroll_pane, BorderLayout.CENTER)

        return self._main_panel

    def log(self, message):
        self._callbacks.printOutput(message + "\n")

    def scan(self, base_url):
        initial_time = datetime.datetime.now()
        startTime = initial_time.strftime('%Y-%m-%d %H:%M:%S')
        print("scan called!")
        url1 = str(base_url) + "/nacos/"
        url2 = str(base_url) + "/nacos"

        try:
            req1 = urllib2.urlopen(url1)
            if req1.getcode() == 200 or req1.getcode() == 302:
                now = datetime.datetime.now()
                endTime = now.strftime('%Y-%m-%d %H:%M:%S')
                self._table.getModel().addRow([self._table.getRowCount(), url1, str(req1.getcode()), req1.geturl(), str(startTime), str(endTime)])

            opener = urllib2.build_opener(urllib2.HTTPRedirectHandler())
            req2 = opener.open(url2)

            if req2.getcode() == 302 or req2.getcode() == 200:
                self._table.getModel().addRow([self._table.getRowCount(), url2, str(req2.getcode()), req2.geturl(), str(startTime), str(endTime)])

        except Exception as e:
            self.log("Error: {0}".format(str(e)))
            pass
    def __init__(self):
        self.visited_hosts = set()

    def doPassiveScan(self, baseRequestResponse):
        visited_hosts = set()
        url = baseRequestResponse.getUrl()
        host = url.getHost()
        parsed_url = urlparse(str(url))
        protocol = parsed_url.scheme
        netloc = parsed_url.netloc
        full_url = protocol + "://" + netloc
        print(str(full_url))

        if host not in self.visited_hosts:
            self.visited_hosts.add(host)
            self.scan(str(full_url))
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0
