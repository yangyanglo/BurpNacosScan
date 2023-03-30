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

class NoRedirectHandler(urllib2.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response

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
        self._table = JTable(DefaultTableModel(["Index", "URL", "statusCode", "REALURL", "size", "startTime", "endTime"], 0))
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
        # urls = {"/nacos/", "/nacos","/api/swagger-ui.html", "/swagger-ui.html", "/actuator", "/actuator/heapdump"}
        with open('conf.ini', 'r') as f:
            for url in f.readlines():
                full_url = str(base_url) + str(url)

                try:
                    urllib2.install_opener(urllib2.build_opener(NoRedirectHandler))
                    request = urllib2.Request(full_url)
                    response = urllib2.urlopen(request)
                    get_code = response.code
                    response_size = len(response.read())

                    if get_code == 200:
                        now = datetime.datetime.now()
                        endTime = now.strftime('%Y-%m-%d %H:%M:%S')
                        self._table.getModel().addRow([self._table.getRowCount(), str(full_url), str(get_code), str(response.geturl()), str(response_size),str(startTime), str(endTime)])
                    elif get_code == 302:
                        now = datetime.datetime.now()
                        endTime = now.strftime('%Y-%m-%d %H:%M:%S')
                        redirected_url = response.headers.get('Location')
                        self._table.getModel().addRow([self._table.getRowCount(), str(full_url), str(get_code), str(redirected_url), str(response_size),str(startTime), str(endTime)])

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
