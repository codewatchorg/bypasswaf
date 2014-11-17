from burp import IBurpExtender
"""
Name:           Bypass WAF
Version:        0.0.1
Date:           11/16/2014
Author:         Josh Berry - josh.berry@codewatch.org
Github:         https://github.com/codewatchorg/bypasswaf

Description:    This plugin adds headers useful for bypassing some WAF devices when added to a Burp Session Handling rule.

This plugin was inspired by the Bypassing web application firewalls using HTTP headers found here:
http://h30499.www3.hp.com/t5/Fortify-Application-Security/Bypassing-web-application-firewalls-using-HTTP-headers/ba-p/6418366#.VGlMR-90wsd

This article by Fishnet was used to help understand how to build the plugin:
https://www.fishnetsecurity.com/6labs/blog/automatically-adding-new-header-burp

"""

from burp import ISessionHandlingAction
from burp import IParameter

class BurpExtender(IBurpExtender, ISessionHandlingAction):

  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("Bypass WAF")
    callbacks.registerSessionHandlingAction(self)
    return

  def performAction(self, currentRequest, macroItems):
    requestInfo = self._helpers.analyzeRequest(currentRequest)
    headers = requestInfo.getHeaders()
    reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
    
    # WAF Bypass IP
    bypassip = '127.0.0.1'

    # Add WAF Bypass headers
    headers.add('x-originating-IP: '+bypassip)
    headers.add('x-forwarded-for: '+bypassip)
    headers.add('x-remote-IP: '+bypassip)
    headers.add('x-remote-addr: '+bypassip)

    # Build request with bypass headers
    message = self._helpers.buildHttpMessage(headers, reqBody)

    # Update Request with New Header
    currentRequest.setRequest(message)
    return 
