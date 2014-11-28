bypasswaf
=========

Add headers to all Burp requests to bypass some WAF products.  This extension will automatically add the following headers to all requests.

<pre>
  X-Originating-IP: 127.0.0.1
  X-Forwarded-For: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Remote-Addr: 127.0.0.1
</pre>


Usage
=====

Steps include:
<ol>
<li>Add extension to burp</li>
<li>Create a session handling rule in Burp that invokes this extension</li>
<li>Modify the scope to include applicable tools and URLs</li>
<li>Configure the bypass options on the "Bypass WAF" tab</li>
<li>Test away</li>
</ol>

More information can be found at: <a href="https://www.codewatch.org/blog/?p=408" target=_codewatch>https://www.codewatch.org/blog/?p=408</a>


Features
========

All of the features are based on Jason Haddix's work found <a href="http://h30499.www3.hp.com/t5/Fortify-Application-Security/Bypassing-web-application-firewalls-using-HTTP-headers/ba-p/6418366#.VGlMR-90wsd" target=_hp>here</a>, and Ivan Ristic's WAF bypass work found <a href="https://github.com/ironbee/waf-research" target=_git>here</a> and <a href="https://media.blackhat.com/bh-us-12/Briefings/Ristic/BH_US_12_Ristic_Protocol_Level_WP.pdf" target=_blackhat>here</a>.

Bypass WAF contains the following features:

<img src="https://www.codewatch.org/postimg/408/bypasswaf_options.png">

A description of each feature follows:
<ol>
<li>Users can modify the  X-Originating-IP, X-Forwarded-For, X-Remote-IP, X-Remote-Addr headers sent in each request.  This is probably the top bypass technique i the tool.  It isn't unusual for a WAF to be configured to trust itself (127.0.0.1) or an upstream proxy device, which is what this bypass targets.</li>
<li>The "Content-Type" header can remain unchanged in each request, removed from all requests, or by modified to one of the many other options for each request.  Some WAFs will only decode/evaluate requests based on known content types, this feature targets that weakness.</li>
<li>The "Host" header can also be modified.  Poorly configured WAFs might be configured to only evaluate requests based on the correct FQDN of the host found in this header, which is what this bypass targets.</li>
<li>The request type option allows the Burp user to only use the remaining bypass techniques on the given request method of "GET" or "POST", or to apply them on all requests.</li>
<li>The path injection feature can leave a request unmodified, inject random path info information (/path/to/example.php/randomvalue?restofquery), or inject a random path parameter (/path/to/example.php;randomparam=randomvalue?resetofquery).  This can be used to bypass poorly written rules that rely on path information.</li>
<li>The path obfuscation feature modifies the last forward slash in the path to a random value, or by default does nothing.  The last slash can be modified to one of many values that in many cases results in a still valid request but can bypass poorly written WAF rules that rely on path information.</li>
<li>The parameter obfuscation feature is language specific. PHP will discard a + at the beginning of each parameter, but a poorly written WAF rule might be written for specific parameter names, thus ignoring parameters with a + at the beginning.  Similarly, ASP discards a % at the beginning of each parameter.</li>
<li>The "Set Configuration" button activates all the settings that you have chosen.</li>
</ol>

All of these features can be combined to provide multiple bypass options.


Future
======

I intend to add the following features, at a minimum, to future versions:
<ol>
<li>HTTP Parameter Pollution - Automatically perform HPP attacks on GET/POST parameters.</li>
<li>HTTP Requests Smuggling - Automatically perform an HTTP request smuggling attack on each request where a dummy request is added to the beginning and the real (smuggled) request is added at the end.</li>
</ol>

I have been adding features rapidly and it is very possible that the above will be in the code by the time anyone actually reads this.


Note
=====

I am not maintaining the Python version.
