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

<ul>
<ol>Add extension to burp</ol>
<ol>Create a session handling rule in Burp that invokes this extension</ol>
<ol>Modify the scope to include applicable tools and URLs</ol>
<ol>Test away</ol>
</ul>

More information can be found at: <a href="ttps://www.codewatch.org/blog/?p=408" target=_codewatch>https://www.codewatch.org/blog/?p=408</a>
