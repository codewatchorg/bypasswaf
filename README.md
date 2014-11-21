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
<ul>
<ol>1) Add extension to burp</ol>
<ol>2) Create a session handling rule in Burp that invokes this extension</ol>
<ol>3) Modify the scope to include applicable tools and URLs</ol>
<ol>4) Test away</ol>
</ul>

More information can be found at: <a href="ttps://www.codewatch.org/blog/?p=408" target=_codewatch>https://www.codewatch.org/blog/?p=408</a>


Note
=====

I am not maintaining the Python version.
