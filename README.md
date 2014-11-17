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

1) Add extension to burp
2) Create a session handling rule in Burp that invokes this extension
3) Modify the scope to include applicable tools and URLs
4) Test away

More information can be found at: 
