/*
 * Name:           Bypass WAF
 * Version:        0.1.0
 * Date:           11/16/2014
 * Author:         Josh Berry - josh.berry@codewatch.org
 * Github:         https://github.com/codewatchorg/bypasswaf
 * 
 * Description:    This plugin adds headers useful for bypassing some WAF devices when added to a Burp Session Handling rule.
 * 
 * This plugin was inspired by the Bypassing web application firewalls using HTTP headers found here:
 * http://h30499.www3.hp.com/t5/Fortify-Application-Security/Bypassing-web-application-firewalls-using-HTTP-headers/ba-p/6418366#.VGlMR-90wsd
 * 
 * This article by Fishnet was used to help understand how to build the plugin:
 * https://www.fishnetsecurity.com/6labs/blog/automatically-adding-new-header-burp
 *
 * Other bypass techinques have largely been derived from Ivan Ristic's work:
 * https://media.blackhat.com/bh-us-12/Briefings/Ristic/BH_US_12_Ristic_Protocol_Level_WP.pdf
 * https://media.blackhat.com/bh-us-12/Briefings/Ristic/BH_US_12_Ristic_Protocol_Level_Slides.pdf
 * https://github.com/ironbee/waf-research
*/

package burp;

import java.util.List;
import java.awt.Component;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JComboBox;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Random;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab {

  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  public JPanel bwafPanel;
  private static final String bypassWafVersion = "0.0.3";
  private PrintWriter printOut;
  private String bypassIP = "127.0.0.1";
  private String contentTypeBypass = "Keep";
  private String hostNameBypass = "DefaultHostname";
  private String pathInfoBypass = "NoPathInfo";
  private String pathObfuscationBypass = "NoObfuscation";
  private String paramObfuscationBypass = "None";
  private String bypassRequestType = "All";
  private String defaultHttpVersion = "HTTP/1.1";
  private String defaultPathParam = "";
  private String defaultPathValue = "";
  private final List<String> bwafHeaders = Arrays.asList("X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Remote-Addr");
  private final List<String> bwafPathInfo = Arrays.asList("NoPathInfo", "PathInfoInjection", "PathParametersInjection");
  private final List<Integer> bwafHeaderInit = Arrays.asList( 0, 0, 0, 0 );
  private final List<String> bwafRequestTypes = Arrays.asList("All", "GET", "POST");
  private final List<String> bwafParamObfuscation = Arrays.asList("None", "+", "%");
  private final List<String> bwafPathObfuscation = Arrays.asList(
      "NoObfuscation",
      "//",
      "/./",
      "/random/../",
      "\\",
      "%2f%2f",
      "%2f.%2f",
      "%2frandom%2f..%2f",
      "%5c"
  );
  
  private final List<String> bwafCTHeaders = Arrays.asList(
      "Keep",
      "Remove",
      "invalid",
      "example",
      "multipart/",
      "multipart/digest",
      "multipart/digest; boundary=0000",
      "multipart/; boundary=0000",
      "multipart/fake",
      "multipart/fake; boundary=0000",
      "multipart/mixed",
      "multipart/mixed; boundary=0000",
      "multipart/alternative",
      "multipart/alternative; boundary=0000",
      "multipart/related",
      "multipart/related; boundary=0000",
      "multipart/form-data",
      "multipart/form-data; boundary=0000",
      "multipart/form-data ; boundary=0000",
      "multipart/form-data, boundary=0000",
      "multipart/form-data boundary=0000",
      "multipart/form-data; boundary=\"0000\"",
      "multipart/form-data; boundary=0000'",
      "multipart/fake; boundary=0000",
      "multipart/fake ; boundary=0000",
      "multipart/fake, boundary=0000",
      "multipart/fake; boundary=\"0000\"",
      "multipart/fake; boundary=0000'",
      "multipart/fake boundary=0000",
      "multipart/form-data-rand; boundary=0000",
      "multipart/form-data-rand boundary=0000",
      "multipart/form-data-rand ; boundary=0000",
      "multipart/form-data-rand, boundary=0000",
      "multipart/form-data-rand; boundary=\"0000\"",
      "multipart/form-data-rand; boundary=0000'",
      "multipart/signed",
      "multipart/signed; boundary=0000",
      "multipart/encrypted",
      "multipart/encrypted; boundary=0000",
      "multipart/example",
      "multipart/example; boundary=0000",
      "text/cmd",
      "text/css",
      "text/csv",
      "text/example",
      "text/fake",
      "text/html",
      "text/javascript",
      "text/plain",
      "text/rtf",
      "text/vnd.abc",
      "text/xml",
      "text/x-gwt-rpc",
      "text/x-jquery-tmpl",
      "text/x-markdown",
      "application/example",
      "application/fake",
      "application/ecmascript",
      "application/json",
      "application/javascript",
      "application/xml",
      "application/x-javascript",
      "application/x-latex",
      "application/x-www-form-urlencoded",
      "application/x-www-form-urlencoded-rand"
  );
  
  /* Create a random values for obfuscation functions */
  public String setRand() {
      char[] randChars = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
      StringBuilder randString = new StringBuilder();
      Random random = new Random();
      
      for (int i = 0; i < 8; i++) {
          char c = randChars[random.nextInt(randChars.length)];
          randString.append(c);
      }
      
      return randString.toString();
  }
  
  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    extCallbacks = callbacks;
    extHelpers = extCallbacks.getHelpers();
    extCallbacks.setExtensionName("Bypass WAF");
    extCallbacks.registerSessionHandlingAction(this);
    
    /* Create a tab to configure header values */
    bwafPanel = new JPanel(null);
    JLabel bwafIPLabel = new JLabel();
    JLabel bwafIPDescLabel = new JLabel();
    JLabel bwafCTLabel = new JLabel();
    JLabel bwafCTDescLabel = new JLabel();
    JLabel bwafHostLabel = new JLabel();
    JLabel bwafHostDescLabel = new JLabel();
    JLabel bwafReqTypesLabel = new JLabel();
    JLabel bwafReqTypesDescLabel = new JLabel();
    JLabel bwafPathInfoLabel = new JLabel();
    JLabel bwafPathInfoDescLabel = new JLabel();
    JLabel bwafPathObfuscLabel = new JLabel();
    JLabel bwafPathObfuscDescLabel = new JLabel();
    JLabel bwafSetHeaderDescLabel = new JLabel();
    JLabel bwafParamObfuscLabel = new JLabel();
    JLabel bwafParamObfuscDescLabel = new JLabel();
    final JComboBox bwafCTCbx = new JComboBox(bwafCTHeaders.toArray());
    final JComboBox bwafPathInfoCbx = new JComboBox(bwafPathInfo.toArray());
    final JComboBox bwafPathObfuscCbx = new JComboBox(bwafPathObfuscation.toArray());
    final JComboBox bwafReqTypesCbx = new JComboBox(bwafRequestTypes.toArray());
    final JComboBox bwafParamObfuscCbx = new JComboBox(bwafParamObfuscation.toArray());
    final JTextField bwafIPText = new JTextField();
    final JTextField bwafHostText = new JTextField();
    JButton bwafSetHeaderBtn = new JButton("Set Configuration");
    printOut = new PrintWriter(extCallbacks.getStdout(), true);
    printHeader();
    
    /* Set values for labels, panels, locations, etc */
    bwafIPLabel.setText("Header IP:");
    bwafIPDescLabel.setText("Set IP for X-Originating-IP, X-Forwarded-For, X-Remote-IP, and X-Remote-Addr headers.");
    bwafIPLabel.setBounds(16, 15, 75, 20);
    bwafIPText.setBounds(146, 12, 275, 26);
    bwafIPDescLabel.setBounds(441, 15, 600, 20);
    
    /* Set Content-Type headers */
    bwafCTLabel.setText("Content-Type:");
    bwafCTDescLabel.setText("Keep current Content-Type, remove it, or replace with one of these values.");
    bwafCTLabel.setBounds(16, 50, 85, 20);
    bwafCTCbx.setBounds(146, 47, 275, 26);
    bwafCTDescLabel.setBounds(441, 50, 600, 20);
    
    /* Set host header */
    bwafHostLabel.setText("Host Header:");
    bwafHostDescLabel.setText("Modify what is sent in the Host header.");
    bwafHostLabel.setBounds(16, 85, 85, 20);
    bwafHostText.setBounds(146, 82, 275, 26);
    bwafHostDescLabel.setBounds(441, 85, 600, 20);
    
    /* Configure to path info and other certain request methods or all */
    bwafReqTypesLabel.setText("Request Method:");
    bwafReqTypesDescLabel.setText("Configure options below for all request methods, GET only, or POST only.");
    bwafReqTypesLabel.setBounds(16, 120, 115, 20);
    bwafReqTypesCbx.setBounds(146, 117, 275, 26);
    bwafReqTypesDescLabel.setBounds(441, 120, 600, 20);
    
    /* Set path info or parameters */
    bwafPathInfoLabel.setText("Path Info:");
    bwafPathInfoDescLabel.setText("Do nothing, add random path info at end of URL, or add random path parameters at end of URL.");
    bwafPathInfoLabel.setBounds(16, 155, 115, 20);
    bwafPathInfoCbx.setBounds(146, 152, 275, 26);
    bwafPathInfoDescLabel.setBounds(441, 155, 600, 20);
    
    /* Set last / to a new value */
    bwafPathObfuscLabel.setText("Path Obfuscation:");
    bwafPathObfuscDescLabel.setText("Do nothing or replace the last / in the request with one of these values.");
    bwafPathObfuscLabel.setBounds(16, 190, 115, 20);
    bwafPathObfuscCbx.setBounds(146, 187, 275, 26);
    bwafPathObfuscDescLabel.setBounds(441, 190, 600, 20);
    
    /* Add character to beginning of every parameter */
    bwafParamObfuscLabel.setText("Param Obfuscation:");
    bwafParamObfuscDescLabel.setText("Add the following character to the beginning of every parameter name.");
    bwafParamObfuscLabel.setBounds(16, 225, 115, 20);
    bwafParamObfuscCbx.setBounds(146, 222, 275, 20);
    bwafParamObfuscDescLabel.setBounds(441, 225, 600, 20);
    
    /* Create button for setting options */
    bwafSetHeaderDescLabel.setText("Enable the WAF bypass configuration.");
    bwafSetHeaderDescLabel.setBounds(441, 260, 600, 20);
    bwafSetHeaderBtn.setBounds(146, 257, 275, 20);
    bwafSetHeaderBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        bypassIP = bwafIPText.getText();
        hostNameBypass = bwafHostText.getText();
        contentTypeBypass = (String)bwafCTCbx.getSelectedItem();
        pathInfoBypass = (String)bwafPathInfoCbx.getSelectedItem();
        pathObfuscationBypass = (String)bwafPathObfuscCbx.getSelectedItem();
        paramObfuscationBypass = (String)bwafParamObfuscCbx.getSelectedItem();
        bypassRequestType = (String)bwafReqTypesCbx.getSelectedItem();
        bwafCTCbx.setSelectedIndex(bwafCTCbx.getSelectedIndex());
        bwafPathInfoCbx.setSelectedIndex(bwafPathInfoCbx.getSelectedIndex());
        bwafPathObfuscCbx.setSelectedIndex(bwafPathObfuscCbx.getSelectedIndex());
        bwafParamObfuscCbx.setSelectedIndex(bwafParamObfuscCbx.getSelectedIndex());
        bwafReqTypesCbx.setSelectedIndex(bwafReqTypesCbx.getSelectedIndex());
        
        if (!contentTypeBypass.startsWith("NoPathInfo")) {
            defaultPathParam = setRand();
            defaultPathValue = setRand();
        }
        
        /* Check if it was one of the random values */
        if (pathObfuscationBypass.contains("random")) {
            pathObfuscationBypass = pathObfuscationBypass.replace("random", setRand());
        }
      }
    });
    
    /* Initialize defaults */
    bwafIPText.setText(bypassIP);
    bwafCTCbx.setSelectedIndex(0);
    bwafHostText.setText(hostNameBypass);
    bwafPathInfoCbx.setSelectedIndex(0);
    bwafPathObfuscCbx.setSelectedIndex(0);
    bwafParamObfuscCbx.setSelectedIndex(0);
    bwafReqTypesCbx.setSelectedIndex(0);

    /* Add label and field to tab */
    bwafPanel.add(bwafIPLabel);
    bwafPanel.add(bwafIPDescLabel);
    bwafPanel.add(bwafIPText);
    bwafPanel.add(bwafCTLabel);
    bwafPanel.add(bwafCTDescLabel);
    bwafPanel.add(bwafCTCbx);
    bwafPanel.add(bwafHostLabel);
    bwafPanel.add(bwafHostDescLabel);
    bwafPanel.add(bwafHostText);
    bwafPanel.add(bwafReqTypesLabel);
    bwafPanel.add(bwafReqTypesDescLabel);
    bwafPanel.add(bwafReqTypesCbx);
    bwafPanel.add(bwafPathInfoLabel);
    bwafPanel.add(bwafPathInfoDescLabel);
    bwafPanel.add(bwafPathInfoCbx);
    bwafPanel.add(bwafPathObfuscLabel);
    bwafPanel.add(bwafPathObfuscDescLabel);
    bwafPanel.add(bwafPathObfuscCbx);
    bwafPanel.add(bwafParamObfuscLabel);
    bwafPanel.add(bwafParamObfuscDescLabel);
    bwafPanel.add(bwafParamObfuscCbx);
    bwafPanel.add(bwafSetHeaderBtn);
    bwafPanel.add(bwafSetHeaderDescLabel);
    
    /* Add the tab to Burp */
    extCallbacks.customizeUiComponent(bwafPanel);
    extCallbacks.addSuiteTab(BurpExtender.this);
  }
  
  /* Print to extension output tab */
  public void printHeader() {
      printOut.println("Bypass WAF: v" + bypassWafVersion + "\n==================\nBypass WAF devices with headers.  "
              + "WAFs are frequently configured to whitelist specific IPs and do this based on HTTP headers\n\n"
              + "josh.berry@codewatch.org");
  }
  
  /* Tab caption */
  @Override
  public String getTabCaption() { return "Bypass WAF"; }

  /* Java component to return to Burp */
  @Override
  public Component getUiComponent() { return bwafPanel; }
  
  /* Action to set in a session rule */
  @Override
  public String getActionName(){ return "Bypass WAF"; }

  /* Action for extension to perform */
  @Override
  public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
      
    /* Setup default variables */
    IRequestInfo requestInfo = extHelpers.analyzeRequest(currentRequest);
    List<String> headers = requestInfo.getHeaders();
    String reqPath = requestInfo.getUrl().getPath();
    String reqQuery = requestInfo.getUrl().getQuery();
    String reqRef = requestInfo.getUrl().getRef();
    String reqRaw = new String(currentRequest.getRequest());
    String reqBody = reqRaw.substring(requestInfo.getBodyOffset());
    Integer contentInHeader = 0;
    Integer updateUrl = 0;
    String newReq = "";
    String reqMethod = "";
    String newPath = "";
    String newQuery = "";
    String newRef = "";
    
    if (reqQuery != null) {
        newQuery = "?" + reqQuery;
    }
    
    if (reqRef != null) {
        newRef = "#" + reqRef;
    }
    
    /* Loop through the headers to add or set values */
    for (int i = 0; i < headers.size(); i++) {
        
        /* Set to one of the selected content types or remove Content-Type */
        if (headers.get(i).startsWith("Content-Type:")) {                
            if (contentTypeBypass.startsWith("Remove")) {
                headers.remove(i);
            } else if (!contentTypeBypass.startsWith("Keep")) {
                headers.set(i, "Content-Type: " + contentTypeBypass);
                contentInHeader = 1;
            }
        /* Set host header value */
        } else if (headers.get(i).startsWith("Host:")) {
            if (!hostNameBypass.startsWith("DefaultHostname")) {
                headers.set(i, "Host: " + hostNameBypass);
            }
        }
        /* If this is the the first header (GET/POST with URL) check to see if we are modifying path, path info, or parameters */
        if (i == 0 && (headers.get(i).startsWith("GET ") || headers.get(i).startsWith("POST "))) {

            /* Check request type, only process if a match is found */
            if (bypassRequestType.startsWith("All") || (headers.get(i).startsWith("GET ") && bypassRequestType.startsWith("GET")) || (headers.get(i).startsWith("POST ") && bypassRequestType.startsWith("POST"))) {
                
                /* Determine whether it was a GET or POST request, and use the correct method */
                if (headers.get(i).startsWith("GET ")) {
                    reqMethod = "GET";
                } else {
                    reqMethod = "POST";
                }
            
                /* Obfuscate the last path (/) value */
                if (!pathObfuscationBypass.startsWith("NoObfuscation")) {
                
                    /* If there was a slash, replace last one with obfuscated version */
                    if (reqPath.contains("/")) {
                        StringBuilder slashReplace = new StringBuilder(reqPath);
                        slashReplace.replace(reqPath.lastIndexOf("/"), reqPath.lastIndexOf("/")+1, pathObfuscationBypass );
                        newPath = slashReplace.toString();
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    }
                }
        
                /* Set path info in URL */
                if (!pathInfoBypass.startsWith("NoPathInfo")) {
                
                    /* Determine the right injection and set the new request */
                    if (pathInfoBypass.startsWith("PathInfoInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && newReq.isEmpty()) {
                        newReq = reqMethod + " " + reqPath + "/" + defaultPathParam + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (pathInfoBypass.startsWith("PathInfoInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && !newReq.isEmpty()) {
                        newReq = reqMethod + " " + newPath + "/" + defaultPathParam + newQuery + newRef + " " + defaultHttpVersion;
                    } else if (pathInfoBypass.startsWith("PathParametersInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && newReq.isEmpty()) {
                        newReq = reqMethod + " " + reqPath + ";" + defaultPathParam + "=" + defaultPathValue + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (pathInfoBypass.startsWith("PathParametersInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && !newReq.isEmpty()) {
                        newReq = reqMethod + " " + newPath + ";" + defaultPathParam + "=" + defaultPathValue + newQuery + newRef + " " + defaultHttpVersion;
                    }
                }
                
                /* Add special character to beginning of all parameter names */
                if (!paramObfuscationBypass.startsWith("None")) {
                    
                    /* Determine the right injection and set the new request in URL */
                    if (newQuery.startsWith("?") && !newQuery.startsWith("?" + paramObfuscationBypass) && newReq.isEmpty()) {
                        String updQuery = newQuery.replaceFirst("\\?", "?" + paramObfuscationBypass);
                        updQuery = updQuery.replaceAll("&", "&" + paramObfuscationBypass);
                        newReq = reqMethod + " " + reqPath + "/" + defaultPathParam + updQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (newQuery.startsWith("?") && !newQuery.startsWith("?" + paramObfuscationBypass) && !newReq.isEmpty()) {
                        String updQuery = newQuery.replaceFirst("\\?", "?" + paramObfuscationBypass);
                        updQuery = updQuery.replaceAll("&", "&" + paramObfuscationBypass);
                        newReq = reqMethod + " " + newPath + "/" + defaultPathParam + updQuery + newRef + " " + defaultHttpVersion;
                    }
                    
                    /* Determine the right injection and set the new request in POST body */
                    if (!reqBody.startsWith(paramObfuscationBypass) && reqMethod.startsWith("POST")) {
                        reqBody = paramObfuscationBypass + reqBody.replaceAll("&", "&" + paramObfuscationBypass);
                    }
                }
            }
        }
                
        /* Check to see if the bypass headers have already been set */
        for (int j = 0; j < bwafHeaders.size(); j++) {
            if (headers.get(i).startsWith(bwafHeaders.get(j))) {
                bwafHeaderInit.set(j, 1);
            }
        }
    }
    
    /* If the request URL was modified, update it here */
    if (updateUrl == 1) {
        headers.set(0, newReq);
    }
    
    /* If set to a specific content type, but Content-Type wasn't in request, then add */
    if (contentInHeader == 0 && !contentTypeBypass.startsWith("Keep") && !contentTypeBypass.startsWith("Remove")) {
        headers.add("Content-Type: " + contentTypeBypass);
    }
    
    /* Add WAF Bypass headers if they don't already exist */
    for (int idx = 0; idx < bwafHeaderInit.size(); idx++) {
        if (bwafHeaderInit.get(idx) == 0) {
            headers.add(bwafHeaders.get(idx) + ": " + bypassIP);
        }
    }

    /* Build request with bypass headers */
    byte[] message = extHelpers.buildHttpMessage(headers, reqBody.getBytes());

    /* Update Request with New Header */
    currentRequest.setRequest(message);
  }
}