/*
 * Name:           Bypass WAF
 * Version:        0.0.3
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

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab {

  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  public JPanel bwafPanel;
  private static final String bypassWafVersion = "0.0.3";
  private PrintWriter printOut;
  private String bypassIP = "127.0.0.1";
  /*private int contentTypeBypass = 0;*/
  private String contentTypeBypass = "Keep";
  /*private final Integer[] contentOpts = { 0, 1, 2 };*/
  private final List<String> bwafHeaders = Arrays.asList("X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Remote-Addr");
  private final List<Integer> bwafHeaderInit = Arrays.asList( 0, 0, 0, 0 );
  private final List<String> bwafCTHeaders = Arrays.asList(
      "Keep",
      "Remove",
      "invalid",
      "example",
      "multipart/",
      "multipart/; boundary=0000",
      "multipart/fake",
      "multipart/mixed",
      "multipart/alternative",
      "multipart/related",
      "multipart/form-data",
      "multipart/form-data; boundary=0000",
      "multipart/form-data boundary=0000",
      "multipart/fake; boundary=0000",
      "multipart/fake boundary=0000",
      "multipart/form-data-rand; boundary=0000",
      "multipart/form-data-rand boundary=0000",
      "multipart/signed",
      "multipart/encrypted",
      "multipart/example",
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
  
  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    extCallbacks = callbacks;
    extHelpers = extCallbacks.getHelpers();
    extCallbacks.setExtensionName("Bypass WAF");
    extCallbacks.registerSessionHandlingAction(this);
    
    /* Create a tab to configure header IP or alternate values */
    bwafPanel = new JPanel(null);
    JLabel bwafIPLabel = new JLabel();
    JLabel bwafCTLabel = new JLabel();
    /*JLabel bwafCTOptsLabel = new JLabel();*/
    /*final JComboBox bwafCTCbx = new JComboBox(contentOpts);*/
    final JComboBox bwafCTCbx = new JComboBox(bwafCTHeaders.toArray());
    final JTextField bwafIPText = new JTextField();
    JButton bwafSetHeaderBtn = new JButton("Set Headers");
    printOut = new PrintWriter(extCallbacks.getStdout(), true);
    printHeader();
    
    /* Set values for labels, panels, locations, etc */
    bwafIPLabel.setText("Header IP:");
    bwafIPLabel.setBounds(16, 15, 75, 20);
    bwafIPText.setBounds(146, 12, 275, 26);
    
    /* Set Content-Type headers */
    bwafCTLabel.setText("Content-Type:");
    /*bwafCTOptsLabel.setText("<html>0 - Content-Type unchanged<BR>1 - Content-Type: invalid<BR>2 - Content-Type removed</html>");*/
    bwafCTLabel.setBounds(16, 50, 85, 20);
    /*bwafCTCbx.setBounds(146, 47, 50, 26);*/
    bwafCTCbx.setBounds(146, 47, 275, 26);
    /*bwafCTOptsLabel.setBounds(221, 45, 200, 70);*/
    
    /* Create button for setting options */
    bwafSetHeaderBtn.setBounds(441, 15, 100, 20);
    bwafSetHeaderBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        bypassIP = bwafIPText.getText();
        /*contentTypeBypass = (int)bwafCTCbx.getSelectedItem();*/
        contentTypeBypass = (String)bwafCTCbx.getSelectedItem();
        bwafCTCbx.setSelectedIndex(bwafCTCbx.getSelectedIndex());
      }
    });
    
    /* Initialize defaults */
    bwafIPText.setText(bypassIP);
    bwafCTCbx.setSelectedIndex(0);

    /* Add label and field to tab */
    bwafPanel.add(bwafIPLabel);
    bwafPanel.add(bwafIPText);
    bwafPanel.add(bwafCTLabel);
    /*bwafPanel.add(bwafCTOptsLabel);*/
    bwafPanel.add(bwafCTCbx);
    bwafPanel.add(bwafSetHeaderBtn);
    
    /* Add the tab to Burp */
    extCallbacks.customizeUiComponent(bwafPanel);
    extCallbacks.addSuiteTab(BurpExtender.this);
    
  }
  
  /* Print to extension output tab */
  public void printHeader() {
      printOut.println("Bypass WAF: v" + bypassWafVersion + "\n=========\nBypass WAF devices with headers.  "
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
    String reqRaw = new String(currentRequest.getRequest());
    String reqBody = reqRaw.substring(requestInfo.getBodyOffset());
    Integer contentInHeader = 0;
    /*Integer originIPExist = 0;
    Integer forwardForExist = 0;
    Integer remoteIPExist = 0;
    Integer remoteAddrExist = 0;*/
    
    /* Loop through the headers to add or set values */
    for (int i = 0; i < headers.size(); i++) {
            
        /* Set to either a Content-Type of "invalid" or remove Content-Type */
        if (headers.get(i).startsWith("Content-Type:")) {                
            /*if (contentTypeBypass == 1) {
                contentInHeader = 1;
                headers.set(i, "Content-Type: invalid" );
            } else if (contentTypeBypass == 2) {
                headers.remove(i);
            }*/
            
            if (contentTypeBypass.startsWith("Remove")) {
                headers.remove(i);
            } else if (!contentTypeBypass.startsWith("Keep")) {
                headers.set(i, "Content-Type: " + contentTypeBypass);
                contentInHeader = 1;
            }
        }
                
        /* Check to see if any WAF Bypass headers were already added, if so, don't add twice */    
        /*} else if (headers.get(i).startsWith("X-Originating-IP:")) {
            originIPExist = 1;
        } else if (headers.get(i).startsWith("X-Forwarded-For:")) {
            forwardForExist = 1;
        } else if (headers.get(i).startsWith("X-Remote-IP:")) {
            remoteIPExist = 1;
        } else if (headers.get(i).startsWith("X-Remote-Addr:")) {
            remoteAddrExist = 1;
        }*/
        for (int j = 0; j < bwafHeaders.size(); j++) {
            if (headers.get(i).startsWith(bwafHeaders.get(j))) {
                bwafHeaderInit.set(j, 1);
            }
        }
    }
    
    /* If set to Content-Type: invalid, but Content-Type wasn't in request, then add */
    /*if (contentInHeader == 0 && contentTypeBypass == 1) {
        headers.add("Content-Type: invalid");
    }*/
    if (contentInHeader == 0 && !contentTypeBypass.startsWith("Keep") && !contentTypeBypass.startsWith("Remove")) {
        headers.add("Content-Type: " + contentTypeBypass);
    }
    
    /* Add WAF Bypass headers if they don't already exist */
    /*if (originIPExist == 0) {
        headers.add("X-Originating-IP: " + bypassIP);
    }
    
    if (forwardForExist == 0) {
        headers.add("X-Forwarded-For: " + bypassIP);
    }
    
    if (remoteIPExist == 0) {
        headers.add("X-Remote-IP: " + bypassIP);
    }
    
    if (remoteAddrExist == 0) {
        headers.add("X-Remote-Addr: " + bypassIP);
    }*/
    
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