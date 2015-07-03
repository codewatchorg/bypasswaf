/*
 * Name:           Bypass WAF
 * Version:        0.2.2
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
import javax.swing.JCheckBox;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;
import java.net.URLDecoder;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab {

  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  public JPanel bwafPanel;
  private static final String bypassWafVersion = "0.2.2";
  private PrintWriter printOut;
  private String bypassIP = "127.0.0.1";
  private String contentTypeBypass = "Keep";
  private String hostNameBypass = "DefaultHostname";
  private String pathInfoBypass = "NoPathInfo";
  private String pathObfuscationBypass = "NoObfuscation";
  private String paramObfuscationBypass = "None";
  private String bypassRequestType = "All";
  private String charEncoding = "None";
  private String spaceEncoding = "None";
  private String spacePayload = "None";
  private Integer bypassHpp = 0;
  private Integer defaultSizeValue = 100;
  private String bypassHppLocation = "First";
  private String defaultHttpVersion = "HTTP/1.1";
  private String defaultPathParam = "";
  private String defaultPathValue = "";
  private String defaultHppValue = "1";
  private final List<String> bwafHeaders = Arrays.asList("X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Remote-Addr");
  private final List<String> bwafPathInfo = Arrays.asList("NoPathInfo", "PathInfoInjection", "PathParametersInjection");
  private final List<Integer> bwafHeaderInit = Arrays.asList( 0, 0, 0, 0 );
  private final HashMap<String, String> bwafCharEncodings = new HashMap();
  private final HashMap<String, String> bwafQueryEncodings = new HashMap();
  private final HashMap<String, String> bwafSpacePayloads = new HashMap();
  private final List<String> bwafCharEncodeTypes = Arrays.asList("None", "URL", "%u", "Double URL", "Double Double URL", "Double %u");
  private final List<String> bwafQueryEncodeTypes = Arrays.asList("None", "URL", "%u", "Double URL", "Double Double", "Double %u", "Hex");
  private final List<String> bwafSpaceTypes = Arrays.asList("Null", "Tab", "NL", "CR", "VTab", "NB");
  private final List<String> bwafRequestTypes = Arrays.asList("All", "GET", "POST");
  private final List<String> bwafParamObfuscation = Arrays.asList("None", "+", "%", "%20", "%00");
  private final List<String> bwafHppLocation = Arrays.asList("First", "Last");
  private final List<String> bwafPathInfoSize = new ArrayList();
  private final List<String> bwafPathObfuscSize = new ArrayList();
  private final List<String> bwafPathObfuscation = Arrays.asList(
      "NoObfuscation",
      "//",
      "/./",
      "/random/../",
      "\\",
      "/.//",
      "/./\\",
      "/.\\",
      "/random/..//",
      "/random/.././/",
      "/random/.././\\",
      "/random/../.\\",
      "%2f%2f",
      "%2f.%2f",
      "%2frandom%2f..%2f",
      "%5c",
      "%2f.%2f%2f",
      "%2f.%2f\\",
      "%2f.\\",
      "%2f.%5c",
      "%2f.%2f%5c",
      "%2frandom%2f..%2f%2f",
      "%2frandom%2f..%2f.%2f%2f",
      "%2frandom%2f..%2f.%2f%5c",
      "%2frandom%2f..%2f.%5c",
      "%252f%252f",
      "%252f.%252f",
      "%252frandom%252f..%252f",
      "%255c",
      "%252f.%252f%252f",
      "%252f.%252f\\",
      "%252f.\\",
      "%252f.%255c",
      "%252f.%252f%255c",
      "%252frandom%252f..%252f%252f",
      "%252frandom%252f..%252f.%252f%252f",
      "%252frandom%252f..%252f.%252f%255c",
      "%252frandom%252f..%252f.%255c",
      "%u002f%u002f",
      "%u002f.%u002f",
      "%u002frandom%u002f..%u002f",
      "%u005c",
      "%u002f.%u002f%u002f",
      "%u002f.%u002f\\",
      "%u002f.\\",
      "%u002f.%u005c",
      "%u002f.%u002f%u005c",
      "%u002frandom%u002f..%u002f%u002f",
      "%u002frandom%u002f..%u002f.%u002f%u002f",
      "%u002frandom%u002f..%u002f.%u002f%u005c",
      "%u002frandom%u002f..%u002f.%u005c",
      "%002f%002f",
      "%002f.%002f",
      "%002frandom%002f..%002f",
      "%005c",
      "%002f.%002f%002f",
      "%002f.%002f\\",
      "%002f.\\",
      "%002f.%005c",
      "%002f.%002f%005c",
      "%002frandom%002f..%002f%002f",
      "%002frandom%002f..%002f.%002f%002f",
      "%002frandom%002f..%002f.%002f%005c",
      "%002frandom%002f..%002f.%005c"
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
      "multipart/form-data; boundary911=0000",
      "multipart/form-data; boundary =0000",
      "multipart/form-data; boundary= 0000",
      "multipart/form-data; boundary=0000 1111",
      "multipart/form-data; boundary=0000,1111",
      "multipart/form-data; boundary=0000 boundary=1111",
      "multipart/form-data; boundary=0000, boundary=1111",
      "multipart/form-data; boundary=0000; boundary=1111",
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
  
  /* Create random values for obfuscation functions */
  public String setRand(int sz) {
      char[] randChars = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
      StringBuilder randString = new StringBuilder();
      Random random = new Random();
      
      for (int i = 0; i <= sz; i++) {
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
    
    /* Initialize encodings for URL character */
    bwafCharEncodings.put("None", "None");
    bwafCharEncodings.put("URL", "%");
    bwafCharEncodings.put("%u", "%u00");
    bwafCharEncodings.put("Double URL", "%25");
    bwafCharEncodings.put("Double Double URL", "%25%");
    bwafCharEncodings.put("Double %u", "%u0025%u00");

    /* Initialize encodings for spaces in query parameters */
    bwafQueryEncodings.put("None", "None");
    bwafQueryEncodings.put("URL", "%");
    bwafQueryEncodings.put("%u", "%u00");
    bwafQueryEncodings.put("Double URL", "%25");
    bwafQueryEncodings.put("Double Double", "%25%");
    bwafQueryEncodings.put("Double %u", "%u0025%u00");
    bwafQueryEncodings.put("Hex", "\\x");
    
    /* Initialize space types */
    bwafSpacePayloads.put("Null", "00");
    bwafSpacePayloads.put("Tab", "09");
    bwafSpacePayloads.put("NL", "0A");
    bwafSpacePayloads.put("CR", "0D");
    bwafSpacePayloads.put("VTab", "0B");
    bwafSpacePayloads.put("NB", "A0");
    
    /* Intialize size arrays */
    for (int sz = 1; sz <= defaultSizeValue; sz++) {
        bwafPathInfoSize.add(String.valueOf(sz));
        bwafPathObfuscSize.add(String.valueOf(sz));
    }
    
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
    JLabel bwafPathInfoSizeLabel = new JLabel();
    JLabel bwafPathObfuscLabel = new JLabel();
    JLabel bwafPathObfuscDescLabel = new JLabel();
    JLabel bwafPathObfuscSizeLabel = new JLabel();
    JLabel bwafSetHeaderDescLabel = new JLabel();
    JLabel bwafParamObfuscLabel = new JLabel();
    JLabel bwafParamObfuscDescLabel = new JLabel();
    JLabel bwafHppCheckLabel = new JLabel();
    JLabel bwafHppCheckDescLabel = new JLabel();
    JLabel bwafHppLocationLabel = new JLabel();
    JLabel bwafCharEncodeLabel = new JLabel();
    JLabel bwafCharEncodeDescLabel = new JLabel();
    JLabel bwafQueryEncodeLabel = new JLabel();
    JLabel bwafQueryEncodeDescLabel = new JLabel();
    JLabel bwafSpacePayloadLabel = new JLabel();
    JLabel bwafHppValueLabel = new JLabel();
    final JComboBox bwafCTCbx = new JComboBox(bwafCTHeaders.toArray());
    final JComboBox bwafPathInfoCbx = new JComboBox(bwafPathInfo.toArray());
    final JComboBox bwafPathInfoSizeCbx = new JComboBox(bwafPathInfoSize.toArray());
    final JComboBox bwafPathObfuscCbx = new JComboBox(bwafPathObfuscation.toArray());
    final JComboBox bwafPathObfuscSizeCbx = new JComboBox(bwafPathObfuscSize.toArray());
    final JComboBox bwafReqTypesCbx = new JComboBox(bwafRequestTypes.toArray());
    final JComboBox bwafParamObfuscCbx = new JComboBox(bwafParamObfuscation.toArray());
    final JComboBox bwafHppLocationCbx = new JComboBox(bwafHppLocation.toArray());
    final JComboBox bwafCharEncodeCbx = new JComboBox(bwafCharEncodeTypes.toArray());
    final JComboBox bwafQueryEncodeCbx = new JComboBox(bwafQueryEncodeTypes.toArray());
    final JComboBox bwafSpacePayloadCbx = new JComboBox(bwafSpaceTypes.toArray());
    final JCheckBox bwafHppCheck = new JCheckBox("HPP");
    final JTextField bwafIPText = new JTextField();
    final JTextField bwafHostText = new JTextField();
    final JTextField bwafHppValueText = new JTextField();
    JButton bwafSetHeaderBtn = new JButton("Set Configuration");
    printOut = new PrintWriter(extCallbacks.getStdout(), true);
    printHeader();
    
    /* Set values for labels, panels, locations, etc */
    bwafIPLabel.setText("Header IP:");
    bwafIPDescLabel.setText("Set IP for X-Originating-IP, X-Forwarded-For, X-Remote-IP, and X-Remote-Addr headers.");
    bwafIPLabel.setBounds(16, 15, 75, 20);
    bwafIPText.setBounds(146, 12, 310, 26);
    bwafIPDescLabel.setBounds(606, 15, 600, 20);
    
    /* Set Content-Type headers */
    bwafCTLabel.setText("Content-Type:");
    bwafCTDescLabel.setText("Keep current Content-Type, remove it, or replace with one of these values.");
    bwafCTLabel.setBounds(16, 50, 85, 20);
    bwafCTCbx.setBounds(146, 47, 310, 26);
    bwafCTDescLabel.setBounds(606, 50, 600, 20);
    
    /* Set host header */
    bwafHostLabel.setText("Host Header:");
    bwafHostDescLabel.setText("Modify what is sent in the Host header.");
    bwafHostLabel.setBounds(16, 85, 85, 20);
    bwafHostText.setBounds(146, 82, 310, 26);
    bwafHostDescLabel.setBounds(606, 85, 600, 20);
    
    /* Configure to path info and other certain request methods or all */
    bwafReqTypesLabel.setText("Request Method:");
    bwafReqTypesDescLabel.setText("Configure options below for all request methods, GET only, or POST only.");
    bwafReqTypesLabel.setBounds(16, 120, 115, 20);
    bwafReqTypesCbx.setBounds(146, 117, 310, 26);
    bwafReqTypesDescLabel.setBounds(606, 120, 600, 20);
    
    /* Set path info or parameters */
    bwafPathInfoLabel.setText("Path Info:");
    bwafPathInfoDescLabel.setText("Do nothing, add random path info at end of URL, or add random path parameters at end of URL.  Set the size of the random data.");
    bwafPathInfoLabel.setBounds(16, 155, 115, 20);
    bwafPathInfoCbx.setBounds(146, 152, 310, 26);
    bwafPathInfoSizeLabel.setText("Size:");
    bwafPathInfoSizeLabel.setBounds(476, 155, 40, 20);
    bwafPathInfoSizeCbx.setBounds(526, 152, 60, 26);
    bwafPathInfoDescLabel.setBounds(606, 155, 800, 20);
    
    /* Set last / to a new value */
    bwafPathObfuscLabel.setText("Path Obfuscation:");
    bwafPathObfuscDescLabel.setText("Do nothing or replace the last / in the request with one of these values.  Set the size of the random value where applicable.");
    bwafPathObfuscLabel.setBounds(16, 190, 115, 20);
    bwafPathObfuscCbx.setBounds(146, 187, 310, 26);
    bwafPathObfuscSizeLabel.setText("Size:");
    bwafPathObfuscSizeLabel.setBounds(476, 190, 40, 20);
    bwafPathObfuscSizeCbx.setBounds(526, 187, 60, 26);
    bwafPathObfuscDescLabel.setBounds(606, 190, 850, 20);
    
    /* Add character to beginning of every parameter */
    bwafParamObfuscLabel.setText("Param Obfuscation:");
    bwafParamObfuscDescLabel.setText("Add the following character to the beginning of every parameter name.");
    bwafParamObfuscLabel.setBounds(16, 225, 115, 20);
    bwafParamObfuscCbx.setBounds(146, 222, 310, 26);
    bwafParamObfuscDescLabel.setBounds(606, 225, 600, 20);
    
    /* HTTP Parameter Pollution check */
    bwafHppCheckLabel.setText("HPP:");
    bwafHppCheckLabel.setBounds(16, 260, 115, 20);
    bwafHppCheck.setBounds(146, 257, 50, 26);
    bwafHppLocationLabel.setText("Place:");
    bwafHppLocationLabel.setBounds(256, 260, 40, 20);
    bwafHppLocationCbx.setBounds(316, 257, 140, 26);
    bwafHppValueLabel.setText("Value:");
    bwafHppValueLabel.setBounds(476, 260, 40, 20);
    bwafHppValueText.setBounds(526, 257, 60, 26);
    bwafHppCheckDescLabel.setText("Perform HPP, keeping the original payload in either the First/Last (duplicate) parameter value, replace the other value with a 1 or chosen value.");
    bwafHppCheckDescLabel.setBounds(606, 260, 850, 20);
    
    /* Character encoding obfuscation */
    bwafCharEncodeLabel.setText("Character Encodings:");
    bwafCharEncodeDescLabel.setText("Encode a single character in the URL with the selected encoding type.");
    bwafCharEncodeLabel.setBounds(16, 295, 140, 20);
    bwafCharEncodeCbx.setBounds(146, 292, 310, 26);
    bwafCharEncodeDescLabel.setBounds(606, 295, 600, 20);
    
    /* Query space encoding obfuscation */
    bwafQueryEncodeLabel.setText("Space Encodings:");
    bwafQueryEncodeDescLabel.setText("Encode spaces in query parameters with misinterpreted values (nulls, tabs, new lines, carriage returns, vert tabs, and non-breaking spaces).");
    bwafQueryEncodeLabel.setBounds(16, 330, 140, 20);
    bwafQueryEncodeCbx.setBounds(146, 327, 115, 26);
    bwafSpacePayloadLabel.setText("Type:");
    bwafSpacePayloadLabel.setBounds(286, 330, 45, 20);
    bwafSpacePayloadCbx.setBounds(341, 327, 115, 26);
    bwafQueryEncodeDescLabel.setBounds(606, 330, 850, 20);
    
    /* Create button for setting options */
    bwafSetHeaderDescLabel.setText("Enable the WAF bypass configuration.");
    bwafSetHeaderDescLabel.setBounds(606, 365, 600, 20);
    bwafSetHeaderBtn.setBounds(146, 363, 310, 20);
    bwafSetHeaderBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        bypassIP = bwafIPText.getText();
        hostNameBypass = bwafHostText.getText();
        contentTypeBypass = (String)bwafCTCbx.getSelectedItem();
        pathInfoBypass = (String)bwafPathInfoCbx.getSelectedItem();
        pathObfuscationBypass = (String)bwafPathObfuscCbx.getSelectedItem();
        paramObfuscationBypass = (String)bwafParamObfuscCbx.getSelectedItem();
        bypassRequestType = (String)bwafReqTypesCbx.getSelectedItem();
        bypassHppLocation = (String)bwafHppLocationCbx.getSelectedItem();
        bwafCTCbx.setSelectedIndex(bwafCTCbx.getSelectedIndex());
        bwafPathInfoCbx.setSelectedIndex(bwafPathInfoCbx.getSelectedIndex());
        bwafPathObfuscCbx.setSelectedIndex(bwafPathObfuscCbx.getSelectedIndex());
        bwafParamObfuscCbx.setSelectedIndex(bwafParamObfuscCbx.getSelectedIndex());
        bwafReqTypesCbx.setSelectedIndex(bwafReqTypesCbx.getSelectedIndex());
        bwafHppLocationCbx.setSelectedIndex(bwafHppLocationCbx.getSelectedIndex());
        bwafCharEncodeCbx.setSelectedIndex(bwafCharEncodeCbx.getSelectedIndex());
        bwafQueryEncodeCbx.setSelectedIndex(bwafQueryEncodeCbx.getSelectedIndex());
        bwafSpacePayloadCbx.setSelectedIndex(bwafSpacePayloadCbx.getSelectedIndex());
        bwafPathInfoSizeCbx.setSelectedIndex(bwafPathInfoSizeCbx.getSelectedIndex());
        bwafPathObfuscSizeCbx.setSelectedIndex(bwafPathObfuscSizeCbx.getSelectedIndex());
        
        if (!pathInfoBypass.startsWith("NoPathInfo")) {
            defaultPathParam = setRand(bwafPathInfoSizeCbx.getSelectedIndex());
            defaultPathValue = setRand(bwafPathInfoSizeCbx.getSelectedIndex());
        } else {
            defaultPathParam = "";
            defaultPathValue = "";
        }
        
        /* Check if it was one of the random values */
        if (pathObfuscationBypass.contains("random")) {
            pathObfuscationBypass = pathObfuscationBypass.replace("random", setRand(bwafPathObfuscSizeCbx.getSelectedIndex()));
        }
        
        /* Is HPP enabled? */
        if (bwafHppCheck.isSelected()){
            bypassHpp = 1;
            
            if (!bwafHppValueText.getText().isEmpty()) {
                defaultHppValue = bwafHppValueText.getText();
            } else {
                defaultHppValue = "1";
            }
        } else {
            bypassHpp = 0;
        }
        
        charEncoding = bwafCharEncodings.get(bwafCharEncodeCbx.getItemAt(bwafCharEncodeCbx.getSelectedIndex()));
        spaceEncoding = bwafQueryEncodings.get(bwafQueryEncodeCbx.getItemAt(bwafQueryEncodeCbx.getSelectedIndex()));
        
        /* Check to see if double double */
        if (spaceEncoding.contains("%25%")) {
            String initPayload = bwafSpacePayloads.get(bwafSpacePayloadCbx.getItemAt(bwafSpacePayloadCbx.getSelectedIndex()));
            StringBuilder encChar = new StringBuilder();
            encChar.append(toHex(initPayload.charAt(0) / 16));
            encChar.append(toHex(initPayload.charAt(0) % 16));
            encChar.append('%');
            encChar.append(toHex(initPayload.charAt(1) / 16));
            encChar.append(toHex(initPayload.charAt(1) % 16));
            spacePayload = spaceEncoding + encChar;
        } else {
            spacePayload = spaceEncoding + bwafSpacePayloads.get(bwafSpacePayloadCbx.getItemAt(bwafSpacePayloadCbx.getSelectedIndex()));
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
    bwafHppLocationCbx.setSelectedIndex(0);
    bwafCharEncodeCbx.setSelectedIndex(0);
    bwafQueryEncodeCbx.setSelectedIndex(0);
    bwafSpacePayloadCbx.setSelectedIndex(0);
    bwafPathInfoSizeCbx.setSelectedIndex(9);
    bwafPathObfuscSizeCbx.setSelectedIndex(9);

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
    bwafPanel.add(bwafPathInfoSizeLabel);
    bwafPanel.add(bwafPathInfoSizeCbx);
    bwafPanel.add(bwafPathObfuscLabel);
    bwafPanel.add(bwafPathObfuscDescLabel);
    bwafPanel.add(bwafPathObfuscCbx);
    bwafPanel.add(bwafPathObfuscSizeLabel);
    bwafPanel.add(bwafPathObfuscSizeCbx);
    bwafPanel.add(bwafParamObfuscLabel);
    bwafPanel.add(bwafParamObfuscDescLabel);
    bwafPanel.add(bwafParamObfuscCbx);
    bwafPanel.add(bwafHppCheckLabel);
    bwafPanel.add(bwafHppCheck);
    bwafPanel.add(bwafHppCheckDescLabel);
    bwafPanel.add(bwafHppLocationLabel);
    bwafPanel.add(bwafHppLocationCbx);
    bwafPanel.add(bwafHppValueLabel);
    bwafPanel.add(bwafHppValueText);
    bwafPanel.add(bwafSetHeaderBtn);
    bwafPanel.add(bwafSetHeaderDescLabel);
    bwafPanel.add(bwafCharEncodeLabel);
    bwafPanel.add(bwafCharEncodeDescLabel);
    bwafPanel.add(bwafCharEncodeCbx);
    bwafPanel.add(bwafQueryEncodeLabel);
    bwafPanel.add(bwafQueryEncodeDescLabel);
    bwafPanel.add(bwafQueryEncodeCbx);
    bwafPanel.add(bwafSpacePayloadLabel);
    bwafPanel.add(bwafSpacePayloadCbx);
    
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
  
  /* Hex encoding for URLs */
  private static char toHex(int ch) {
      return (char) (ch < 10 ? '0' + ch : 'A' + ch - 10);
  }

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
                
                /* Perform character encoding obfuscation */
                if (reqPath.contains("/") && !charEncoding.contains("None")) {
                    StringBuilder encodeReplace = new StringBuilder(reqPath);
                    char encChar1;
                    char encChar2;
                    char encChar3;
                    
                    if (reqPath.lastIndexOf("/") > 0) {                    
                        encChar1 = reqPath.charAt(reqPath.lastIndexOf("/")-1);
                    } else {
                        encChar1 = '/';
                    }
                    
                    if (reqPath.length() > 1) {
                        encChar2 = reqPath.charAt(reqPath.lastIndexOf("/")+1);
                    } else {
                        encChar2 = '/';
                    }
                    
                    if (reqPath.length() > 2) {
                        encChar3 = reqPath.charAt(reqPath.lastIndexOf("/")+2);
                    } else {
                        encChar3 = '/';
                    }
                    
                    StringBuilder encChar = new StringBuilder();
                    
                    if (reqPath.lastIndexOf("/") > 0 && !String.valueOf(encChar1).contains("/") 
                            && !String.valueOf(encChar1).contains("?") && !String.valueOf(encChar1).contains("=")
                            && !String.valueOf(encChar1).contains(";") && !String.valueOf(encChar1).contains("&")) {

                        /* Add encoding to character before / */
                        encChar.append(charEncoding);
                        
                        /* Check to see if double double */
                        if (charEncoding.contains("%25%")) {
                            StringBuilder firstEncode = new StringBuilder();
                            firstEncode.append(toHex(encChar1 / 16));
                            firstEncode.append(toHex(encChar1 % 16));
                            encChar.append(toHex(firstEncode.charAt(0) / 16));
                            encChar.append(toHex(firstEncode.charAt(0) % 16));
                            encChar.append('%');
                            encChar.append(toHex(firstEncode.charAt(1) / 16));
                            encChar.append(toHex(firstEncode.charAt(1) % 16));
                        } else {
                            encChar.append(toHex(encChar1 / 16));
                            encChar.append(toHex(encChar1 % 16));
                        }
                        
                        /* Replace character in URL string */
                        encodeReplace.replace(reqPath.lastIndexOf("/")-1, reqPath.lastIndexOf("/"), encChar.toString() );
                        newPath = encodeReplace.toString();
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                        
                    } else if (reqPath.length() > 2 && !String.valueOf(encChar2).contains("/") 
                            && !String.valueOf(encChar2).contains("?") && !String.valueOf(encChar2).contains("=")
                            && !String.valueOf(encChar2).contains(";") && !String.valueOf(encChar2).contains("&")) {
                        
                        /* Add encoding to character after / */
                        encChar.append(charEncoding);
                        
                        /* Check to see if double double */
                        if (charEncoding.contains("%25%")) {
                            StringBuilder firstEncode = new StringBuilder();
                            firstEncode.append(toHex(encChar2 / 16));
                            firstEncode.append(toHex(encChar2 % 16));
                            encChar.append(toHex(firstEncode.charAt(0) / 16));
                            encChar.append(toHex(firstEncode.charAt(0) % 16));
                            encChar.append('%');
                            encChar.append(toHex(firstEncode.charAt(1) / 16));
                            encChar.append(toHex(firstEncode.charAt(1) % 16));
                        } else {
                            encChar.append(toHex(encChar2 / 16));
                            encChar.append(toHex(encChar2 % 16));
                        }
                        
                        /* Replace character in URL string */
                        encodeReplace.replace(reqPath.lastIndexOf("/")+1, reqPath.lastIndexOf("/")+2, encChar.toString() );
                        newPath = encodeReplace.toString();
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                        
                    } else if (reqPath.length() > 3 && !String.valueOf(encChar3).contains("/") 
                            && !String.valueOf(encChar3).contains("?") && !String.valueOf(encChar3).contains("=")
                            && !String.valueOf(encChar3).contains(";") && !String.valueOf(encChar3).contains("&")) {
                        
                        /* Add encoding to  second character after / */
                        encChar.append(charEncoding);
                        
                        /* Check to see if double double */
                        if (charEncoding.contains("%25%")) {
                            StringBuilder firstEncode = new StringBuilder();
                            firstEncode.append(toHex(encChar3 / 16));
                            firstEncode.append(toHex(encChar3 % 16));
                            encChar.append(toHex(firstEncode.charAt(0) / 16));
                            encChar.append(toHex(firstEncode.charAt(0) % 16));
                            encChar.append('%');
                            encChar.append(toHex(firstEncode.charAt(1) / 16));
                            encChar.append(toHex(firstEncode.charAt(1) % 16));
                        } else {
                            encChar.append(toHex(encChar3 / 16));
                            encChar.append(toHex(encChar3 % 16));
                        }
                        
                        /* Replace character in URL string */
                        encodeReplace.replace(reqPath.lastIndexOf("/")+2, reqPath.lastIndexOf("/")+3, encChar.toString() );
                        newPath = encodeReplace.toString();
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                        
                    }
                }
            
                /* Obfuscate the last path (/) value */
                if (!pathObfuscationBypass.startsWith("NoObfuscation")) {
                
                    /* If there was a slash, replace last one with obfuscated version */
                    if (reqPath.contains("/") && newPath.isEmpty()) {
                        StringBuilder slashReplace = new StringBuilder(reqPath);
                        slashReplace.replace(reqPath.lastIndexOf("/"), reqPath.lastIndexOf("/")+1, pathObfuscationBypass );
                        newPath = slashReplace.toString();
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (reqPath.contains("/")) {
                        StringBuilder slashReplace = new StringBuilder(newPath);
                        slashReplace.replace(newPath.lastIndexOf("/"), newPath.lastIndexOf("/")+1, pathObfuscationBypass );
                        newPath = slashReplace.toString();
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    }
                }
        
                /* Set path info in URL */
                if (!pathInfoBypass.startsWith("NoPathInfo")) {
                
                    /* Determine the right injection and set the new request */
                    if (pathInfoBypass.startsWith("PathInfoInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && newReq.isEmpty()) {
                        
                        if (newPath.isEmpty()) {
                            newPath = reqPath + "/" + defaultPathParam;
                        } else {
                            newPath = newPath + "/" + defaultPathParam;
                        }
                        
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (pathInfoBypass.startsWith("PathInfoInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && !newReq.isEmpty()) {
                        
                        if (newPath.isEmpty()) {
                            newPath = reqPath + "/" + defaultPathParam;
                        } else {
                            newPath = newPath + "/" + defaultPathParam;
                        }
                        
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                    } else if (pathInfoBypass.startsWith("PathParametersInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && newReq.isEmpty()) {
                        
                        if (newPath.isEmpty()) {
                            newPath = reqPath + ";" + defaultPathParam + "=" + defaultPathValue;
                        } else {
                            newPath = newPath + ";" + defaultPathParam + "=" + defaultPathValue;
                        }
                        
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (pathInfoBypass.startsWith("PathParametersInjection") && !reqPath.contains(defaultPathParam) && !newQuery.contains(defaultPathParam) && !newReq.isEmpty()) {
                        
                        if (newPath.isEmpty()) {
                            newPath = reqPath + ";" + defaultPathParam + "=" + defaultPathValue;
                        } else {
                            newPath = newPath + ";" + defaultPathParam + "=" + defaultPathValue;
                        }
                        
                        newReq = reqMethod + " " + newPath + newQuery + newRef + " " + defaultHttpVersion;
                    }
                }
                
                /* Add special character to beginning of all parameter names */
                if (!paramObfuscationBypass.startsWith("None")) {
                    
                    /* Determine the right injection and set the new request in URL */
                    if (newQuery.startsWith("?") && !newQuery.startsWith("?" + paramObfuscationBypass) && newReq.isEmpty()) {
                        newQuery = newQuery.replaceFirst("\\?", "?" + paramObfuscationBypass);
                        newQuery = newQuery.replaceAll("&", "&" + paramObfuscationBypass);
                        String updPath = "";
                        
                        if (newPath.isEmpty()) {
                            updPath = reqPath;
                        } else {
                            updPath = newPath;
                        }
                        
                        newReq = reqMethod + " " + updPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (newQuery.startsWith("?") && !newQuery.startsWith("?" + paramObfuscationBypass) && !newReq.isEmpty()) {
                        newQuery = newQuery.replaceFirst("\\?", "?" + paramObfuscationBypass);
                        newQuery = newQuery.replaceAll("&", "&" + paramObfuscationBypass);
                        String updPath = "";
                        
                        if (newPath.isEmpty()) {
                            updPath = reqPath;
                        } else {
                            updPath = newPath;
                        }
                        
                        newReq = reqMethod + " " + updPath + newQuery + newRef + " " + defaultHttpVersion;
                    }
                    
                    /* Determine the right injection and set the new request in POST body */
                    if (!reqBody.startsWith(paramObfuscationBypass) && reqMethod.startsWith("POST")) {
                        reqBody = paramObfuscationBypass + reqBody.replaceAll("&", "&" + paramObfuscationBypass);
                    }
                }
                
                /* Replace space characters with specially encoded non-standard space characters */
                if (!spaceEncoding.startsWith("None")) {
                    if (newReq.isEmpty() && newQuery.startsWith("?")) {
                        String updQuery = "";
                        
                        /* Get the params so that we can change the spaces in each */
                        if (newQuery.contains("&") && newQuery.contains("=")) {
                            for (String pageFields: newQuery.split("&")) {
                                String[] pageParams = pageFields.split("=");
                                String updParam = pageParams[1].replaceAll("\\+", spacePayload);
                                updParam = updParam.replaceAll("%2[bB]", spacePayload);
                                updParam = updParam.replaceAll("\\s+", spacePayload);
                                updParam = updParam.replaceAll("%20", spacePayload);
                                updQuery = updQuery + pageParams[0] + "=" + updParam + "&";
                            }
                        } else if (newQuery.contains("=")) {
                            String[] pageParams = newQuery.split("=");
                            String updParam = pageParams[1].replaceAll("\\+", spacePayload);
                            updParam = updParam.replaceAll("%2[bB]", spacePayload);
                            updParam = updParam.replaceAll("\\s+", spacePayload);
                            updParam = updParam.replaceAll("%20", spacePayload);
                            updQuery = pageParams[0] + "=" + updParam + "&";
                        }
                        
                        newQuery = "?" + updQuery.substring(1, updQuery.length()-1);
                        String updPath = "";
                        
                        if (newPath.isEmpty()) {
                            updPath = reqPath;
                        } else {
                            updPath = newPath;
                        }
                        
                        newReq = reqMethod + " " + updPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (!newReq.isEmpty() && newQuery.startsWith("?")) {
                        String updQuery = "";
                        
                        /* Get the params so that we can change the spaces in each */
                        if (newQuery.contains("&") && newQuery.contains("=")) {
                            for (String pageFields: newQuery.split("&")) {
                                String[] pageParams = pageFields.split("=");
                                String updParam = pageParams[1].replaceAll("\\+", spacePayload);
                                updParam = updParam.replaceAll("%2[bB]", spacePayload);
                                updParam = updParam.replaceAll("\\s+", spacePayload);
                                updParam = updParam.replaceAll("%20", spacePayload);
                                updQuery = updQuery + pageParams[0] + "=" + updParam + "&";
                            }
                        } else if (newQuery.contains("=")) {
                            String[] pageParams = newQuery.split("=");
                            String updParam = pageParams[1].replaceAll("\\+", spacePayload);
                            updParam = updParam.replaceAll("%2[bB]", spacePayload);
                            updParam = updParam.replaceAll("\\s+", spacePayload);
                            updParam = updParam.replaceAll("%20", spacePayload);
                            updQuery = pageParams[0] + "=" + updParam + "&";;
                        }
                        
                        newQuery = "?" + updQuery.substring(1, updQuery.length()-1);
                        String updPath = "";
                        
                        if (newPath.isEmpty()) {
                            updPath = reqPath;
                        } else {
                            updPath = newPath;
                        }
                        
                        newReq = reqMethod + " " + updPath + newQuery + newRef + " " + defaultHttpVersion;
                    }
                    
                    /* Determine the right injection and set the new request in POST body */
                    if (reqMethod.startsWith("POST")) {
                        String updQuery = "";
                        
                        /* Get the params so that we can change the spaces in each */
                        if (reqBody.contains("&") && reqBody.contains("=")) {
                            for (String pageFields: reqBody.split("&")) {
                                String[] pageParams = pageFields.split("=");
                                String updParam = pageParams[1].replaceAll("\\+", spacePayload);
                                updParam = updParam.replaceAll("%2[bB]", spacePayload);
                                updParam = updParam.replaceAll("\\s+", spacePayload);
                                updParam = updParam.replaceAll("%20", spacePayload);
                                updQuery = updQuery + pageParams[0] + "=" + updParam + "&";
                            }
                        } else if (reqBody.contains("=")) {
                            String[] pageParams = reqBody.split("=");
                            String updParam = pageParams[1].replaceAll("\\+", spacePayload);
                            updParam = updParam.replaceAll("%2[bB]", spacePayload);
                            updParam = updParam.replaceAll("\\s+", spacePayload);
                            updParam = updParam.replaceAll("%20", spacePayload);
                            updQuery = updQuery + pageParams[0] + "=" + updParam + "&";
                        }
                        
                        newQuery = updQuery.substring(0, updQuery.length()-1);
                        reqBody = newQuery;
                    }
                }
                
                /* Perform HPP if enabled */
                if (bypassHpp == 1) {
                    if (newReq.isEmpty() && newQuery.startsWith("?")) {
                        String updQuery = "";
                        
                        /* Get the params so that we can either change the first or last to 1 */
                        if (newQuery.contains("&") && newQuery.contains("=")) {
                            for (String pageFields: newQuery.split("&")) {
                                String[] pageParams = pageFields.split("=");
                                updQuery = updQuery + pageParams[0] + "=" + defaultHppValue + "&";
                            }
                        } else if (newQuery.contains("=")) {
                            String[] pageParams = newQuery.split("=");
                            updQuery = updQuery + pageParams[0] + "=" + defaultHppValue + "&";
                        }
                        
                        /* Figure out whether to set first or duplicate param to 1 */
                        if (bypassHppLocation.startsWith("First")) {
                            newQuery = newQuery + "&" + updQuery.substring(1, updQuery.length()-1);
                        } else {
                            newQuery = updQuery + newQuery.substring(1, newQuery.length());
                        }
                        
                        String updPath = "";
                        
                        if (newPath.isEmpty()) {
                            updPath = reqPath;
                        } else {
                            updPath = newPath;
                        }
                        
                        newReq = reqMethod + " " + updPath + newQuery + newRef + " " + defaultHttpVersion;
                        updateUrl = 1;
                    } else if (!newReq.isEmpty() && newQuery.startsWith("?")) {
                        String updQuery = "";
                        
                        /* Get the params so that we can either change the first or last to 1 or value */
                        if (newQuery.contains("&") && newQuery.contains("=")) {
                            for (String pageFields: newQuery.split("&")) {
                                String[] pageParams = pageFields.split("=");
                                updQuery = updQuery + pageParams[0] + "=" + defaultHppValue + "&";
                            }
                        } else if (newQuery.contains("=")) {
                            String[] pageParams = newQuery.split("=");
                            updQuery = updQuery + pageParams[0] + "=" + defaultHppValue + "&";
                        }
                        
                        /* Figure out whether to set first or duplicate param to 1 or value */
                        if (bypassHppLocation.startsWith("First")) {
                            newQuery = newQuery + "&" + updQuery.substring(1, updQuery.length()-1);
                        } else {
                            newQuery = updQuery + newQuery.substring(1, newQuery.length());
                        }
                        
                        String updPath = "";
                        
                        if (newPath.isEmpty()) {
                            updPath = reqPath;
                        } else {
                            updPath = newPath;
                        }
                        
                        newReq = reqMethod + " " + updPath + newQuery + newRef + " " + defaultHttpVersion;
                    }
                    
                    /* Determine the right injection and set the new request in POST body */
                    if (reqMethod.startsWith("POST")) {
                        String updQuery = "";
                        
                        /* Get the params so that we can either change the first or last to 1 */
                        if (reqBody.contains("&") && reqBody.contains("=")) {
                            for (String pageFields: reqBody.split("&")) {
                                String[] pageParams = pageFields.split("=");
                                updQuery = updQuery + pageParams[0] + "=" + defaultHppValue + "&";
                            }
                        } else if (reqBody.contains("=")) {
                            String[] pageParams = reqBody.split("=");
                            updQuery = updQuery + pageParams[0] + "=" + defaultHppValue + "&";
                        }
                        
                        /* Figure out whether to set first or duplicate param to 1 */
                        if (bypassHppLocation.startsWith("First")) {
                            newQuery = reqBody + "&" + updQuery.substring(0, updQuery.length()-1);
                        } else {
                            newQuery = updQuery + reqBody;
                        }
                        
                        reqBody = newQuery;
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