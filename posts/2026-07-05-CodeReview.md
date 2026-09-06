---
title: "A guide to Hunting vulnerabilities in open-source. Part 1: Reverse Engineering CVE-2026-34486 and CVE-2026-29146"
date: 2026-07-05
categories: [Security, White-box, Code review, Vulnerability research]
tags:
  [
    Security,
    Whitebox,
    CodeReview,
    VulnResearch,
    Auditing,
    AppSec,
    SecureCode,
    Exploits,
    BugHunting
  ]
---

Hi, in this blog post I'm going to share my journey on source code review and mainly, how to find and report vulnerabilities in open-source code and how to choose targets. As of today it is 7th of July 2026 where I too began with (almost) no experience learning code review, besides programming and web bug bounty work I didn't do much.

# Where do I start?

A great place to start is knowing what kind of application are you testing, is it web? Is it embedded software? what kind of vulnerabilities and which programming language is the project you're analyzing using.
For example, if I'm looking at some IoT firmware I'll have to know which language is the IoT firmware using, if it's using C/C++ use-after-free's, buffer overflows and other memory corruption vulnerabilities might be worth looking into. If it's using something like rust, more or less, since rust is specifically made to replace C/C++ by mentaining it's low level surface and introducing more secure coding practices.
If it's something like a web service and the api code is available start by looking into that, might be worth while looking into authentication, IDOR, XSS, SQLi, etc. and later on business logic vulnerabilities in the code and other good stuff.
Basically any user-controlled input and any action you can perform on that product it's worth checking, this is mainly due to the reason that exploitability comes from dynamic code, dynamic code is code the user can manipulate, the code users cannot manipulate is static code, which is useless cause static code will always remain the same regardless of anything.

# The Beginning

First of all we want to know what do these vulnerabilities in source code look like. So what are we going to do is analyze published CVEs so we could gain an insight in the code to build our pattern recognition.
A great resource on how you can do that is [this video right here](https://youtu.be/wEVcv88BoJ4?si=e84isGwcm3V6Z0Yi) this channel doesn't have that many resources but it does give some good insight into code review.

Alright, so I opened twitter and searched for recently published CVEs and i came by CVE-2026-34486, an unauthenticated RCE vulnerability in Apache Tomcat. The description goes as follows:

```text
Missing Encryption of Sensitive Data vulnerability in Apache Tomcat due
to the fix for CVE-2026-29146 allowing the bypass of the
EncryptInterceptor. This issue affects Apache Tomcat: 11.0.20, 10.1.53,
9.0.116. Users are recommended to upgrade to version 11.0.21, 10.1.54 or
9.0.117, which fix the issue.
```

so we're gonna clone the repository of Apache Tomcat to see what we're dealing with:

```bash
git clone https://github.com/apache/tomcat.git
```

Running the following command we will be able to pinpoint the vulnerable version:

```bash
git tag | grep "11.0.20"
```

#### Result

```bash
11.0.20
```

Perfect! There is only one version to work with. The same goes for 11.0.21.

Running the following command we will be able to output the changes between 11.0.20 to 11.0.21 to a file we can analyze.

```bash
git diff 11.0.20 11.0.21 > CVE-2026-34486.diff
```

I was facing some issues with the file format, running `file CVE-2026-34486.diff` i got the following output:

```bash
CVE-2026-34486.diff: unified diff output text, 1st line
"diff --git a/.gitignore b/.gitignore", 2nd line "", 3rd line "index 02db74388d..3634dc1cd7 100644", Unicode text, UTF-16, little-endian text, with very long lines (303), with CRLF line terminators
```

I asked ChatGPT how i might fix this and it gave me the following command:

```bash
iconv -f UTF-16LE -t UTF-8 CVE-2026-34486.diff > CVE-2026-34486.utf8.diff
```

it basically converts UTF-16 encoding into UTF-8 so it can be processed.

Okay, now let's begin the analysis. Running the following grep command retrieved me the files changed in the patch:

```bash
grep '^+++' CVE-2026-34486.utf8.diff
```

#### Result

```bash
+++ b/.gitignore
+++ b/BUILDING.txt
+++ b/build.properties.default
+++ b/build.properties.release
+++ b/java/org/apache/catalina/core/LocalStrings_fr.properties
+++ b/java/org/apache/catalina/core/LocalStrings_ja.properties
+++ b/java/org/apache/catalina/ha/tcp/ReplicationValve.java
+++ b/java/org/apache/catalina/manager/host/HostManagerServlet.java
+++ b/java/org/apache/catalina/mapper/LocalStrings.properties
+++ b/java/org/apache/catalina/mapper/Mapper.java
+++ b/java/org/apache/catalina/mapper/MappingData.java
+++ b/java/org/apache/catalina/servlets/WebdavServlet.java
+++ b/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java
+++ b/java/org/apache/catalina/tribes/group/interceptors/LocalStrings_fr.properties
+++ b/java/org/apache/catalina/tribes/group/interceptors/LocalStrings_ja.properties
+++ b/java/org/apache/catalina/tribes/membership/cloud/AbstractStreamProvider.java
+++ b/java/org/apache/catalina/tribes/membership/cloud/LocalStrings.properties
+++ b/java/org/apache/catalina/tribes/membership/cloud/TokenStreamProvider.java
+++ b/java/org/apache/catalina/valves/AbstractAccessLogValve.java
+++ b/java/org/apache/coyote/http11/filters/ChunkedOutputFilter.java
+++ b/java/org/apache/coyote/http2/Http2Parser.java
+++ b/java/org/apache/tomcat/util/http/parser/LocalStrings_fr.properties
+++ b/java/org/apache/tomcat/util/http/parser/LocalStrings_ja.properties
+++ b/java/org/apache/tomcat/util/net/LocalStrings.properties
+++ b/java/org/apache/tomcat/util/net/LocalStrings_fr.properties
+++ b/java/org/apache/tomcat/util/net/LocalStrings_ja.properties
+++ b/java/org/apache/tomcat/util/net/NioEndpoint.java
+++ b/java/org/apache/tomcat/util/net/SSLSupport.java
+++ b/java/org/apache/tomcat/util/net/SecureNio2Channel.java
+++ b/java/org/apache/tomcat/util/net/SecureNioChannel.java
+++ b/java/org/apache/tomcat/util/net/openssl/ciphers/OpenSSLCipherConfigurationParser.java
+++ b/java/org/apache/tomcat/util/net/openssl/panama/OpenSSLContext.java
+++ b/java/org/apache/tomcat/util/net/openssl/panama/OpenSSLEngine.java
+++ b/java/org/apache/tomcat/util/net/openssl/panama/OpenSSLUtil.java
+++ b/res/maven/mvn.properties.default
+++ b/res/maven/mvn.properties.release
+++ b/test/org/apache/catalina/authenticator/TestSSLAuthenticator.java
+++ b/test/org/apache/catalina/connector/TestValidateClientSessionId.java
+++ b/test/org/apache/catalina/filters/TestHttpHeaderSecurityFilter.java
+++ b/test/org/apache/catalina/filters/TesterHttpServletRequest.java
+++ b/test/org/apache/catalina/storeconfig/TestStoreConfig.java
+++ b/test/org/apache/catalina/valves/TestJsonErrorReportValve.java
+++ b/test/org/apache/coyote/http11/filters/TestChunkedOutputFilter.java
+++ b/test/org/apache/coyote/http2/TestHttp2Section_6_2.java
+++ b/test/org/apache/tomcat/util/net/TestAlpnFallback.java
+++ b/test/org/apache/tomcat/util/net/TestLargeClientHello.java
+++ b/test/org/apache/tomcat/util/net/TestSslHandshakeFailure.java
+++ b/test/org/apache/tomcat/util/net/TesterKeystoreGenerator.java
+++ b/test/org/apache/tomcat/util/net/TesterSupport.java
+++ b/test/org/apache/tomcat/util/net/ocsp/TestOcspEnabled.java
+++ b/test/org/apache/tomcat/util/net/ocsp/TestOcspSoftFailInternalError.java
+++ b/test/org/apache/tomcat/util/net/ocsp/TestOcspSoftFailTryLater.java
+++ b/test/org/apache/tomcat/util/net/ocsp/TesterOcspResponder.java
+++ b/test/org/apache/tomcat/util/net/ocsp/TesterOcspResponderServlet.java
+++ b/webapps/docs/changelog.xml
+++ b/webapps/docs/config/filter.xml
+++ b/webapps/docs/config/http.xml
+++ b/webapps/docs/config/listeners.xml
```

nice! Here it is, on line 13 the file `EncryptInterceptor.java` which is mentioned in the CVE description.
Okayyy, so I started examaning the `CVE-2026-34486.utf8.diff` file for any sign on of `EncryptInterceptor.java` and it came back with quite the interesting results. Here is what I found:

```java
diff --git a/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java b/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java
index 31866f254c..291f46724c 100644
--- a/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java
+++ b/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java
@@ -140,10 +140,10 @@ public class EncryptInterceptor extends ChannelInterceptorBase implements Encryp
             xbb.clear();
             xbb.append(data, 0, data.length);
 
+            super.messageReceived(msg);
         } catch (GeneralSecurityException gse) {
             log.error(sm.getString("encryptInterceptor.decrypt.failed"), gse);
         }
-        super.messageReceived(msg);
     }
```
It seems like in the previous vulnerable version `super.messageReceived(msg)` is executed regardless of whether decryption succeeds or fails. So if `decrypt(msg);`
throws a `GeneralSecurityException` error, Tomcat logs the error, continues to process the message and passes the message to the next interceptor in the chain. This aligns perfectly with what the CVE tells us:

```text
Missing Encryption of Sensitive Data due to the fix for CVE-2026-29146
allowing the bypass of the EncryptInterceptor.
```

It's important to note that while the CVE-2026-34486 which is the one we are analyzing leads to RCE, it is a mere bypass of the security protocols implemented in CVE-2026-29146 which actually has the RCE vulnerability in it, facilitating the patch for CVE-2026-29146 useless, with the vulnerable component still being present via a bypass vulnerability which leads to RCE.
Okay, keeping that in mind we need to dig down the rabbit hole and investigate the CVE-2026-29146 which states:

```text
Padding Oracle vulnerability in Apache Tomcat's EncryptInterceptor with
default configuration. This issue affects Apache Tomcat: from 11.0.0-M1
through 11.0.18, from 10.0.0-M1 through 10.1.52, from 9.0.13 through
9.115, from 8.5.38 through 8.5.100, from 7.0.100 through 7.0.109.
Users are recommended to upgrade to version 11.0.19, 10.1.53 and
9.0.116, which fixes the issue.
```

I did the same process with CVE-2026-29146 and when i used vscode to search for the code snippet and i actually got 2, but none relevant besides:

```java
diff --git a/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java b/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java
index 31866f254c..291f46724c 100644
--- a/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java
+++ b/java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java
@@ -140,10 +140,10 @@ public class EncryptInterceptor extends ChannelInterceptorBase implements Encryp
             xbb.clear();
             xbb.append(data, 0, data.length);
 
+            super.messageReceived(msg);
         } catch (GeneralSecurityException gse) {
             log.error(sm.getString("encryptInterceptor.decrypt.failed"), gse);
         }
-        super.messageReceived(msg);
     }
```

which is just the vulnerable component in CVE-2026-34486.


Okay but the really important part is *where* `super.messageReceived(msg);` *goes*? *and how is it being processed?*

Because i am new to this, I asked chatgpt what to do and where could i pinpoint where and how `super.messageReceived(msg)` is being processed and it told me to run these 2 commands:

```powershell
grep -R "class .*Interceptor" java/org/apache/catalina/tribes
grep -R "messageReceived(ChannelMessage" java/org/apache/catalina/tribes
```

#### Result

```java
grep -R "class .*Interceptor" java/org/apache/catalina/tribes            
java/org/apache/catalina/tribes/group/ChannelCoordinator.java:public class ChannelCoordinator extends ChannelInterceptorBase implements MessageListener {
java/org/apache/catalina/tribes/group/ChannelInterceptorBase.java:public abstract class ChannelInterceptorBase implements ChannelInterceptor {
java/org/apache/catalina/tribes/group/GroupChannel.java:public class GroupChannel extends ChannelInterceptorBase implements ManagedChannel, JmxChannel, GroupChannelMBean {
java/org/apache/catalina/tribes/group/GroupChannel.java:    public static class InterceptorIterator implements Iterator<ChannelInterceptor> {
java/org/apache/catalina/tribes/group/InterceptorPayload.java:public class InterceptorPayload {
java/org/apache/catalina/tribes/group/interceptors/DomainFilterInterceptor.java:public class DomainFilterInterceptor extends ChannelInterceptorBase implements DomainFilterInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java:public class EncryptInterceptor extends ChannelInterceptorBase implements EncryptInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/FragmentationInterceptor.java:public class FragmentationInterceptor extends ChannelInterceptorBase implements FragmentationInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/GzipInterceptor.java:public class GzipInterceptor extends ChannelInterceptorBase implements GzipInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/MessageDispatchInterceptor.java:public class MessageDispatchInterceptor extends ChannelInterceptorBase implements MessageDispatchInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/NonBlockingCoordinator.java:public class NonBlockingCoordinator extends ChannelInterceptorBase {
java/org/apache/catalina/tribes/group/interceptors/NonBlockingCoordinator.java:    public static class CoordinationEvent implements InterceptorEvent {
java/org/apache/catalina/tribes/group/interceptors/OrderInterceptor.java:public class OrderInterceptor extends ChannelInterceptorBase {
java/org/apache/catalina/tribes/group/interceptors/SimpleCoordinator.java:public class SimpleCoordinator extends ChannelInterceptorBase {
java/org/apache/catalina/tribes/group/interceptors/StaticMembershipInterceptor.java:public class StaticMembershipInterceptor extends ChannelInterceptorBase implements StaticMembershipInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/TcpFailureDetector.java:public class TcpFailureDetector extends ChannelInterceptorBase implements TcpFailureDetectorMBean {
java/org/apache/catalina/tribes/group/interceptors/TcpPingInterceptor.java:public class TcpPingInterceptor extends ChannelInterceptorBase implements TcpPingInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/ThroughputInterceptor.java:public class ThroughputInterceptor extends ChannelInterceptorBase implements ThroughputInterceptorMBean {
java/org/apache/catalina/tribes/group/interceptors/TwoPhaseCommitInterceptor.java:public class TwoPhaseCommitInterceptor extends ChannelInterceptorBase {
```
```bash
grep -R "messageReceived(ChannelMessage" java/org/apache/catalina/tribes
java/org/apache/catalina/tribes/ChannelInterceptor.java:    void messageReceived(ChannelMessage data);
java/org/apache/catalina/tribes/group/ChannelCoordinator.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/ChannelInterceptorBase.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/GroupChannel.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/DomainFilterInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/FragmentationInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/GzipInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/NonBlockingCoordinator.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/OrderInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/StaticMembershipInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/TcpFailureDetector.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/TcpPingInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/ThroughputInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/TwoPhaseCommitInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/membership/McastService.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/MessageListener.java:    void messageReceived(ChannelMessage msg);
```

This data shows that messageReceived() is a core message-processing primitive used throughout Tomcat Tribes. When EncryptInterceptor calls with `super.messageReceived(msg);` it isn't handing the message to a single consumer. It's forwarding it through an entire interceptor chain. So we want to see what `messageReceived(ChannelMessage msg)` looks like and if its vulnerable, we do so by opening the file or running the following command in the tomcat repository:

```bash
grep -A 20 -B 5 "messageReceived(ChannelMessage" java/org/apache/catalina/tribes/group/ChannelInterceptorBase.java
```

#### Result

```java
            getNext().sendMessage(destination, msg, payload);
        }
    }

    @Override
    public void messageReceived(ChannelMessage msg) {
        if (getPrevious() != null) {
            getPrevious().messageReceived(msg);
        }
    }

    @Override
    public void memberAdded(Member member) {
        // notify upwards
        if (getPrevious() != null) {
            getPrevious().memberAdded(member);
        }
    }

    @Override
    public void memberDisappeared(Member member) {
        // notify upwards
        if (getPrevious() != null) {
            getPrevious().memberDisappeared(member);
        }
    }
```

This confirms the message keeps moving through the interceptor chain toward the application layer regardless of whether decrypt() succeeded. Great, knowing we have the files corresponding with `messageReceived(ChannelMessage msg)` that is tied to the attacker user controlled input `super.messageReceived(msg);` with the encryption bypass, we just need to track down the vulnerable deserealization component. And we do so by running the following command:

```bash
grep -rn "deserialize\|readObject" java/org/apache/catalina/tribes
```

### Result

```bash
java/org/apache/catalina/tribes/ByteMessage.java:25: * A byte message is not serialized and deserialized by the channel instead it is sent as a byte array.
java/org/apache/catalina/tribes/ByteMessage.java:29: * deserialize the object properly.
java/org/apache/catalina/tribes/group/GroupChannel.java:287:                    fwd = XByteBuffer.deserialize(msg.getMessage().getBytesDirect(), 0, msg.getMessage().getLength());
java/org/apache/catalina/tribes/group/GroupChannel.java:289:                    log.error(sm.getString("groupChannel.unable.deserialize", msg), e);
java/org/apache/catalina/tribes/group/LocalStrings.properties:26:groupChannel.unable.deserialize=Unable to deserialize message:[{0}]
java/org/apache/catalina/tribes/group/LocalStrings_fr.properties:29:groupChannel.unable.deserialize=Impossible de désérialiser le message [{0}]
java/org/apache/catalina/tribes/group/LocalStrings_ja.properties:29:groupChannel.unable.deserialize=メッセージをデシリアライズできません： [{0}]
java/org/apache/catalina/tribes/group/LocalStrings_ko.properties:28:groupChannel.unable.deserialize=메시지를 역직렬화할 수 없습니다:[{0}]
java/org/apache/catalina/tribes/group/LocalStrings_zh_CN.properties:28:groupChannel.unable.deserialize=无法反序列化消息：[{0}]
java/org/apache/catalina/tribes/group/RpcMessage.java:81:        message = (Serializable) in.readObject();
java/org/apache/catalina/tribes/io/ChannelData.java:259:     * @param b The byte array to deserialize from
java/org/apache/catalina/tribes/io/XByteBuffer.java:430:     * Extracts a complete package from the buffer and deserializes it into a ChannelData object.
java/org/apache/catalina/tribes/io/XByteBuffer.java:433:     * @return the deserialized ChannelData object
java/org/apache/catalina/tribes/io/XByteBuffer.java:680:     * @return the deserialized object
java/org/apache/catalina/tribes/io/XByteBuffer.java:683:     * @throws ClassCastException if the deserialized object is not Serializable
java/org/apache/catalina/tribes/io/XByteBuffer.java:685:    public static Serializable deserialize(byte[] data) throws IOException, ClassNotFoundException, ClassCastException {
java/org/apache/catalina/tribes/io/XByteBuffer.java:686:        return deserialize(data, 0, data.length);
java/org/apache/catalina/tribes/io/XByteBuffer.java:694:     * @param length the length of the data to deserialize
java/org/apache/catalina/tribes/io/XByteBuffer.java:695:     * @return the deserialized object
java/org/apache/catalina/tribes/io/XByteBuffer.java:698:     * @throws ClassCastException if the deserialized object is not Serializable
java/org/apache/catalina/tribes/io/XByteBuffer.java:700:    public static Serializable deserialize(byte[] data, int offset, int length)
java/org/apache/catalina/tribes/io/XByteBuffer.java:702:        return deserialize(data, offset, length, null);
java/org/apache/catalina/tribes/io/XByteBuffer.java:712:     * @param length the length of the data to deserialize
java/org/apache/catalina/tribes/io/XByteBuffer.java:714:     * @return the deserialized object
java/org/apache/catalina/tribes/io/XByteBuffer.java:717:     * @throws ClassCastException if the deserialized object is not Serializable
java/org/apache/catalina/tribes/io/XByteBuffer.java:719:    public static Serializable deserialize(byte[] data, int offset, int length, ClassLoader[] cls)
java/org/apache/catalina/tribes/io/XByteBuffer.java:730:            message = stream.readObject();
java/org/apache/catalina/tribes/membership/MemberImpl.java:178:     * @return - the bytes for this member deserialized
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:302:                        mapMsg.deserialize(getExternalLoaders());
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:322:                        log.error(sm.getString("abstractReplicatedMap.unable.deserialize.MapMessage"), e);
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:599:                        msg.deserialize(getExternalLoaders());
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:699:            mapmsg.deserialize(getExternalLoaders());
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:720:            log.error(sm.getString("abstractReplicatedMap.unable.deserialize.MapMessage"), x);
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:742:            mapmsg.deserialize(getExternalLoaders());
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:744:            log.error(sm.getString("abstractReplicatedMap.unable.deserialize.MapMessage"), x);
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:1203:                    msg.deserialize(getExternalLoaders());
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:1772:                value = (V) XByteBuffer.deserialize(data, offset, length);
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:1916:        public void deserialize(ClassLoader[] cls) throws IOException, ClassNotFoundException {
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:1948:                throw new RuntimeException(sm.getString("mapMessage.deserialize.error.key"), e);
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:1957:         * @return The deserialized key
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:1969:            key = XByteBuffer.deserialize(keydata, 0, keydata.length, cls);
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:1992:                throw new RuntimeException(sm.getString("mapMessage.deserialize.error.value"), e);
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:2001:         * @return The deserialized value
java/org/apache/catalina/tribes/tipis/AbstractReplicatedMap.java:2013:            value = XByteBuffer.deserialize(valuedata, 0, valuedata.length, cls);
java/org/apache/catalina/tribes/tipis/LocalStrings.properties:33:abstractReplicatedMap.unable.deserialize.MapMessage=Unable to deserialize MapMessage.
java/org/apache/catalina/tribes/tipis/LocalStrings.properties:50:mapMessage.deserialize.error.key=Failed to deserialize MapMessage key
java/org/apache/catalina/tribes/tipis/LocalStrings.properties:51:mapMessage.deserialize.error.value=Failed to deserialize MapMessage value
java/org/apache/catalina/tribes/tipis/LocalStrings_fr.properties:36:abstractReplicatedMap.unable.deserialize.MapMessage=Impossible de désérialiser MapMessage
java/org/apache/catalina/tribes/tipis/LocalStrings_fr.properties:53:mapMessage.deserialize.error.key=Erreur de désérialisation de la clé du MapMessage
java/org/apache/catalina/tribes/tipis/LocalStrings_fr.properties:54:mapMessage.deserialize.error.value=Erreur de désérialisation de la valeur du MapMessage
java/org/apache/catalina/tribes/tipis/LocalStrings_ja.properties:36:abstractReplicatedMap.unable.deserialize.MapMessage=MapMessageのデシリアライズができません。
java/org/apache/catalina/tribes/tipis/LocalStrings_ja.properties:53:mapMessage.deserialize.error.key=MapMessage キーのデシリアライズに失敗しました。
java/org/apache/catalina/tribes/tipis/LocalStrings_ja.properties:54:mapMessage.deserialize.error.value=MapMessageの値のデシリアライズに失敗しました。
java/org/apache/catalina/tribes/tipis/LocalStrings_ko.properties:32:abstractReplicatedMap.unable.deserialize.MapMessage=MapMessage를 역직렬화할 수 없습니다.
java/org/apache/catalina/tribes/tipis/LocalStrings_ko.properties:49:mapMessage.deserialize.error.key=MapMessage.key()에서 역직렬화에 실패했습니다.
java/org/apache/catalina/tribes/tipis/LocalStrings_ko.properties:50:mapMessage.deserialize.error.value=MapMessage 값을 역직렬화하지 못했습니다.
java/org/apache/catalina/tribes/tipis/LocalStrings_zh_CN.properties:32:abstractReplicatedMap.unable.deserialize.MapMessage=无法反序列化映射消息。
java/org/apache/catalina/tribes/tipis/LocalStrings_zh_CN.properties:49:mapMessage.deserialize.error.key=反序列化MapMessage主键失败
java/org/apache/catalina/tribes/tipis/LocalStrings_zh_CN.properties:50:mapMessage.deserialize.error.value=MapMessage.value的反序列化误差
java/org/apache/catalina/tribes/tipis/ReplicatedMapEntry.java:37: * When the data is deserialized the logic is called in the following order<br>
java/org/apache/catalina/tribes/tipis/ReplicatedMapEntry.java:39: * 1. ReplicatedMapEntry entry = (ReplicatedMapEntry)objectIn.readObject();<br>
```

We can see from this that `GroupChannel.java` is part of:

```bash
java/org/apache/catalina/tribes/ChannelInterceptor.java:    void messageReceived(ChannelMessage data);
java/org/apache/catalina/tribes/group/ChannelCoordinator.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/ChannelInterceptorBase.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/GroupChannel.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/DomainFilterInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/EncryptInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/FragmentationInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/GzipInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/NonBlockingCoordinator.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/OrderInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/StaticMembershipInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/TcpFailureDetector.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/TcpPingInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/ThroughputInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/group/interceptors/TwoPhaseCommitInterceptor.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/membership/McastService.java:    public void messageReceived(ChannelMessage msg) {
java/org/apache/catalina/tribes/MessageListener.java:    void messageReceived(ChannelMessage msg);
```

which chains through everything else we talked about. Time to analyze `GroupChannel.java` and doing so i found the following code snippet:

```java
    /**
     * Callback from the interceptor stack. <br>
     * When a message is received from a remote node, this method will be invoked by the previous interceptor.<br>
     * This method can also be used to send a message to other components within the same application, but it's an
     * extreme case, and you're probably better off doing that logic between the applications itself.
     *
     * @param msg ChannelMessage
     */
    @Override
    public void messageReceived(ChannelMessage msg) {
        if (msg == null) {
            return;
        }
        try {
            if (Logs.MESSAGES.isTraceEnabled()) {
                Logs.MESSAGES.trace("GroupChannel - Received msg:" + new UniqueId(msg.getUniqueId()) + " at " +
                        new java.sql.Timestamp(System.currentTimeMillis()) + " from " + msg.getAddress().getName());
            }

            Serializable fwd;
            if ((msg.getOptions() & SEND_OPTIONS_BYTE_MESSAGE) == SEND_OPTIONS_BYTE_MESSAGE) {
                fwd = new ByteMessage(msg.getMessage().getBytes());
            } else {
                try {
                    fwd = XByteBuffer.deserialize(msg.getMessage().getBytesDirect(), 0, msg.getMessage().getLength());
                } catch (Exception e) {
                    log.error(sm.getString("groupChannel.unable.deserialize", msg), e);
                    return;
                }
            }
            if (Logs.MESSAGES.isTraceEnabled()) {
                Logs.MESSAGES.trace("GroupChannel - Receive Message:" + new UniqueId(msg.getUniqueId()) + " is " + fwd);
            }

            // get the actual member with the correct alive time
            Member source = msg.getAddress();
            boolean rx = false;
            boolean delivered = false;
            for (ChannelListener channelListener : channelListeners) {
                if (channelListener != null && channelListener.accept(fwd, source)) {
                    channelListener.messageReceived(fwd, source);
                    delivered = true;
                    // if the message was accepted by an RPC channel, that channel
                    // is responsible for returning the reply, otherwise we send an absence reply
                    if (channelListener instanceof RpcChannel) {
                        rx = true;
                    }
                }
            } // for
            if ((!rx) && (fwd instanceof RpcMessage)) {
                // if we have a message that requires a response,
                // but none was given, send back an immediate one
                sendNoRpcChannelReply((RpcMessage) fwd, source);
            }
```

Our focus is on this try block:

```java
try {
  fwd = XByteBuffer.deserialize(msg.getMessage().getBytesDirect(), 0, msg.getMessage().getLength());
  }
```

When we did this grep command:

```bash
grep -rn "deserialize\|readObject" java/org/apache/catalina/tribes
```

in the try block, a fwd variable is created. Which calls the `XByteBuffer` java file for the deserialization function used by `messageReceived(ChannelMessage msg)`

Now all we need to do is inspect the `deserialize()` function in `XByteBuffer.java` used by `messageReceived(ChannelMessage msg)` which is used by `super.messageReceived(msg);` and we found the following code:

```java
public static Serializable deserialize(byte[] data, int offset, int length, ClassLoader[] cls)
        throws IOException, ClassNotFoundException, ClassCastException {
    invokecount.addAndGet(1);
    Object message = null;
    if (cls == null) {
        cls = new ClassLoader[0];
    }
    if (data != null && length > 0) {
        InputStream instream = new ByteArrayInputStream(data, offset, length);
        ObjectInputStream stream;
        stream = (cls.length > 0) ? new ReplicationStream(instream, cls) : new ObjectInputStream(instream);
        message = stream.readObject();
        instream.close();
        stream.close();
    }
```

*We hit the jackpot!* Upon further analysis I determined that the javascript function `readObject()` is the primary source of Java Insecure Deserialization vulnerabilities (says so the all knowing **Google**). and it states as follows:

*When processing untrusted data, attackers can use "gadget chains" (a combination of existing classes on your classpath) to execute arbitrary code or commands on the server.*

Perfect! We can see that there is a variable `message` that uses another variable `stream` to call the vulnerable function, and stream contains the following line:

```java
stream = (cls.length > 0) ? new ReplicationStream(instream, cls) : new ObjectInputStream(instream);
```

This means attacker-controlled bytes that reach this function are indeed being deserialized using Java serialization, and the next thing to do is to investigate `ReplicationStream`

```java
public final class ReplicationStream extends ObjectInputStream {

    static final StringManager sm = StringManager.getManager(ReplicationStream.class);

    /**
     * The class loader we will use to resolve classes.
     */
    private ClassLoader[] classLoaders;

    /**
     * Construct a new instance of CustomObjectInputStream
     *
     * @param stream       The input stream we will read from
     * @param classLoaders The class loader array used to instantiate objects
     *
     * @exception IOException if an input/output error occurs
     */
    public ReplicationStream(InputStream stream, ClassLoader[] classLoaders) throws IOException {

        super(stream);
        this.classLoaders = classLoaders;
    }

    /**
     * Load the local class equivalent of the specified stream class description, by using the class loader assigned to
     * this Context.
     *
     * @param classDesc Class description from the input stream
     *
     * @exception ClassNotFoundException if this class cannot be found
     * @exception IOException            if an input/output error occurs
     */
    @Override
    public Class<?> resolveClass(ObjectStreamClass classDesc) throws ClassNotFoundException, IOException {
        String name = classDesc.getName();
        try {
            return resolveClass(name);
        } catch (ClassNotFoundException e) {
            return super.resolveClass(classDesc);
        }
    }

    /**
     * Resolve a class by name using the configured class loaders.
     *
     * @param name the class name
     * @return the resolved class
     * @exception ClassNotFoundException if this class cannot be found
     */
    public Class<?> resolveClass(String name) throws ClassNotFoundException {

        boolean tryRepFirst = name.startsWith("org.apache.catalina.tribes");
        try {
            if (tryRepFirst) {
                return findReplicationClass(name);
            } else {
                return findExternalClass(name);
            }
        } catch (Exception e) {
            if (tryRepFirst) {
                return findExternalClass(name);
            } else {
                return findReplicationClass(name);
            }
        }
    }
```

here the most interest part is:

```java
/**
     * Resolve a class by name using the configured class loaders.
     *
     * @param name the class name
     * @return the resolved class
     * @exception ClassNotFoundException if this class cannot be found
     */
    public Class<?> resolveClass(String name) throws ClassNotFoundException {

        boolean tryRepFirst = name.startsWith("org.apache.catalina.tribes");
        try {
            if (tryRepFirst) {
                return findReplicationClass(name);
            } else {
                return findExternalClass(name);
            }
        } catch (Exception e) {
            if (tryRepFirst) {
                return findExternalClass(name);
            } else {
                return findReplicationClass(name);
            }
        }
    }
```

There's no allow-list, no ObjectInputFilter, nothing checking what class is being instantiated. It just resolves whatever class name is embedded in the serialized stream. And as shown above, the actual call path in GroupChannel doesn't even go through this class, it uses plain ObjectInputStream, which is even less restricted.
That's it! Hope you're having a nice day!

:)




### Resources in-use

- [pwnable.kr](https://pwnable.kr/) — Great resource for learning buffer overflows, heap overflows, and integer vulnerabilities.
-[codereviewlab.com](https://www.codereviewlab.com/) - Practice static code analysis in realistic scenarios.