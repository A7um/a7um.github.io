---
title: Bypassing 5G/4G/WiFi Network Encryption Using "Length Side-Channel" to Hijack TCP/UDP Connections
date: 2025-08-01 10:56:27
tags: [wireless-security]
abstract: In today's digital era, wireless communication technologies such as 5G, 4G, and Wi-Fi have become essential infrastructure in our daily lives. These networks commonly employ advanced encryption protocols that theoretically provide effective protection for user communications. However, recent research findings published at EuroS&P 2025 by our Tencent Xuanwu Lab in collaboration with Professor Chen Jianjun's team from Tsinghua University have revealed a new security vulnerability called LenOracle. This research demonstrates that attackers can exploit radio frame length information as a side-channel to hijack TCP/UDP connections in encrypted networks without breaking the wireless encryption. We conducted tests in real commercial LTE networks and Wi-Fi environments, successfully injecting a forged short message into a victim device in TCP scenarios and polluting the victim device's DNS cache in UDP scenarios, demonstrating the potential destructive power of this attack on critical network services.
---
Originally published on the [Tencent Xuanwu Lab Blog](https://xlab.tencent.com/cn/2025/08/01/len-oracle/
)

In today's digital era, wireless communication technologies such as 5G, 4G, and Wi-Fi have become essential infrastructure in our daily lives. These networks commonly employ advanced encryption protocols that theoretically provide effective protection for user communications. However, recent research findings published at EuroS&P 2025 by our Tencent Xuanwu Lab in collaboration with Professor Chen Jianjun's team from Tsinghua University have revealed a new security vulnerability called LenOracle. This research demonstrates that attackers can exploit radio frame length information as a side-channel to hijack TCP/UDP connections in encrypted networks without breaking the wireless encryption. We conducted tests in real commercial LTE networks and Wi-Fi environments, successfully injecting a forged short message into a victim device in TCP scenarios and polluting the victim device's DNS cache in UDP scenarios, demonstrating the potential destructive power of this attack on critical network services.

How does this work? While encryption protocols in wireless networks can prevent attackers from eavesdropping on communication content or tampering with and injecting messages at the physical layer, at the transport layer, if attackers can obtain the four-tuple information (client IP, client port, server IP, server port) along with the sequence number (SEQ) and acknowledgment number (ACK), they can still inject arbitrary data into the corresponding network connection by sending forged packets with the spoofed four-tuple. These forged packets are routed through the Internet, ultimately modulated into radio frames and delivered to the victim device, thus indirectly achieving message injection into the wireless channel. In practice, attackers typically find it difficult to obtain critical information such as the four-tuple and sequence numbers. Our research has discovered that by combining radio frame length information with the working mechanism of Network Address Translation (NAT) and inherent characteristics of the TCP protocol, it is possible to gradually infer the target connection's four-tuple (source IP, source port, destination IP, destination port) and critical protocol state information (such as sequence numbers and acknowledgment numbers), thereby achieving hijacking of TCP/UDP communications in the network.

<!--more-->

## 0x01 What is a Length Side-Channel?

Side-channel attacks do not directly crack encryption algorithms, but instead indirectly infer information that should not be leaked by analyzing "byproducts" generated during network communication processes—such as packet length, transmission latency, etc.

The length side-channel in wireless networks that we propose is fundamentally caused by the fact that most wireless protocols employ stream ciphers for encryption. An important characteristic of stream ciphers is that the plaintext and ciphertext lengths are exactly the same before and after encryption. In actual communication, encrypted data packets are encapsulated into radio frames for transmission over wireless channels. Although the data content is encrypted, wireless eavesdroppers can still capture these frames and indirectly obtain the original plaintext packet length information by analyzing the length of each frame.

<center><img src='/static/len_oracle/stream-cipher-encryption.png' /></center>

## 0x02 Why Can Length Side-Channels Be Used for Off-Path Hijacking of TCP and UDP Connections

In network communications, whether TCP or UDP, a connection is uniquely identified by a four-tuple: client IP, client port, server IP, and server port. Theoretically, attackers need to master these four parameters to achieve off-path hijacking. However, in actual attack scenarios, the server's IP and port are often known or within a very limited set, for two reasons: on one hand, attackers typically clearly select a target server before launching an attack; on the other hand, many services (such as DNS, web servers) use fixed server IPs and ports in a region or application, for example, the commonly used DNS address 8.8.8.8:53. Therefore, in actual attacks, the attacker's focus is mainly on how to obtain the victim's external IP address and the external source port number used when communicating with the server.

For the UDP protocol, if attackers can obtain the victim's external IP and source port and can perform source IP spoofing (i.e., sending packets with forged source IP), they may be able to inject data into that connection—this attack method is called "off-path hijacking." For the TCP protocol, in addition to the four-tuple, attackers also need to accurately obtain the sequence number (SEQ) and acknowledgment number (ACK); otherwise, forged packets will be directly dropped by the protocol stack, making hijacking more difficult.

<center><img src='/static/len_oracle/data-exchange.png' /></center>

Our research has found that attackers can use side-channel information such as packet length exposed in wireless channels to gradually infer the source port number used by the victim, and even further obtain TCP connection parameters such as SEQ and ACK, thereby creating conditions for hijacking attacks. The victim's external IP address can be obtained without user interaction through methods such as RCS protocol vulnerabilities.

### Obtaining the Victim's External Source IP

Most home and enterprise networks operate under NAT (Network Address Translation) environments, where internal IPs are not visible and the external IP is typically the NAT IP of the victim's location. One method to obtain the IP is to use the RCS protocol to send a message to the victim's phone containing a preview image link pointing to the attacker's server. This message will trigger the victim to send a GET request to the attacker's server, thereby revealing the victim's public IP, with no user action required.

<center><img src='/static/len_oracle/xml-request.png' /></center>

Additionally, attackers can use geolocation information and base station locations, combined with carrier IP allocation patterns, to narrow down the range of public IP guessing.

### Using Length Side-Channel to Obtain the Victim's External Source Port

After determining the public IP, the next step is to obtain the external port assigned by NAT to the victim. NAT typically assigns ports within a certain range (such as the common Linux range 32768-61000), but which specific port is usually not visible to the external world. Attackers can construct packets of different lengths for different ports and send them to the external NAT IP where the victim is located. Only packets matching the real port will be forwarded by NAT and appear as encrypted frames in the wireless channel, which can be captured by the attacker. By analyzing the length characteristics of frames appearing in the wireless channel, attackers can obtain the victim's external port number.

<center><img src='/static/len_oracle/nat-ip-port.png' /></center>

### Using Length Side-Channel to Obtain Correct SEQ and ACK

For the UDP protocol, attackers can perform forged hijacking once they obtain the external IP and port. The TCP protocol is more complex—in addition to the four-tuple, it also requires accurate acquisition of the sequence number (SEQ) and acknowledgment number (ACK); otherwise, forged packets will be directly dropped.

At this point, the length side-channel plays a role again. Attackers can exploit the TCP protocol's Challenge ACK mechanism by sending forged packets with different sequence numbers to the server. If a packet is sent with a sequence number/acknowledgment number that falls within the window (In Window), the target machine will respond with a Challenge ACK packet; if the sequence number/acknowledgment number is completely wrong, the packet is directly dropped. By observing whether a fixed-length Challenge ACK frame appears in the victim's wireless channel, if it appears, it indicates that the guessed SEQ/ACK is within the correct range. Through continuous adjustment of the guessing range using methods such as binary search, it is ultimately possible to precisely obtain the valid SEQ and ACK of the TCP connection, thereby completely controlling the connection.

<center><img src='/static/len_oracle/challenge-ack.png' /></center>

## 0x03 Real-World Attack Demonstration

We demonstrated an attack method based on a real scenario: by hijacking the TCP long connection of RCS (also known as 5G messaging), arbitrary forged messages can be injected into the target. RCS is a TCP-based SMS protocol, and by hijacking its long connection, attackers can send arbitrary forged text messages to victims. The process of hijacking the TCP connection takes approximately 40 seconds. After successful hijacking, attackers only need to inject the forged SMS structure into the connection for the victim to receive any forged text message.

<center><img src='/static/len_oracle/real-world.png' /></center>

## 0x04 Summary and Security Reminders

The essence of this type of attack lies in the fact that even though wireless traffic is encrypted, metadata such as packet length and transmission timing still leak critical information. Attackers do not need to crack encryption algorithms; by merely analyzing the length of encrypted frames and protocol characteristics, they can gradually reconstruct the victim's connection parameters and achieve remote hijacking. The reason length information leakage occurs is mainly because wireless protocols commonly employ stream ciphers, which result in packet lengths being exactly the same before and after encryption. Therefore, this issue can be directly fixed at the protocol layer by adding random padding. However, this type of fix involves protocol stack updates and has high costs.

Fortunately, if the application layer employs additional encryption protocols (such as HTTPS, SSH), even if attackers can hijack the connection, they cannot inject meaningful data content, which to some extent mitigates the risk (but connections can still potentially be reset through this method). Additionally, global carriers should filter IP packets with forged source addresses through border policies. However, it is worth noting that as long as any ASN globally allows sending packets with forged source addresses, this type of attack cannot be completely eliminated.
