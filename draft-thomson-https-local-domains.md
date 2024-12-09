---
title: "Public Key Hash for Authenticating Local Domains"
abbrev: "PKH for Authenticating Local Domains"
category: std

docname: draft-thomson-https-local-domains-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: SETTLE
  type: ""
  mail: settle@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/settle/
  github: "danwing/https-local-domains"
  latest: "https://danwing.github.io/https-local-domains/draft-thomson-https-local-domains.html"

author:
 -
    fullname: Martin Thomson
    organization: Mozilla
    email: mt@lowentropy.net
 -
    ins: D. Wing
    name: Dan Wing
    organization: Citrix
    abbrev: Citrix
    email: danwing@gmail.com
    role: editor

normative:

informative:

  secure-context:
    title: Web Platform Design Principles
    date: June 2024
    author:
      org: W3C
    target: https://w3ctag.github.io/design-principles/#secure-context

  containers:
    title: Put your multiple online personalities in Firefox Multi-Account Containers
    date: September 2017
    author:
      org: Mozilla
      name: Chelsea Novak
    target: https://blog.mozilla.org/en/products/firefox/introducing-firefox-multi-account-containers/

--- abstract

This document explores a method for providing secure HTTPS access
to local domains without the need for traditional certificates.
By leveraging local domain names embedded with public keys, this
approach ensures secure communication within a local network. The
method simplifies the setup process and enhances security by avoiding
the complexities of certificate management by using raw public keys.
This solution is particularly beneficial for local services that
require HTTPS access without exposing them to the Internet.

--- middle

# Introduction

As more of the web transitions to using HTTPS, users that access
services on their local network are being increasingly marginalized.
Servers that run in local networks often cannot easily get a valid
server certificate.  The majority of devices use unsecured HTTP.

Browsers are progressively reducing the capabilities and features that
are available to origins that use unsecured HTTP.  In particular, new
features ({{secure-context}}) are being developed exclusively for HTTPS
origins.

Non-HTTPS origins are vulnerable to a range of attacks, so all of this
is easy to understand, however it means that local devices are left
with user interface that shows negative security indicators (e.g.,
'not secure' on the URL bar) and diminished access to web features
requiring secure context (e.g., Cookie Store API, Credential
Management API, Web Bluetooth, Storage API, Push API, Notifications
API, WebTransport API).

Servers that operate publicly accessible endpoints have few challenges
with getting certificates that allow them to be authenticated.  The
challenge is giving servers that are less publicly available access
to the same opportunities without compromising the assurances provided
to other servers.

We could run HTTP over TLS without authenticating the server
{{?RFC8164}}, which would provide some of the confidentiality and
privacy benefits of HTTPS.  However, aside from the exposure to
man-in-the-middle attack, a site using {{?RFC8164}} does not gain an
HTTPS origin.

What is really needed is a way to use HTTPS proper.

# Background

## Using Real Names

The best option for a device that is installed in a local network
might be to use a genuine domain name.  The vendor of a device could
run a service that assigns a unique name from the global DNS namespace
to the device, such as \<deviceID\>.devices.example.com. Mozilla’s IOT
Gateway does exactly this, and this is a pattern that is emerging as
best practice.

The way that this works is that a service, often operated by the
device vendor, provides devices with a unique identity. Typically,
this is a subdomain of a domain owned by that vendor. The service
might also further enable the acquisition of certificates for devices.

A split horizon DNS ensures that requests for that name produce the
correct domain name.  The device vendor might also provision the DNS
for that name, which could improve reachability in some circumstances,
but it could also present a privacy exposure by making network address
assignments publicly accessible. This requires that devices have
access to a means of controlling DNS.  Thus, this is more feasible for
a router that also provides DHCP, but less for other devices.  Even
for a device like a router, a manual configuration of a DNS server
makes the name inaccessible.

A redirect from a friendly name (such as gateway.local) to the full
device name ensures that the device can be reached by typing a more
readily memorable string.  However, there is no way to secure this
redirect: the name that is entered is not unique and therefore a valid
certificate cannot be issued for that name.

Unlike suggestions to the contrary this does not require that the
device itself be exposed to packets from the internet at large, only
that it be able to reach one particular server on the internet.
Firewall rules could be set to permit only what is necessary to
communicate with a certificate provisioning server.  That server can
proxy requests for certificates; for instance, responding to ACME
challenges as needed and relaying the certificate that is received.
This only requires that the server authenticate devices.
Manufacturers might use keys that are provisioned at the time of
manufacture. If the manufacturer is prepared to provide certificates
to any device, the device might provide credentials when it first
claims an unused name.

For the device to be accessible from the internet, the device
manufacturer needs to establish and relay communications. This
effectively leads to the device being exposed to the internet, though
the manufacturer might be able to provide some measure of protection
from attacks like denial of service.

Access to a device using a local
name might be used opportunistically.  For this, HTTP Alternative
Services ({{?RFC7838}}) can be used to provide an alternative route to the device
that does not depend on the external server.  The design of
alternative services ensures that this is used automatically when
available.

This is a good solution but is not without drawbacks.  The names
that are produced are not generally usable by humans as a consequence
of a need to be globally unique.  Some deployments address this by
providing a second service with a memorable name that manages
rendezvous.  That in turn has consequences for privacy, because that
service needs to mediate interactions between users and their devices.

This approach also imposes an ongoing operational cost on the device
vendor.  With the plethora of things being released with tiny profit
margins, additional operational costs are hard to justify.  Support
from vendors over the lifetime of the device is not guaranteed.  A
vendor that goes out of business is likely to cease operation of a
certificate enrollment service. This might be managed if the device
could be updated with new software that could use a different
service. That only reduces the problem to a previously unsolved one:
that of ensuring continuity of software updates for devices.

## Server Authentication on the Web

It probably makes sense to take another look at how server
authentication is used on the web.

Why does HTTPS need certificates? Unique, memorable names.

The DNS provides centralized management of names and enforces
uniqueness of those names.  The Web PKI provides security for those
names through the issuance of certificates.

A name is important for ensuring that a web browser can faithfully
translate user intent into action.  When someone types example.com
into their browser, that name is compared against the name in a
certificate to determine if the server is correct.

The web origin model cares little that the identity of a server is a
name. A browser cares more about the uniqueness of identity than its
form. The web origin model is built to secure access to the state that
a browser accumulates for an origin, it cares more that the identity
accessing that state remain constant than how it is identified. A
certificate provides a unique anchor for that state, ensuring that
only a single entity controls access to that information.

# Conventions and Definitions

{::boilerplate bcp14-tagged}



# Extended Origins for Local Domains

The key challenge for local domains is that names are not unique. Any
printer is entitled to claim the name printer.local and use it.  Thus,
any server has a legitimate claim to that name. If we are to make
https://printer.local a viable origin, how do we ensure that it is
unique?

Extending the origin makes this possible. A web origin is defined as a
tuple of scheme, host and port. This is a capability that browsers are
building to enable a range of use cases, such as the creation of
separate browsing contexts (see e.g., {{containers}}). By adding an
additional property to that tuple that cannot be used by any other
server, we ensure that the tuple is able to uniquely identify that
server.

For this, the public key of the server is ideal.  No other server can
successfully use that identity without undermining the security of the
web and any HTTPS server is always able to provide that information.

Adding a public key to the origin tuple creates a separation between
origins.  Two servers can claim to be printer.local, but the browser
will ensure that they are distinct entities that are fully isolated
from each other.  Passwords and form data saved for one printer will
not be used by the other printer.  The same separation applies to
permissions, storage, cookies and other state associated with the
origin.


# Identifying Servers as Local

The idea here is to do this only for names that are not inherently
unique. Domain names like example.com are unique and therefore would
not get this treatment.

Servers with .local ({{?RFC6762}}), .home.arpa ({{?RFC8375}}), or
.internal {{?I-D.davies-internal-tld}} suffixes will be considered
local.  These names are specifically designed for local use and are
non-unique by design.

Servers with IPv4 literals from the {{?RFC1918}} address spaces (10/8,
172.16/12, and 192.168/16) will be treated as local. Similarly, hosts
with link-local literals (169.254/16 or fe80::/64) or Unique Local
IPv6 Unicast Addresses (fc00::/7) are considered local.

Servers on loopback interfaces are local.  This includes the IPv4
literal (127.0.0.1), the host-scope IPv6 literal (::1), and any origin
with the name “localhost”
({{?I-D.ietf-dnsop-let-localhost-be-localhost}}).

Address literals might reach a server that can also be reached using a
domain name.  This is not fundamentally different to a server that can
be reached by two different names (for example, servers often respond
to names both with and without a “www” label: https://example.com and
https://www.example.com).  A server that is identified with a URL that
includes a domain name has a different identity to the server that is
identified with a URL that includes an IP address literal, even if the
domain name resolves to that IP address.  Servers with multiple
identities will be able to use this capability to either provide a
secure redirect to a preferred name or to present a different service
to clients.

The names that are identified as local are all non-unique and
therefore not valid targets for certificates. This means that HTTPS
connections to these servers could not otherwise be made using a
genuine Web PKI certificate.

Other means of identifying servers as local might be added in future.



# Origin Serialization {#origin-serialization}

The primary drawback of adding more attributes to the origin tuple is
the effect it has on applications that use origin in their processing.

For instance, the postMessage API uses the origin to describe the
source or destination of messages. The sender of a message identifies
the origin that it expects to receive the message. The recipient of a
message is expected to check that the origin matches their
expectations.

This proposes a change to the serialization of origins for local
servers so that it includes a hash of the server’s public key
information (SPKI).  This is added to the ASCII and Unicode
serializations of the origin.

For example, this might use the underscore convention to add the SPKI
hash to the domain name,
https://_NPNE4IG2GJ4VAL4DCHL64YSM5BII4A2X.printer.local, or it could
use a separator of some sort to partition off space for a key.

TBD: Does this need a new scheme? Is it a new field, or can it be
added to the domain name? What separator would this use? How should
the SPKI hash be encoded (base64url, base32, hex)? How many bits are
enough? Do we need to signal hash function?  Is this a new field at
the end, a change to the name, or something else? Should SPKI go in
the middle to discourage prefix-matching?

Adding a non-backwards compatible serialization for origins makes
these APIs harder to use.  For instance, sending a message to a
printer.local requires learning this value. This is partly
intentional. The space of possible names for local servers is limited,
and the choice of names for devices like printers even more narrowly
limited. Including a server public key in the origin makes it
difficult to correctly guess the name that will cause a message to be
received by the device.  A device can make its name known by sending
its own message to other servers (e.g., {{?mDNS=RFC6762}}).

The other potential problem is that .local names are permitted to use
a wider range of characters than domain names.  What sort of
normalization do we do to avoid confusable characters?

# Advantages and Drawbacks

The key advantage of this approach is that the extension of origin
allows local services, including those running on the local machine,
to use and benefit from HTTPS.

There are several drawbacks, each of which needs careful
consideration.

## User Involvement

Part of the security of this system involves user awareness.  If
printer.local at home has a password, then moving to a different
network exposes the user to a phishing-type attack where a different
printer.local attempts to retrieve the password for the home printer.

This is why there is a warning shown on first connection to servers
and an enhanced warning is shown after a name-collision.  It is
possible that other security UX might be enhanced to better signal the
status of local servers. For instance, showing the identicon in the
above examples next to the server’s chosen favicon.  For password
stealing, using a reliable password manager should help. It might be
necessary to include notices warning users about the server identity.

Third-party password managers would need to be enhanced to recognize
the additional information in the origin and properly segment the
namespace. A password manager that looks at window.location.host is
likely to broadcast passwords inappropriately.

To mitigate this risk we might consider blocking concurrent use of the
same name with different keys if a password manager is installed.
However, I don’t think that we necessarily know that an extension is a
password manager.  This probably reduces to some due diligence with
the help of the addons team.

## Key Changes (Key Rotation)

Devices that rotate keys will gain a new identity, and lose access to
any existing state.  This creates an incentive to avoid changing keys,
which runs counter to most operational practices.  In this case, the
advantages of making HTTPS available would seem to far outweigh the
risk of using a key over long periods.

It is also possible that a reset of the device might cause keys to be
reset, leading to the more alarming user notice.

## Address Changes

Devices that are identified by their IP address will receive a new
identity when their assigned address changes.  This is a consequence
of extending the origin tuple to include a public key.  This is
intentional: a device might intentionally operate multiple identities
and wish to preserve separation of origins.

## Ergonomics of Origins

As outlined in the construction of origins for local servers
{{origin-serialization}}, the ergonomics of an origin that includes a
SPKI hash is not always ideal -- it is not human readable.

A mitigation for this issue is short names {{short}}.



# Operation

## Server Operation

A server running on a local network (see {{unique}}) uses a unique host
name that includes a hash of its public key.  This unique name is encoded as
described in {{encoding}}.

The server MAY also advertise its unique name using {{?DNS-SD=RFC6763}}.  It
MAY also advertise its short name as described in {{short}}.

## Client Operation

When clients connect to such a local domain name or IP address
({{local}}) using TLS they examine if the domain name starts with a
registered hash identifier in the second label and if the rest of that
label consists of an appropriate-length encoded hash. If those
conditions apply, the client MAY send a TLS ClientHello with the Raw
Public Key extension {{?RFC7250}}. When the client receives the
server's raw public key or certificate, the client checks if the hash
matches the public key received in the TLS ServerHello. If they match,
the client authenticates the TLS connection. If they do not match, the
client behavior falls back to the client's normal handling of the
presented TLS raw public key or certificate (which may well be valid).


# Unique Host Names {#unique}

Web browsers and other application clients store per-host state using
the host name, including cached form data such as passwords,
integrated and 3rd party password managers, cookies, and other data.
When a name collision occurs (e.g., the same printer.local name on
two different networks) the client cannot recognize a different host
is being encountered.  While it is possible to extend all of these
clients to extend their index to include the server's public key, this
seems to lack business justification for the engineering effort to
solely improve the user experience (short name, {{short}}) on local networks.

A unique name can be created by embedding the hash of the public
key into the name itself.  This achieves uniqueness and is also
used by the client to validate the server's public key {{validation}}.
Details on encoding are in {{encoding}}.

To ease clients connecting to these long names, servers SHOULD
advertise their long names on the local network {{?DNS-SD=RFC6763}}.


# Short Host Names {#short}

Long host names containing encoded public keys are awkward for users. This
section describes how short names can also be advertised by servers and
securely validated by clients, so that the short name is presented to
users while the long name is used to actually connect.

The server advertises both its (long) unique name and its short
nickname using {{!DNS-SD=RFC6763}}.  The client connects to the long
name and performs a full TLS handshake and validation
({{validation}}).  The client then connects to the short nickname and
performs a full TLS handshake. If the same public key was presented by
both TLS connections, the client SHOULD present both the
long name and short name to the user.

The client need only look for matching short name and unique name
within the same TLD domain name (that is, if a unique name is advertised
with a ".local" domain, the client does not need to look for its
accompanying short name within ".internal").

To avoid the problems described in {{unique}}, the TLS data connection
to the printer MUST always use the long name.  Thus, if the client has
validated the short name as described above and a user attempts to
connect to printer.local (by typing or by some other user
interaction), the client MUST connect to the unique name.  The TLS
connection to the short name MUST NOT be used by the client after the
TLS handshake completes and the server MUST terminate the TLS
handshake after the Finished message by sending TLS close_notify.

> Discussion: A short name could be entirely handled on the
  client. The disadvantage to client-side handling is each client
  might choose its own short name (one user chooses "office printer",
  another chooses "downstairs printer", another doesn't bother
  choosing a short name at all). While annoying to manage those
  different names, it is not a severe problem.


# Raw Public Keys {#rpk}

Raw public keys are used in various security protocols to facilitate
authentication without the need for full certificate chains {{?RFC7250}}.
This approach simplifies the certificate exchange process by
transmitting only the necessary public key information.

Certificates are complicated because they involve:

  * Managing multiple levels of certificate authorities (CAs).
  * Regular renewal and lifecycle management.
  * Establishing and verifying trust with CAs.

Raw public keys offer a simpler alternative:

  * No need for complex certificate chains.
  * Using raw public keys allows for direct authentication,
  making it easier to implement and understand.
  * Raw public keys use a public key for the lifetime of the device,
   eliminating the need for renewal and longer lifetimes.
  * Robust authentication through public key cryptography.

Using raw public keys can streamline authentication processes while
maintaining high levels of security, making them an attractive
alternative to traditional certificates.

# Validation {#validation}

The client connects to a unique hostname and sends a TLS ClientHello.
As the client only needs the raw public key, the request MAY include
a request for a raw public key {{!RFC7250}}.  The client parses
the returned certificate or raw public key to extract the public key
and compare its hash with the hash contained in the hostname. If
they match, the TLS session continues. If they do not match, the
client might warn the user (as is common today) or simply abandon
the TLS connection.

If a certificate is returned both its 'NotBefore' and 'NotAfter' dates
are ignored for purposes of this specification.

# Encoding Details {#encoding}

The general format is hostname, a period, a digit indicating the hash
algorithm, and then the hash of the server's public key.  The binary
hash output is base32 encoded ({{Section 6 of !RFC4648}}) without
trailing "=" padding.  Currently only SHA256 hash is defined with the
value "0" ({{iana}}).  While base32 encoding is specified as uppercase,
implementations should treat uppercase, lowercase, and mixed case
the same.

~~~~ abnf
friendly-name = 1*63(ALPHA / DIGIT / "-")

hash-algorithm = DIGIT   ; 0=SHA256

base32-digits = "2" / "3" / "4" / "5" / "6" / "7"

hash = 1*62(/ ALPHA / base32-digits )
     ; 62+1 octet limit from RFC1035

encoded-hostname = friendly-name "."
                   hash-algorithm
                   hash
~~~~~
{: artwork-align="center" artwork-name="encoding"}

An example encoding is shown in {{test-encoding}}.


# Identifying Servers as Local {#local}

This section defines the domain names and IP addresses considered
"local" which clients MAY use with this specification.  Other domain
names and other IP addresses SHOULD NOT be used with this
specification.

## Local Domain Names

The following domain name suffixes are considered "local":

* ".local" (from {{?mDNS=RFC6762}})
* ".home-arpa" (from {{?Homenet=RFC8375}})
* ".internal" (from {{?I-D.davies-internal-tld}})
* both ".localhost" and "localhost" (Section 6.3 of {{?RFC6761}})

## Local IP Addresses

Additionally, if any host resolves to a local IP address and
connection is made to that address, those are also considered
"local":

* 10/8, 172.16/12, and 192.168/16 (from {{?RFC1918}})
* 169.254/16 and fe80::/10 (from {{?RFC3927}} and {{?RFC4291}})
* fc00::/7 (from {{?RFC4193}})
* 127/8 and ::1/128 (from {{?RFC990}} and {{?RFC4291}})

# Operational Considerations

## Incremental Deployment

Where a server's hostname can be configured, a motivated network
administrator can configure server hostnames to comply with this
specification to provide immediate value to supporting clients.

## Server Identity Change

The server's public key is encoded into its domain name.
Changing the public key would also change its domain name -- thus, its
identity as known by client password managers and other configurations
in clients (e.g., printer, SMB share, etc.). As such an identity
change is extremely disruptive, it needs to be avoided.


# Security Considerations

TODO: write more on security considerations

Due to challenges in key rotation, the public/private key pair on a
server needs to stay static. The tradeoff is servers are vulnerable
to their private keys being stolen and an active attacker intercepting
traffic to that server.  The alternatives are to continue using
unencrypted communication to local servers, which is vulnerable to
passive attack, or to condition users to validate self-signed certificates
for local servers. In this case, the
advantages of making HTTPS available would seem to far outweigh the
risk of using a key over long periods.


# IANA Considerations {#iana}

New registry for hash type, 0=SHA256.  Extensions via IETF Action.


--- back

# Discussion Points

## DTLS

This should work for DTLS, as well?


# Test Encoding {#test-encoding}

Server with private key in PEM format is:

~~~~~
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCOkTU8TOKW/IZ6
whhyhg+1I4u0jm019z4SVUKAwKyOtFPtoEvRGPdKYUoLaPZmVyN/VTYlubVn7dE8
IYpibwkDhs38DKmyo0vdWjUaopQOaygtLB+PZ12l/XaSCE1cWsl45ShUvktcVR/D
DKwv7DWEIZrRTLKy6M+8Ne4x++kKXmwbSj8WsNQ4kU4uFhS+JXHXToZvhvoQLkTs
486XXPn4SJPLyTN62b6KHTLM1vb7RY4i4U7N6hS1UWe7bIxZNZ0vnf4vZ7A6SR7W
nM31DoaW5XCBH7CL56MSdn7dmuksRimfNmnsEmvBXZmuQMHnUZghBLMHPC9xmHhT
8q3pSY5jAgMBAAECggEANiAY1vDVob7zi01/HJObCQkatAzSl4drUGiAHAOKP49k
wbV2s0bIM7vl8ZkC2u3AM0p1iTMNFQzrv+l38VD4WhdmwodIMeLfHYVu3dLVZPf3
w9aZkMcMfcVRq7VtMV/iV3ygqDOqxr4mldWM1ZDW7HgZn9Z/jX7nxyuuZ9mcquuH
Brl8pcUba7666jcz+F9NNjXTPCwfm7ihCPkTeYr1NflQGTR5PJ+D5dywb53iulm1
ZTk2zBXJMujbIyTL0p+MqdEKXci7oQJqf7bQsxsO2ZUD24CmzYldsE6vmYUFxJpw
ZbYzO/a/Mv0mXQhcUTWKkJkU78QT2Us7SuSL+IPGSQKBgQDC5iRKtlYulUgxV9gu
TmX30R0W7R0nnsEjolNAqUwcIoUMHk8ODXEsp7jVOSFMJhHRMXL+VKYiBsiIV7vk
GlTbLRP34HgK54auRF6PTxBfNAkF+FQxl2mzWxj7wi5mg0g+tCJTLereUXULz8+r
h5Vqp4BCjcoumlyY0xlLtbr9/wKBgQC7Qx2Lb70XCL5eivdokMh2lRint9cfxC2W
fJ6QOnJgsN9XIQGTUAk3cLvmrKg3UOmJXXq+Q6djVB/3Op3+TFzsGS2ORMel9r6o
kAHYG/qdairlW9uTDsnwUP8UtE0lidhSXLGIAy71eMDbDg/c/yyrWTvysXf5kAiJ
CzTnyvY3nQKBgBt+Va5IbH3jxyxWxQM7Qf0kfaMHTe6R4ZMCShY8C6WIZRZhjCti
UA3JlzRU+9J/KFJHVH52OH1iUZWSMsopwMCuaju0aZq4MHKS6Hf04k1bzM4Pyui4
AEwx1KNnMB579IwL4y+ysYgtG4LQDO6YkMZb3KcG03ehhOB2HwJkH33HAoGATOw3
8bQ3v4OG970r/lcjEZsTYqnhA5qJg3yzgdmQbGmbhOX5CLNi5dQ4S3x3KSnilNvC
dO/DjcjbzKnWhsSFkzKQhRV50ZH3JbTqHQT5QLqA3nCKVPFJQJ90+ONLoXTrWIHd
J1rvakRtLE6tc4GartRcDMib2PcymmDxHZpA4/0CgYEAs0XF1G0gmnef8oEYuwZT
c+vr4wnD7YCP1h8nsNSgRHLk1e7k727iHGvruX3qrKsY26RHKi2+i1P6A39I4F5s
3Dme4HGXTyoc/qKp+/GAx5XYVG4c3Z3sdBejkpkhPTSlsSsDOHbjaiFV1zCyEdg5
fOPfIBX8uLc3UtOm0+Gn1IQ=
-----END PRIVATE KEY-----
~~~~~

and public key in PEM format is:

~~~~~
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjpE1PEzilvyGesIYcoYP
tSOLtI5tNfc+ElVCgMCsjrRT7aBL0Rj3SmFKC2j2Zlcjf1U2Jbm1Z+3RPCGKYm8J
A4bN/AypsqNL3Vo1GqKUDmsoLSwfj2ddpf12kghNXFrJeOUoVL5LXFUfwwysL+w1
hCGa0UyysujPvDXuMfvpCl5sG0o/FrDUOJFOLhYUviVx106Gb4b6EC5E7OPOl1z5
+EiTy8kzetm+ih0yzNb2+0WOIuFOzeoUtVFnu2yMWTWdL53+L2ewOkke1pzN9Q6G
luVwgR+wi+ejEnZ+3ZrpLEYpnzZp7BJrwV2ZrkDB51GYIQSzBzwvcZh4U/Kt6UmO
YwIDAQAB
-----END PUBLIC KEY-----
~~~~~

Using the binary format (DER) and hashed using SHA256 gives this
hex value:

~~~~~
21ebc0d00e98e3cb289738e2c091e532c4ad8240e0365b22067a1449693e5a18
~~~~~

Converting that hex value to binary and base32 encoded (without
trailing "=") gives:

~~~~~
EHV4BUAOTDR4WKEXHDRMBEPFGLCK3ASA4A3FWIQGPIKES2J6LIMA
~~~~~

After the hash algorithm identification digit (0 for SHA512/256) is
prefixed to that base32 string, resulting in:

~~~~~
0EHV4BUAOTDR4WKEXHDRMBEPFGLCK3ASA4A3FWIQGPIKES2J6LIMA
~~~~~

Finally, if this is a printer named "printer" advertised using
".local", the full FQDN for its unique name would be:

~~~~~
printer.0EHV4BUAOTDR4WKEXHDRMBEPFGLCK3ASA4A3FWIQGPIKES2J6LIMA.local
~~~~~

and the full FQDN for its short name would be "printer.local".


# Acknowledgments
{:numbered="false"}

This Internet Draft started as a document published by Martin
Thomson in 2007.
