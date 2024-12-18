---
title: "Extended Origins for Local Domains"
abbrev: "Extended Origins for Local Domains"
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

This document explores a method for providing secure HTTPS access to
local domains without the need for traditional certificate validation.
By leveraging local domain names and their embedded public keys, this
approach ensures secure communication within a local network.

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

This draft discusses how a client can authenticate to HTTPS servers
belonging to the local domain where the server name is not unique and
where the server does not have a certificate signed by a Certification
Authority (CA) trusted by the client.  This is a relaxed way of
"doing HTTPS" for servers on the local domain.

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



# Extended Origins for Local Domains {#extended-origin}

The key challenge for local domains is that names are not unique. Any
printer is entitled to claim the name printer.local and use it.  Thus,
any server has a legitimate claim to that name. If we are to make
https://printer.local a viable origin, how do we ensure that it is
unique?

Extending the origin -- internally on the client -- makes this
possible. A web origin is defined as a tuple of scheme, host, and port
{{Section 4 of ?RFC6454}}. This is a capability that browsers are
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

# Identifying Servers as Local {#local}

The idea here is to do this only for names that are *not* inherently
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
hash to the domain name for internal representation on the client,
https://_NPNE4IG2GJ4VAL4DCHL64YSM5BII4A2X.printer.local, or it could
use a separator of some sort to partition off space for a key (e.g.,
"lh--" ({{Section 3.2.1 of ?RFC5890}}), taking care of each label not
exceeding 63 octets ({{Section 2.3.1 of ?RFC1035}}) if the internal
representation has such restriction).  The internal representation should
also include the type of key (e.g., RSA1024, secp256r1).

> TBD: Does this need a new scheme? Is it a new field, or can it be
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
and an enhanced warning is shown after a name collision to a server
with a different public key, such as visiting another network that
has a server with the same name.  It is
possible that other security UX might be enhanced to better signal the
status of local servers. For instance, showing the identicon in the
above examples next to the server’s chosen favicon.  For password
stealing, using a reliable password manager -- which also does internal
partioning based on the server's public key -- should help. It might be
necessary to include notices warning users about the server identity.

Third-party password managers would need to be enhanced to recognize
the additional information in the origin and properly segment their
internal namespace. A password manager that looks at window.location.host is
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



# Operation

## Client Operation

The client connects to a local domain name or IP address (as
discussed in {{local}}) using TLS.

Upon receipt of the server's certificate, the client validates
validates the certificate ({{?RFC9525}}, {{?RFC5280}}, and {{Section
4.3.4 of ?RFC9110}} if using HTTPS).  When performing such a
connection to a local domain, the client might avoid warning about a
self-signed certificate because the Certification Authority (CA)
signature will certainly not be signed by a trusted CA.  Rather, a
more subtle indication might be warranted for TLS connections to a
local domain, perhaps only the first time or perhaps each time.

After the TLS connection finishes successfully, the client forms the
extended origin for this server (see {{extended-origin}}).  This
extends the scheme, host, and port origin of {{?RFC6454}} to also
include server's public key.  By doing this only that server with that
public key will be associated with the web origin data (web forms,
cookies, passwords, local storage, etc.).

> Implementation note: See {{origin-serialization}} for suggestions on
representing the public key in the client.

## Server Operation

The server is unaware of the client implementing this draft and needs
no changes.

# Operational Considerations

## Server Identity Change

This specification effectively encodes the server's public key as part
of its identity.  Changing the public key would also change the
internal representation on clients -- thus, its identity as known by
client password managers and other configurations in clients (e.g.,
printer, SMB share, etc.). As such an identity change is extremely
disruptive, changing the server's public key needs to be avoided.


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

This draft defines a new way for clients to authenticate servers
belonging to the local domain.  Unlike the unique names on the
Internet, a server on a local domain definately does not have a unique
name -- two networks can have their own printer.local which is a
different physical printer on a different network, but both have the
same simple name.  When the client associates the server's public key
with the server's origin (scheme, hostname, port), the client can
distinguish one printer.local from another printer.local, even though
they share the same name.  This keeps origin-specific data accessible
only to a server possessing the private key associated with its public
key. When visiting another network where a server is using the same
name, the server will use its own public key in the TLS handshake
which is the client's indication the server is a different origin.
When the client is using an extended origin with a local domain
server, server impersonation still requires possession of the victim's
private key.



# IANA Considerations {#iana}

This draft requires no IANA actions.


--- back


# Acknowledgments
{:numbered="false"}

This Internet Draft started as a document published by Martin
Thomson in 2007.
