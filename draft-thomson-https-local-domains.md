---
title: "HTTPS for Local Domains"
abbrev: "HTTPS Local Domains"
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
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
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
    organization: Cloud Software Group Holdings, Inc.
    abbrev: Cloud Software Group
    email: danwing@gmail.com
    role: editor

normative:

informative:


--- abstract

This specification eliminates security warnings when connecting to local domains
using TLS.  Servers use a long hostname which encodes their public key that
is validated against the public key presented in the TLS handshake. Additional
features are discussed to allow users to securely interact with short names.

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Operation

Server uses a unique host name that includes a hash of its public key.
Clients use TLS to connect to that name, validate the hash matches the key
in the TLS ServerHello, and continue communication.

This system does not require storage on the client.

# Unique Host Names {#unique}

Web browsers and other application clients store per-host state using
the host name, including cached form data such as passwords,
integrated and 3rd party password managers, cookies, and other data.
When a name collision occurs (e.g., the same printer.internal name on
two different networks) the client cannot recognize a different host
is being encountered.  While it is possible to extend all of these
clients to extend their index to include the server's public key, this
seems to lack business justification for the engineering effort to
solely improve the user experience (shorter name) on local networks.

A unique name can be created by embedding the hash of the public
key into the name itself.  This achieves uniqueness and is also
used by the client to validate the server's public key {{validation}}.
Details on encoding are in {{encoding}}.

# Raw Public Keys {#rpk}

Todo:  rewrite this section

Certificates are complicated for most people. They also have an
expiration date.  This system uses a public key for the lifetime
of the device, which is hopefully years. A certificate is not
appropriate; a raw public key is more approporiate.

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
algorithm, and the hash.  Currently only SHA256 is defined. This can
be extended via IANA action.

> Note there is no separator between the hash-algorithm identifier
and the hash itself.  This reduces unecessary periods..

~~~~ abnf
friendly-name = 1*(ALPHA | DIGIT)

hash-algorithm = 0 ; SHA256

hash = 1*(ALPHA | DIGIT)

encoded-hostname = friendly-name "."
                   hash-algorithm
                   hash
~~~~~


# Upgrading to Easier Short Names

Long host names containing encoded public keys are awkward for users. This
section describes how short names can also be advertised by servers and
securely validated by clients, so that the short name is presented to
users while the long name is used to actually connect.

The server advertises both its (long) unique name and its short
nickname using {{!DNS-SD=RFC6763}}.  The client connects to the long
name and performs a full TLS handshake and validation
({{validation}}).  The client then connects to the short nickname and
performs a full TLS handshake. If the same public key was presented
by both TLS connections, the client SHOULD present the short name to
the user.

To avoid the problems described in {{unique}}, the short name MUST NOT
be used by clients after the TLS handshake and the server MUST terminate
the TLS handshake after the Finished message by sending TLS close_notify.



# Security Considerations

TODO Security


# IANA Considerations

Hash type, 0=SHA256, further extensions via IETF Action.


--- back

# Discussion Points

## DTLS

This should work for DTLS, as well?



# Acknowledgments
{:numbered="false"}

TODO acknowledge.
