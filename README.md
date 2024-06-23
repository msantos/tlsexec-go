# SYNOPSIS

tlsexec [*OPTION*] [*IPADDR:*]*PORT* *COMMAND* *...*

# DESCRIPTION

tlsexec: a minimal, [UCSPI](https://jdebp.uk/FGA/UCSPI.html) inetd

`tlsexec` attaches the standard input and output of a command to a
TLS socket:

* `SO_REUSEPORT`: multiple processes concurrently listen and accept data
  on the same port

# EXAMPLES

Generate a self-signed cert for testing:

```
openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 3650 -subj '/CN=example.com'
```

## echo server

```
$ tlsexec :9090 cat

$ tlsexec 127.0.0.1:9090 cat

$ tlsexec [::1]:9090 env
```

## Supervised using daemontools

An echo server allowing 3 concurrent connections:

```
service/
├── echo1
│   └── run
├── echo2
│   └── run
└── echo3
    └── run
```

* service/echo1/run

```
#!/bin/sh

exec tlsexec 127.0.0.1:9090 cat
```

* service/echo2/run

```
#!/bin/sh

exec tlsexec 127.0.0.1:9090 cat
```

* service/echo3/run

```
#!/bin/sh

exec tlsexec 127.0.0.1:9090 cat
```

Then run:

```
svscan service
```

# Build

```
CGO_ENABLED=0 go build -C cmd/tlsexec -trimpath -ldflags "-w"
```

# OPTIONS

cert *string*
: Path to TLS cert file (default "cert.pem")

enable-strict-tls
: Restrict TLS protocols to TLS 1.2+ and use a reduced cipher suite for
TLS 1.2 (default true)

key *string*
: Path to TLS key file (default "key.pem")

verbose
: Display service information

# ENVIRONMENT VARIABLES

PROTO
: protocol, always set to SSL

SSLREMOTEIP
: source IPv4 or IPv6 address

SSLREMOTEPORT
: source port

SSLLOCALIP
: destination IPv4 or IPv6 address

SSLLOCALPORT
: destination port
