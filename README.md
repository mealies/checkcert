# checkert [![Build Status](https://github.com/mealies/checkcert/actions/workflows/push.yml/badge.svg)](https://github.com/mealies/checkcert/actions/workflows/push.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/mealies/checkcert)](https://goreportcard.com/report/github.com/mealies/checkcert)

A Go-based replacement for my shell script


## Usage
```
checkcert -address www.drewbell.net
```

Check certificate on an specific host (load-balancer)
```
checkcert -address site.drewbell.net -sni www.drewbell.net
```

Check a local certificate file
```
checkcert -cert mycert.pem
```

Check a directory of certificates
```
checkcert -cert /path/to/certs/

```

Full help
```
Usage of checkcert:
  -address string
    	Address to connect to (required)
  -cert string
        Path to certificate file or directory to check
  -port string
    	Port to check (default: 443) (default "443")
  -sni string
    	Server Name Indication (SNI) hostname (defaults to address if not specified)
```

