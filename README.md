![CVEHawk](../assets/cvehawk.png?raw=true)

# CVEHawk
It's a Python script that searches for publicly available Proof-of-Concept (PoC) exploits for a given Common Vulnerabilities and Exposures (CVE) identifier. When a new CVE is published by NIST, it is useful to locate exploit code for security research, pentesting, and vulnerability management

## Installation
```sh
git clone https://github.com/0xh7ml/CVEHawk.git

cd CVEHawk

chmod +x cvehawk.py
```

## Usage
```sh
./cvehawk.py --cve CVE-2021-1234
```

Here are all the flags it supports.

```console
INPUT:
    -c , --cve   input target cve id

DEBUG:
    --silent     silent mode

HELP:
    -h 
```

## ToDO

- [x] Take CVE ID as input
- [x] Search PoCs related to that CVE from the publicly available sources. i.e: Github, ExploitDB, Twitter, OpenAI’s GPT
hacking communities, Offensive Security blogs, or Packet Storm Security
- [x] Make this tool supporting multithreading / asynchronous
- [ ] show the output as JSON -j
- [ ] Add write output with flags -o 

## Sources and APIS
- Github
- Exploit DB
- InTheWild
