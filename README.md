# cve_poc_finder
It's a Python script that searches for publicly available Proof-of-Concept (PoC) exploits for a given Common Vulnerabilities and Exposures (CVE) identifier. When a new CVE is published by NIST, it is useful to locate exploit code for security research, pentesting, and vulnerability management


## ToDO

- [ ] Take CVE ID as input
- [ ] Search PoCs related to that CVE from the publicly available sources. i.e: Github, ExploitDB, Twitter, OpenAI’s GPT
hacking communities, Offensive Security blogs, or Packet Storm Security
- [ ] Make this tool supporting multithreading / asynchronous
- [ ] show the output as JSON -j
- [ ] Add write output with flags -o 

## Initial Approach 
- Use Argparser for taking input
- Use AsyncIO for asyncrhonous searching

## Sources and APIS
- Github
- Exploit DB
- Twitter
- Other Sources