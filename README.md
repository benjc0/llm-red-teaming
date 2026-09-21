# llm-red-teaming
AI RedTeaming Github repo Senior Design project.

Tasked with utilizing AI to systematically pentest a given site, in this case owasp juice shop and have it discover, document, and produce mitigations for vulnerabilities.

We are utilizing a custom juice shop website, the website code in this repository will eventually not have the challenge board which lists the possible explots.




cd juice-shop-copy/
docker build -t custom-juice-shop .

docker run --rm -p 127.0.0.1:3000:3000 --name juice-shop custom-juice-shop



## Cycle 1 todo:

- Containerized Juice Shop 
- Challenge board removed (hints and tutorials disabled aswell)
- determine what AI model/how we want to direct the AI at the site
    - have the AI be able to perform automated recon/enumeration of site, but not go further.
- Create a 'master vuln list/document' to base the AI's results off of.
- AI Chat bot backend (Olama, making it accessible to the dockerized container)

- change the branding of the 'Juice Shop' to a custom format in attempt to trick AI/make it not as obvious to the AI model what it is. (AI Models have likely trained on this site plenty, so are able to pull from that instead of strictly pentesting)
- written report
- presentation


## AI Chatbot backend
Local LLM idea:

https://pwning.owasp-juice.shop/companion-guide/snapshot/part1/running.html#_aillm_provider


curl -fsSL https://ollama.com/install.sh | sh
ollama pull gemma4:e4b

need to somehow make it accessible to the docker container hosting the website.
