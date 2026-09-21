# llm-red-teaming
AI RedTeaming Github repo Senior Design project.

Tasked with utilizing AI to systematically pentest a given site, in this case owasp juice shop and have it discover, document, and produce mitigations for vulnerabilities.

We are utilizing a custom juice shop website, the website code in this repository will eventually not have the challenge board which lists the possible explots.




cd juice-shop-copy/
docker build -t custom-juice-shop .

docker run --rm -p 127.0.0.1:3000:3000 --name juice-shop custom-juice-shop



## Cycle 1 todo:

- Containerized Juice Shop - Done 
- Challenge board removed (hints and tutorials disabled aswell) - Ben
- determine what AI model/how we want to direct the AI at the site/logging - Cooper 
    - have the AI be able to perform automated recon/enumeration of site, but not go further. - some sort of bash script that invokes claude code, with optional parameters 
- Create a 'master vuln list/document' to base the AI's results off of.
- AI Chat bot backend (Olama, making it accessible to the dockerized container)

- change the branding of the 'Juice Shop' to a custom format in attempt to trick AI/make it not as obvious to the AI model what it is. (AI Models have likely trained on this site plenty, so are able to pull from that instead of strictly pentesting) - Cooper/Charles
- written report - higher priority, user stories, had a slight change of direction
    - change the branding of the juice shop/give our product its own name
    - Have ability for AI Pentest to be White box vs Black box (provide source code of website or not during pentesting)
    - Remove the challenge board from the website so the AI doesn't have the list of known vulnerabilities with the site
    - "I Would like a full vulnerability list of the website, so I know how the AI model did in its pentesting"
    - "I would like for there to be a locall llm chatbot on the backend that has vulnerabilities that can be discovered as well"
    - "I would like the AI Pentesting bot to document its findings and be able to invoke relevant tool"
    - have a seperate LLM that has all the notes/documentation to have it test and verify
- presentation 


## AI Chatbot backend
Local LLM idea:

https://pwning.owasp-juice.shop/companion-guide/snapshot/part1/running.html#_aillm_provider


curl -fsSL https://ollama.com/install.sh | sh
ollama pull gemma4:e4b

need to somehow make it accessible to the docker container hosting the website.
