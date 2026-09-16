# llm-red-teaming
AI RedTeaming Github repo Senior Design project.

Tasked with utilizing AI to systematically pentest a given site, in this case owasp juice shop and have it discover, document, and produce mitigations for vulnerabilities.

We are utilizing a custom juice shop website, the website code in this repository will eventually not have the challenge board which lists the possible explots.




cd juice-shop-copy/
docker build -t custom-juice-shop .

docker run --rm -p 127.0.0.1:3000:3000 --name juice-shop custom-juice-shop
