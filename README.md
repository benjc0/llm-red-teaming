# llm-red-teaming
test2  





cd juice-shop-copy/
docker build -t custom-juice-shop .
docker run --rm -p 127.0.0.1:3000:3000 --name juice-shop custom-juice-shop
