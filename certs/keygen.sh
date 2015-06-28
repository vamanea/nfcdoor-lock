openssl dsaparam -rand -genkey -out dsa.pem 2048 -outform PEM
openssl req -nodes -config openssl.cnf -days 1825 -x509 -extensions v3_ca -newkey dsa:dsa.pem -out ca.pem -outform PEM
