openssl req -config phone.cnf -nodes -keyout phonetmp.key -newkey dsa:dsa.pem -out phone.csr -days 365
openssl pkcs8 -in phonetmp.key -out phone.key -nocrypt
openssl ca -batch -config sign.cnf -in phone.csr -out phone.cert

