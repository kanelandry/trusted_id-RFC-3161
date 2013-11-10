private_trusted_id-RFC-3161
===================
Collaraboration of digital signatures and identity management to restrict file access and protect the identity of the file's owner.
Requirements: openSSL (v1.0.0+), PHP and Apache installed and running - valid allowance from a RFC 3161 TimeStamping Authority (aka TSA), Exec and Curl extensions enabled in your PHP environment. 

The theory behind this code is the following: "If you can prove you knew a file's hash and the encrypted id of its owner at a certain point in time, that guarantees you knew the file content and its owner."

For more about this technical asset, please consult its full article: 
http://codijuana.blogspot.com/2013/11/case-3-trusted-identity-rfc-3161.html
