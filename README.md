# CS 118 Fall 24 Project 2
## Design Choices
In doing this project, I started off by reading the spec and starter code thoroughly and ensuring I knew if there was a function defined to perform any task I needed. 
I also asked lots of questions to clarify my understanding when I was unsure. 
I decided to use temporary buffers when building the TLV responses in order to help myself stay organized and not accidentally overwrite data I need.
I copied data between buffers with `memcpy` and compared data with `memcmp` to ensure I was getting the correct data.
I built and tested my code incrementally, starting with the client-hello up until the data phase.

## Problems and Solutions
I had issues using `memcpy` sometimes because I was not sure when to pass the address `&` or just the reference. 
I was inconsistent with my use of `&` and `*` and had to go back and fix it.
I also had issues using the `verify()` function because I was unsure about the parameters I was using. 
To fix this issue I learned I needed to pass the public key as a parameter and use the `verify()` function to verify the signature.
I also had my offset incorrect for the signature, which led me to get an incorrect length and snowball from there.
I fixed both by recalculating the offset and the I passed the tests.
One of the things I missed in the spec was when I needed to derive the secret and derive the keys.
I thought that the secret and keys were derived in each data step, but that led to inconsistent HMAC results.
As soon as I resolved that issue, the HMACs were consistent and I was able to pass the tests.

