# diffie-hellman key exchange
## a wrapper for c++

This project is a wrapper for the [Elliptic-Curve Diffie-Hellman key agreement algorithm](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) written in C++.

Only supports one curve, could easily swap it out though (list of possible curves is available on the OpenSSL wiki).

Not well-tested or anything, written at 4AM as part of a bigger project.

User manual
## The usage is pretty simple:
* you create a `diffiehellman` object
* you derive it's public key
* you derive a shared key from your object & the other parties public key (that you received via networking etc.)

```C
auto client = sdk::encryption::diffiehellman();

if (client.derive_pub() != 0) {
	std::cout << "failed to derive client public key, exiting" << std::endl;
	return -1;
}

//this is just an example so you can run it on one machine
//in real-life you'd probably read the public key of the server
//from a network stream or a file etc.

auto server = sdk::encryption::diffiehellman();

if (server.derive_pub() != 0) {
	std::cout << "failed to derive server public key, exiting" << std::endl;
	return -1;
}


//you simply use the diffiehellman object that you have for your side and pass it the public key & public key length of your partner
if (client.derive_shared(server.m_pub, server.m_pub_len) != 0) {
	std::cout << "failed to derive shared key, exiting" << std::endl;
	return -1;
}

printf("\client: \n%s", client.m_pub);
printf("\server: \n%s", server.m_pub);
printf("\shared: ");
for (unsigned int i = 0; i < client.m_shared_len; i++)
	printf("%X", client.m_shared[i]);
printf("\n");
```
