"""

Author: MaxWarman
Description: My RC4 implementation

"""

class Rc4:

	def __init__(self, key_, encoding_="utf-8"):
		self.generateLookupTable(key_, encoding_)

	def getS(self):
		return self.S

	def generateLookupTable(self, keyString, encoding):

		key = bytearray(keyString, encoding)

		s = [i for i in range(256)]

		j = 0
		for i in range(len(s)):
			j = (j + s[i] + key[i % len(key)] ) % len(s)
			s[i], s[j] = s[j], s[i]

		self.S = s

	def generateCipherStream(self, plaintextLength=512):
		i = 0
		j = 0

		cipherStream = ""

		s = self.S

		for k in range(plaintextLength):
			i = (i + 1) % 256
			j = (j + s[i]) % 256

			s[i], s[j] = s[j], s[i]

			h = chr( s[ (s[i] + s[j]) % 256 ] )

			cipherStream += h

		self.S = s

		return cipherStream

	def encrypt(self, plaintext):
		cipherStream = self.generateCipherStream(len(plaintext))
		ciphertext = xorStrings(plaintext, cipherStream)
		ciphertext = stringToHex(ciphertext)
		return ciphertext

def xorStrings(string1, string2):
	xorResult = ""
	for i in range(len(string1)):
		xorResult += chr( ord(string1[i]) ^ ord(string2[i]) )

	return xorResult

def stringToHex(txt):
	h = ""
	for char in txt:
		tmp = hex(ord(char))[2:]
		if len(tmp) == 1:
			h += "0" + tmp
		else:
			h += tmp

	return h

def hexToString(txt):
	string = ""
	for i in range(0, len(txt), 2):
		string += chr( int(f"{txt[i]}{txt[i+1]}", 16) )

	return string


def test():
	plaintext = "Plaintext"
	key = "Key"

	rc4 = Rc4(key)

	ciphertext = rc4.encrypt(plaintext)

	print(f"Plaintext: {plaintext}")
	print(f"Key: {key}")
	print(f"Ciphertext (hex): {ciphertext}")

def main():

	test()

	assert(Rc4("PWr-WhiteHats-CryptoDivision").getS() == [80, 2, 28, 76, 174, 20, 131, 254, 107, 188, 87, 247, 37, 19, 45, 163,186, 59, 114, 67, 64, 197, 23, 150, 161, 30, 172, 53, 88, 251, 139, 34,52, 180, 98, 239, 120, 204, 229, 208, 108, 194, 47, 234, 113, 176, 14, 73,92, 90, 71, 121, 78, 69, 61, 226, 153, 237, 11, 220, 134, 82, 56, 245,68, 157, 165, 199, 126, 240, 115, 158, 243, 211, 40, 3, 167, 16, 151, 142,41, 124, 1, 10, 29, 31, 130, 109, 135, 50, 160, 63, 0, 213, 148, 54,129, 202, 101, 93, 42, 219, 119, 193, 190, 144, 238, 175, 222, 21, 5, 128,112, 181, 70, 60, 140, 7, 248, 155, 177, 154, 24, 105, 117, 84, 133, 91,99, 232, 233, 203, 147, 66, 102, 4, 255, 94, 235, 178, 48, 79, 138, 173,89, 58, 184, 201, 149, 183, 242, 65, 85, 110, 196, 146, 230, 159, 169, 36,145, 206, 137, 55, 218, 96, 214, 122, 39, 62, 46, 246, 26, 18, 136, 191,200, 106, 179, 227, 182, 187, 217, 216, 223, 132, 168, 72, 44, 231, 9, 51,198, 166, 224, 49, 249, 97, 205, 95, 13, 225, 164, 81, 17, 33, 185, 43,209, 25, 74, 141, 143, 170, 27, 103, 210, 207, 118, 236, 171, 215, 75, 38,86, 244, 195, 35, 15, 83, 12, 32, 116, 125, 253, 100, 123, 250, 104, 8,152, 212, 252, 221, 57, 111, 228, 22, 127, 192, 77, 6, 241, 156, 189, 162])
	assert(Rc4("Key").generateCipherStream() == hexToString("eb9f7781b734ca72a7194a2867b642950d5d4c2652177b9e7a8215ec54ab503e80328ac213693189d556897e79bccdefcb267d544b7455dd966a55f41a910e6c7027fed709a616a30f636fbe3164653046266fe1c65a8844cd4cd312a0f8b18d7f8231b4ad8c336bc8b1ffae6d11f5c09e8d7d2e753698bdb1a6186aee0a8527f1ecb7a8d4b5e28a5e8b5bf340ffa7a78167b385398570424346d2ee8808676c7fd3cef6fdd6ff587b659dc71361826f76504c41d42c40a30a2bf9e9ab512ea3c69fc135951c3b152b75eff81bf81cb48ea2b9e8781c8db1ac22edd3c9f79147961822478291dd41ff3c2a347950a5ce14a04f1b63d74e42bd3c7bf2d31cc49092fdd9b6e404ef4fa075f1a344ed816bd0ef77a788f345a7352874ffccdb3b3ba2a96e53e48ff9e1b7f370ee5ab35c14cda970e2a1b69e04a67f1aef9615d1387edce39ecb7c7dff5b6c0d7e0a0943e753895b901f12c3a7edad126bb5adadd499b282b7e869a3f3ef2cf0222e51b0316d8637b5316c576e3dd53cb2cad413a46a9d4bf77ad34c8acce88f3beb16c52cd3b37e209a0fa7db25fe6f61c75a5331a909632badfce1c6eb7611fb8eb4699e304234cb1afe63eea6b4cf7b8c23fcaacf74af8fda99573a4118d9c8bb364302f03b6b4d6ee1f9c55f41e988808c083a57b6640cdf6f05aa8c995035879005276448fd7375a0b20e72e165267e113159"))
	assert(Rc4("Wiki").generateCipherStream() == hexToString("6044db6d41b7e8e7a4d6f9fbd4428354580cb8f17354a7f9b2700782f5aa10b3682202ed1e9beac657c54d6f1cf54a26d1d0c06a3735c2823674a011e711813cc8a3ea90bd0b15255bb6e6049f4fe6cb85d5a6cc7cedfd8aeea22840c2b423aa5438894cdbb38472a3b5463caa941d36a825c80fb8eec351065230615c181b8968fa11faad1c5cc05a7da7dceb1e89bee0d12ac63e5270c5e6239b93bf770aafa0811eccde3265ae50b3495155b437027cbd6588eaa517ca380f465765df5ca8b36032dd4d651bc030869c53f7a71bc214e3846f9d75679abc57b44017bd8e1d25dd8b51868a113a75f708a503ec5154280112ffa13f48405511b37faa67c92269c67d487441b847a785e0dbd562afa22c8afd3c8df770dd7101deb6bb98f012ad675a609f12e24a9d03bf5835d85a22ecb351f63d45de83922e73fe1992006d58700b056a445a843d23de7f6a79c401b023ac4d1a4bec75c7b26310498ae4fbbb84b8dbcd91daea47bf3b5a2855c881ea061e033c75b50e6f30e11a360781aa412483e1b3bdf3344817ca77b3ba88565a98d9bca82bb2f3d357c7a41781b6df6c5f9adfa82ce3e7285c9cc9d276e806102deec1900ad141a898e4bee80ca6f928eda452f16d30dbc76e32e2a90454c425cb8a79be9bc5d49a2ac5c3b7f2c8be6cafff925f2f1c165774fa8e44849b00f77f46a344458f7e5faa81d8813f34d5"))
	assert(Rc4("Secret").generateCipherStream() == hexToString("04d46b053ca87b594172302aec9bb9923211d435594f00771dc9195f4876f087f375447c162d322ec5edaa1196b65fbac7df7ee3dfcbcb5f9a4c70eeeae42fd2e2cbdec25fbe35289c5b87d85f9732d46e6ceb8ead2bb7303f6d93fce6c1234ecefde9847414ef923636c56547cce3881fd7d3f411cc587d43c350b62b35b2a803ad5d947749a858f7304f4ef5a5ac4dacbfe5d4829a5fd1126d424aba2e5fa2fa48c689a085e0ca5fb6d6d7f718c4d0b5c1cba1a7c28719b4e3785e863136a8e002292a292cd733476d6945da971d0caad9dd3e6c21ea61c09b950a82a846c33802e9b5b16366591524e4e0be02da47a2fdf2312f5325eecfa8f0c0fd09d4f948ee294c34a7f59b3f77af7c52db47e2d62786b77227ac61a47c8428100d1e30aaa89e88257e1cc34f08b9bb3f03a7f3194cac45dc0e41e2a54170449c0f177bbbb3658fa77c5e2116e68b5e2c577e67a88290da72c940768fad72be5c05a4c8722ab104f583f97ab48a90a4e247abf0663b40d99bb62bf8b2e566226fe07e7d7d28df8f1d74589f83094dd6e4474340b8fff854504d8963815a3dcdfcf27a429fecf417c22e46d17f8b774362b7faadbec08da6f21469755666e1da4ceed6b470a0c701b0467bdcb5bbf82775e5e87c1eecbb60e42e532764cc69acf34c9ed9411f6796b6b423517f6dd8e8448e9d62c1ac168da4b97fca9b1ff670a0622bb6"))

	print("\nTests successful..")

if __name__ == "__main__":
	main()