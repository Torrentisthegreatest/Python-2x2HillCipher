alphanum = {
	"A":0,0:"A",
	"B":1,1:"B",
	"C":2,2:"C",
	"D":3,3:"D",
	"E":4,4:"E",
	"F":5,5:"F",
	"G":6,6:"G",
	"H":7,7:"H",
	"I":8,8:"I",
	"J":9,9:"J",
	"K":10,10:"K",
	"L":11,11:"L",
	"M":12,12:"M",
	"N":13,13:"N",
	"O":14,14:"O",
	"P":15,15:"P",
	"Q":16,16:"Q",
	"R":17,17:"R",
	"S":18,18:"S",
	"T":19,19:"T",
	"U":20,20:"U",
	"V":21,21:"V",
	"W":22,22:"W",
	"X":23,23:"X",
	"Y":24,24:"Y",
	"Z":25,25:"Z"
}

class  hillcipher22():
	key = [] # 0 is top left, 1 top right, 2 bottom left, 3 bottom right
	plaintext = ""
	ciphertext = ""
	plainarray = []
	cipherarray = []
	calcarray = []
	inkey = []
	mult26 = [2, 13, 26]

	def convertKey(self):
		for i in range(len(self.key)):
			self.key[i] = alphanum.get(self.key[i])

	def inverseKey(self, key): # inkey = d^-1 * adj(key)
		# Finding d^-1
		d = (key[0] * key[3]) - (key[1] * key[2])
		# d * d^-1 = 1 % 26
		for i in range(len(self.mult26)):
			if d % self.mult26[i] == 0:
				return "ERR"
		if d < 0:
			d *= -1
			for i in range(1, 26):
				if (d * i) % 26 == 1:
					ind = i
					break
			ind *= -1
		else:
			for i in range(1, 26):
				if (d * i) % 26 == 1:
					ind = i
					break
		adjkey = [key[3], (-1 * key[1]), (-1 * key[2]), key[0]]
		for i in range(len(adjkey)):
			self.inkey.append(ind * adjkey[i])
		# inkey % 26
		for i in range(len(self.inkey)):
			if self.inkey[i] < 0:
				self.inkey[i] += 26
			elif self.inkey[i] >= 26:
				self.inkey[i] = self.inkey[i] % 26
		return self.inkey

	def multKey(self, lettOne, lettTwo, usekey): # Multiplies by the key and find mod if >26
		finOne = (usekey[0] * lettOne)
		finOne += (usekey[1] * lettTwo)
		finTwo = (usekey[2] * lettOne) 
		finTwo += (usekey[3] * lettTwo)

		if finOne in range(26):
			self.calcarray.append(finOne)
		else:
			finOne = finOne % 26
			self.calcarray.append(finOne)
		
		if finTwo in range(26):
			self.calcarray.append(finTwo)
		else:
			finTwo = finTwo % 26
			self.calcarray.append(finTwo)


	def encrypt(self, plaintext):
		# Plaintext to Array of Numbers
		plaintext = plaintext.replace(" ","")
		plaintext = plaintext.upper()
		self.plainarray = list(plaintext)
		for i in range(len(self.plainarray)):
			self.plainarray[i] = alphanum.get(self.plainarray[i])
		# Ensuring array is even, by adding an A to the end if not
		if len(self.plainarray) % 2 !=  0:
			self.plainarray.append(0)
		calcarray = [] # Ensuring the calcarray is empty
		# Computing each pair
		i = 0
		while i < len(self.plainarray):
			firstNum = self.plainarray[i]
			secondNum = self.plainarray[i+1]
			self.multKey(firstNum, secondNum, self.key)
			i += 2
		# Converting Cipherarray to text
		for i in range(len(self.calcarray)):
			self.calcarray[i] = alphanum.get(self.calcarray[i])
		self.ciphertext = "".join(self.calcarray)
		# Returns the final Ciphertext
		return self.ciphertext

	def decrypt(self, ciphertext):
		self.inverseKey(self.key) # Calculates the inverse of the key
		# Ciphertext to Array of Numbers
		ciphertext = ciphertext.replace(" ","")
		ciphertext = ciphertext.upper()
		self.cipherarray = list(ciphertext)
		for i in range(len(self.cipherarray)):
			self.cipherarray[i] = alphanum.get(self.cipherarray[i])
		# Ensuring the array is even, prints out an error if not.
		if len(self.cipherarray) % 2 != 0:
			return print("ERR: Invalid Ciphertext (text not even)")
		self.calcarray = [] # Ensuring the calcarray is empty
		# Computing each Pair
		i = 0
		while i < len(self.cipherarray):
			firstNum = self.cipherarray[i]
			secondNum = self.cipherarray[i+1]
			self.multKey(firstNum, secondNum, self.inkey)
			i += 2
		# Converting Plainarray to text
		for i in range(len(self.calcarray)):
			self.calcarray[i] = alphanum.get(self.calcarray[i])
		self.plaintext = "".join(self.calcarray)
		# Returns the final Plaintext
		return self.plaintext

hill22 = hillcipher22()
