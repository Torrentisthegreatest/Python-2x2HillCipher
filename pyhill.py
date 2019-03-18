class  hillcipher():

	#key array vals: 0 is top left, 1 top right, 2 bottom left, 3 bottom right
	alphakey = []
	invkey = []
	plaintext = ""
	ciphertext = ""
	cipherarray = []
	
	# keydict template for ease of use when inputting data
	#keydict = {
	#	"topleft":0, "topright":1,
	#	"bottomleft":2, "bottomright":3
	#}

	def __init__(self): #Do not edit, are necessary to work correctly!
		self.mult26 = [2, 13, 26] #Multiples of 26
		self.alphanum = { #Dict of Alpha vals to Num vals
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
		self.calcarray = []

	def keydict2array(self, keydict): #Returns key array from key dict, returns array
		key = []
		for i in keydict:
			key.append(keydict.get(i))
		return key

	def AlphaNumkey(self, key): #Converts key w/ alpha vals to key w/ num vals, returns array
		for i in range(len(key)):
			self.alphakey.append(self.alphanum.get(key[i]))
		return self.alphakey

	def keyValidate(self, key): #Checks the validity of key, returns bool
		self.d = (key[0] * key[3]) - (key[1] * key[2])
		for i in range(len(self.mult26)):
			if self.d % self.mult26[i] == 0:
				return False
			else:
				return True

	def inverseKey(self, key): #inkey = d^-1 * adj(key), returns array
		if key.isalpha(): #Checks to see if inputted key .isalpha, converts if it is.
			key = self.AlphaNumkey(key)
		if self.keyValidate(key) == False: #Checks valididty of key, returns err msg
			return "Invalid Key"
		self.d = (key[0] * key[3]) - (key[1] * key[2]) #Find d
		#Find d^-1 where d * d^-1 = 1 % 26
		for i in range(1, 26): #Find d^-1
			if (abs(self.d) * i) % 26 == 1:
				self.invd = i
				break
		if self.d < 0: #mult d by -1 if d < 0
			self.invd *= -1
		self.adjkey = [key[3], (-1 * key[1]), (-1 * key[2]), key[0]] #Find adjudicate of key
		for i in range(len(self.adjkey)): #Mult adjudicate of key by d^-1 finding invkey
			self.invkey.append(self.invd * self.adjkey[i])
		for i in range(len(self.invkey)): # Finds mod 26 of inverse of the key
			if self.invkey[i] < 0: #Adds 26 if val is negative
				self.invkey[i] += 26
			elif self.invkey[i] >= 26: # Mods val by 26 if > 26
				self.invkey[i] = self.invkey[i] % 26
		
		return self.invkey #Returns final result

	def multKey(self, firstNum, secondNum, usekey): #Mult int pair by the key & validates, returns int
		# Calculates 2x2 key by int pair
		firstFound = (usekey[0] * firstNum)
		firstFound += (usekey[1] * secondNum)
		secondFound = (usekey[2] * firstNum) 
		secondFound += (usekey[3] * secondNum)

		if firstFound in range(26): #Returns if firstFound is between 0 and 26
			return firstFound
		else: #Returns firstFound % 26
			firstFound %= 26
			return firstFound
		
		if secondFound in range(26): #Returns if secondFound is between 0 and 26
			return secondFound
		else: #Returns secondFound % 26
			secondFound %= 26
			return secondFound

	def encrypt(self, plaintext, key): # Encrypts data from string, returns string
		# Plaintext to Array of Numbers
		plaintext = plaintext.upper() #Capitalizes plaintext
		self.plainarray = list(plaintext.replace(" ","")) #Creates array of plaintext
		for i in range(len(self.plainarray)): #Converts plainarray alpha vals to num vals
			self.plainarray[i] = self.alphanum.get(self.plainarray[i])
		if self.keyValidate(key) == False: #Checks validity of key, returns err msg
			return "Invalid Key, cannot be inversed"
		if len(self.plainarray) % 2 !=  0: #Ensuring array is even, adds an 0 (A) to the end if not
			self.plainarray.append(0)
		self.calcarray = [] #empties calcarray
		i = 0 #inits counter
		while i < len(self.plainarray): #Computes each plain pair to cipher pair
			firstNum = self.plainarray[i] #Gets 1st int in pair
			secondNum = self.plainarray[i+1] #Gets 2nd int in pair
			self.cipherarray.append(self.multKey(firstNum, secondNum, key)) #Appends result to cipherarray
			i += 2 #Add counter by 2, nxt iter will use nxt pair
		for i in range(len(self.calcarray)): #Convert cipherarray int vals to alpha vals
			self.cipherarray[i] = self.alphanum.get(self.cipherarray[i])
		self.ciphertext = "".join(self.cipherarray) #Convert cipherarray to str
		return self.ciphertext #Returns the final Ciphertext

	def decrypt(self, ciphertext):
		self.inverseKey(self.key) # Calculates the inverse of the key
		# Ciphertext to Array of Numbers
		ciphertext = ciphertext.replace(" ","")
		ciphertext = ciphertext.upper()
		self.cipherarray = list(ciphertext)
		for i in range(len(self.cipherarray)):
			self.cipherarray[i] = self.alphanum.get(self.cipherarray[i])
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
