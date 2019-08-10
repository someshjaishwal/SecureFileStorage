package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	RSAKey *userlib.PrivateKey
	Hmac []byte
}


// The structure definition for a file record.
// This record containes the key used for encrypting the contents of file and location of file blocks.
// There is a new block generated for each append on file.
type FileData struct{
	Keys [][]rune
	Blocks []string
	Hmac []byte
}


// The structure used to store individual blocks of a file
type FileBlock struct{
	Data []rune
	Hmac []byte
}

// The structure used to store the details for each file for each user who has access to that file.
type UserFile struct{
	Location string
	Key []rune
	Hmac []byte
}
	
// Function to get Address and Key used for a UserFile pair
func UserFileCredentials(username string, password string, filename string) (Addr string, E []byte){
	//Generating address of UserFile structure
	Addr = getAddress([]byte(username+password+filename))

	//Generating Key for UserFile structure
	E =userlib.Argon2Key([]byte(string([]rune(password+username))),[]byte(filename),16)
	userlib.DebugMsg("User %v File %v stored at Addr=%v   E=%v",username,filename,Addr,E)

	return 
}

//Function to compute address in Datastore from given bytes
func getAddress(str []byte) (address string){
	hash :=userlib.NewSHA256()
	hash.Write(str)
	address = hex.EncodeToString(hash.Sum(nil))
	return
}

//Function to encrypt data using AES
func encryptAES(data []byte, key []byte) (ciphertext []byte){
	ciphertext = make([]byte, userlib.BlockSize+len(data))
	iv := ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], data)
	return
}

//Function to decrypt data using AES
func decryptAES(ciphertext []byte, Key []byte) (plaintext []byte, err error){
	if(len(ciphertext)<=userlib.BlockSize){
		return nil,errors.New(strings.ToTitle("Invalid Ciphertext"))
	}
	iv := ciphertext[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(Key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])
	plaintext = ciphertext[userlib.BlockSize:]
	return plaintext,nil
}


// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.
	
// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var Userdata User
	
	//Generating RSA Keys
	RSAKey, err1 := userlib.GenerateRSAKey()
	if(err1!=nil){
		return nil, err1
	}
	
	//Generating key for encryption and HMAC
	Key :=userlib.Argon2Key([]byte(password),[]byte(username),16)

	// Populating User data structure
	Userdata.Username =username
	Userdata.Password =password
	Userdata.RSAKey=RSAKey

	// Marshalling User data structure to JSON representation
	str,_ := json.Marshal(Userdata)

	// Calculating HMAC
	hmac := userlib.NewHMAC(Key)
	hmac.Write([]byte(str))
	Userdata.Hmac=hmac.Sum(nil)

	//Final Marshalled User data structure
	str,_=json.Marshal(Userdata)

	//Storing Public Key in Keystore
	pubkey := RSAKey.PublicKey
	userlib.KeystoreSet(username,pubkey)

	//Calculating hash(password+username) (Location of User data structure in Datastore)
	Index:= getAddress([]byte(password+username))

	// Encrypting User data structure with Key
	ciphertext := encryptAES([]byte(str),Key) 

	// Storing data on Datastore
	userlib.DatastoreSet(Index,ciphertext)

	return &Userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var Userdata User

	// Calculating hash(password+username) (Location of User data structure in Datastore)
	Index := getAddress([]byte(password+username))

	// Fetch data at above Index from Data
	ciphertext, valid := userlib.DatastoreGet(Index)
	if(!valid){
		err1 := errors.New(strings.ToTitle("No such user or User record corrupted."))
		return nil,err1
	}

	//Generating key for encryption and HMAC
	Key :=userlib.Argon2Key([]byte(password),[]byte(username),16)

	//Decrypting Cipher Text using above Key
	UserJson,err2 := decryptAES(ciphertext,Key)
	if(err2!=nil){
		return nil,err2
	}

	//Unmarshalling User data structure
	err1 := json.Unmarshal(UserJson,&Userdata)
	if(err1!=nil){
		err1 := errors.New(strings.ToTitle("No such user or User record corrupted."))
		return nil,err1
	}

	/////////////////////    Verifying HMAC    /////////////////
	// Creating a temporary copy of Userdata without Hmac
	var Usertemp User
	Usertemp.Username = Userdata.Username
	Usertemp.Password = Userdata.Password
	Usertemp.RSAKey = Userdata.RSAKey

	// Marshalling Usertemp
	str,_ := json.Marshal(Usertemp)

	// Calculating Hmac
	hmac := userlib.NewHMAC(Key)
	hmac.Write([]byte(str))
	Usertemp.Hmac=hmac.Sum(nil)

	// Checking if HMACs are equal
	if !userlib.Equal(Usertemp.Hmac, Userdata.Hmac) {
		err1 := errors.New(strings.ToTitle("User record corrupted by server."))
		return nil,err1		
	}

	return &Userdata,err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	var Mapping UserFile
	var File FileData
	var Data FileBlock

	//////////////////////////////////////////////
	//////////// UserFile Record /////////////////
	//////////////////////////////////////////////

	// get address and Encryption Key for UserFile
	Addr,E := UserFileCredentials(userdata.Username,userdata.Password,filename)	

	flag := false //Will be true if a valid file with this name already exists

	//Checking if this file already exists and getting Index and Key for FileData if it exists
	ciphertext,valid := userlib.DatastoreGet(Addr)


	if(valid){
		flag=true
		userlib.DebugMsg("Stored at %v is %v",Addr,ciphertext)

		//Decrypting UserFileData
		plaintext,err10 := decryptAES(ciphertext, E)
		if(err10!=nil) {
			flag = false
		} else {

		err := json.Unmarshal(plaintext,&Mapping)

		if(err!=nil){
			flag=false
			userlib.DebugMsg("Error in unmarshalling already available")
		} else{

			//Verifying HMAC
			var temp UserFile
			temp.Location=Mapping.Location
			temp.Key=Mapping.Key

			str,_ := json.Marshal(temp)

			hmac := userlib.NewHMAC(E)
			hmac.Write([]byte(str))
			temp.Hmac=hmac.Sum(nil)

			if !userlib.Equal(temp.Hmac, Mapping.Hmac) {
				userlib.DebugMsg("%v",errors.New(strings.ToTitle("UserFile record corrupted by server.")))
				flag=false	
			}

		}
	}
}



		///////////////////////////////////////////////
		/////////////// FileData Record ///////////////
		///////////////////////////////////////////////

		var Addr1 string
		var E1 []rune
		if(!flag){

			//Generate Address for FileData
			Addr1 = getAddress(userlib.RandomBytes(256))	
			
			//Generate Key for Encrypting and generating HMAC for FileData record
			E1 =[]rune(string(userlib.Argon2Key([]byte(string([]rune(userdata.Password+filename))),userlib.RandomBytes(16),16)))
			userlib.DebugMsg("User %v File %v stored at Addr1=%v E1=%v",userdata.Username,filename,Addr1,E1)
	

			//Populating UserFile structure 
			Mapping.Location=Addr1
			Mapping.Key=E1

			//Calculating HMAC and updating UserFile structure
			str1,_ := json.Marshal(Mapping)
			hmac1 := userlib.NewHMAC(E)
			hmac1.Write([]byte(str1))
			Mapping.Hmac=hmac1.Sum(nil)	

			//Marshalling UserFile structure
			str1,_ = json.Marshal(Mapping)


			//Encrypting UserFile structure with E
			ciphertext1 := encryptAES( []byte(str1), E) 

			// Storing encrypted UserFile structure at Addr
			userlib.DebugMsg("Stored at %v is %v",Addr,ciphertext1)
			userlib.DatastoreSet(Addr,ciphertext1)
		} else
		{
			//Getting Addr1 and E1 from existing UserFile structure(Overwriting existing file)
			E1=Mapping.Key
			Addr1=Mapping.Location
			userlib.DebugMsg("User %v File %v stored at Addr1=%v E1=%v",userdata.Username,filename,Addr1,E1)
		}

		//Generating Addr2- address for the first block of this file
		Addr2 := getAddress(userlib.RandomBytes(256))


		//Generating E2- Key to encrypt and generate HMAC for the first block of this file
		E2 :=[]rune(string(userlib.Argon2Key(userlib.RandomBytes(256),userlib.RandomBytes(256),16)))
		userlib.DebugMsg("User %v File %v stored at Addr2=%v E2=%v",userdata.Username,filename,Addr2,E2)

		//Populating FileData structure
		File.Keys=nil
		File.Keys=append(File.Keys,E2)
		File.Blocks=nil
		File.Blocks=append(File.Blocks, Addr2)

		//Calculating HMAC and updating FileData structure
		str2,_ := json.Marshal(File)
		hmac2 := userlib.NewHMAC([]byte(string(E1)))
		hmac2.Write([]byte(str2))
		File.Hmac=hmac2.Sum(nil)

		//Marshalling FileData structure
		str2,_ = json.Marshal(File)

		//Encrypting FileData structure with E1
		ciphertext2 := encryptAES([]byte(str2),[]byte(string(E1))[:16]) 

		// Storing encrypted FileData structure at Addr1
		userlib.DatastoreSet(Addr1,ciphertext2)
		userlib.DebugMsg("Stored at %v, Value=%v",Addr1,ciphertext2)

		///////////////////////////////////////////////
		////////////// FileBlock Record ///////////////
		///////////////////////////////////////////////

		Data.Data=[]rune(string(data))

		//Calculating HMAC and updating FileBlock structure
		str3,_ := json.Marshal(Data)
		hmac3 := userlib.NewHMAC([]byte(string(E2)))
		hmac3.Write([]byte(str3))
		Data.Hmac=hmac3.Sum(nil)	

		//Marshalling FileBlock structure
		str3,_ = json.Marshal(Data)

		//Encrypting FileBlock structure with E2
		ciphertext3 := encryptAES([]byte(str3),[]byte(string(E2))[:16]) 

		// Storing encrypted FileBlock structure at Addr2
		userlib.DatastoreSet(Addr2,ciphertext3)
		userlib.DebugMsg("Stored at %v, Value=%v",Addr2,ciphertext3)

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var Mapping UserFile
	var File FileData
	var Data FileBlock

	//////////////////////////////////////////////
	//////////// UserFile Record /////////////////
	//////////////////////////////////////////////

    // Generating address and key for UserFile pair
	Addr,E := UserFileCredentials(userdata.Username,userdata.Password,filename)	
	userlib.DebugMsg("APPEND: User %v File %v stored at Addr=%v E=%v",userdata.Username,filename,Addr,E)

	// Fetching Encrypted UserFile structure from memory
	ciphertext,valid := userlib.DatastoreGet(Addr)
	if(!valid){
		err3 := errors.New(strings.ToTitle("No such file"))
		return err3
	}

	// Decrypting UserFileData
	plaintext,err10 := decryptAES(ciphertext,E)
	if(err10!=nil) {
		return err10
	}
    
    // Unmarshaling and checking for errors
	err3 := json.Unmarshal(plaintext,&Mapping)

	if(err3!=nil){
		return err3
	}

	// Verifying HMAC
	var temp UserFile
	temp.Location=Mapping.Location
	temp.Key=Mapping.Key

	str,_ := json.Marshal(temp)

	hmac := userlib.NewHMAC(E)
	hmac.Write([]byte(string([]rune(string(str)))))
	temp.Hmac=hmac.Sum(nil)

	if !userlib.Equal(temp.Hmac, Mapping.Hmac) {
		err3 = errors.New(strings.ToTitle("UserFile record corrupted by server."))
		userlib.DebugMsg("%v",err3)
		return err3
	}

	////////////////////////////////////////////////////////
	////////////////// FileData structure //////////////////
	////////////////////////////////////////////////////////

	// Fetching Address and Key used for FileData structure
	Addr1 := Mapping.Location
	E1 := Mapping.Key
	userlib.DebugMsg("APPEND: User %v File %v stored at Addr1=%v E1=%v",userdata.Username,filename,Addr1,E1)

	// Fetching Encrypted FileData structure from memory
	ciphertext1,valid1 := userlib.DatastoreGet(Addr1)
	if(!valid1){
		err1 := errors.New(strings.ToTitle("File Data lost"))
		return err1
	}

	// Decrypting FileData record
	plaintext1,err11 := decryptAES(ciphertext1, []byte(string(E1))[:16])
	if(err11!=nil){
		return err11
	}

	err1 := json.Unmarshal(plaintext1, &File)

	if(err1!=nil){
		return err1
	}

	// Verifying HMAC
	var temp1 FileData
	temp1.Blocks=File.Blocks
	temp1.Keys=File.Keys
	temp1.Hmac=File.Hmac

	File.Hmac=nil
	str1,_ := json.Marshal(File)
	hmac1 := userlib.NewHMAC([]byte(string(E1)))
	hmac1.Write([]byte(str1))
	File.Hmac=hmac1.Sum(nil)

	if !userlib.Equal(temp1.Hmac, File.Hmac) {
		err1 = errors.New(strings.ToTitle("Append: FileData record corrupted by server."))
		userlib.DebugMsg("%v",err1)
		return err1
	}

////////////////////////    Updating FileData structure      //////////////////////// 
//////////////////////// and storing it back in Datastore    //////////////////////// 

	// Generating Addr2- address for this block of this file
	Addr2 := getAddress(userlib.RandomBytes(256))


	// Generating E2- Key to encrypt and generate HMAC for this block of this file
	E2 :=[]rune(string(userlib.Argon2Key(userlib.RandomBytes(256),userlib.RandomBytes(256),16)))
	userlib.DebugMsg("APPEND: User %v File %v stored at Addr2=%v E2=%v",userdata.Username,filename,Addr2,E2)

    // Updating slices of FileData structure
	File.Keys=append(File.Keys,E2)
	File.Blocks=append(File.Blocks, Addr2)
	File.Hmac=nil

	// Calculating HMAC and updating FileData structure
	str2,_ := json.Marshal(File)
	hmac2 := userlib.NewHMAC([]byte(string(E1)))
	hmac2.Write([]byte(str2))
	File.Hmac=hmac2.Sum(nil)

	// Marshalling FileData structure
	str2,_ = json.Marshal(File)

	// Encrypting FileData structure with E1
	ciphertext2 := encryptAES([]byte(str2), []byte(string(E1))[:16])

	// Storing encrypted FileData structure at Addr1
	userlib.DatastoreSet(Addr1,ciphertext2)



	////////////////////////////////////////////////////////////////////
	///////////////////// Appending FileBlock //////////////////////////
	////////////////////////////////////////////////////////////////////

	Data.Data=[]rune(string(data))

	//Calculating HMAC and updating FileBlock structure
	str3,_ := json.Marshal(Data)
	hmac3 := userlib.NewHMAC([]byte(string(E2)))
	hmac3.Write([]byte(str3))
	Data.Hmac=hmac3.Sum(nil)	

	//Marshalling FileBlock structure
	str3,_ = json.Marshal(Data)

	//Encrypting FileBlock structure with E2
	ciphertext3 := encryptAES([]byte(str3), []byte(string(E2))[:16]) 

	// Storing encrypted FileBlock structure at Addr2
	userlib.DatastoreSet(Addr2,ciphertext3)
	userlib.DebugMsg("Stored at %v, Value=%v",Addr2,ciphertext3)


	return nil
}

// This loads a file from the Datastore.
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	var Mapping UserFile
	var File FileData
	var Data FileBlock

	//////////////////////////////////////////////
	//////////// UserFile Record /////////////////
	//////////////////////////////////////////////

    // Generating address and key for UserFile pair
	Addr,E := UserFileCredentials(userdata.Username,userdata.Password,filename)	
	userlib.DebugMsg("LOAD: User %v File %v stored at Addr=%v E=%v",userdata.Username,filename,Addr,E)


	// Fetching Encrypted UserFile structure from memory
	ciphertext,valid := userlib.DatastoreGet(Addr)
	if(!valid){
		err3 := errors.New(strings.ToTitle("No such file"))
		return nil,err3
	}

	// Decrypting UserFileData
	plaintext,err10 := decryptAES(ciphertext, E)
	if(err10!=nil){
		return nil,err10
	}


	err3 := json.Unmarshal(plaintext,&Mapping)

	if(err!=nil){
		return nil,err
	}

	//Verifying HMAC
	var temp UserFile
	temp.Location=Mapping.Location
	temp.Key=Mapping.Key

	str,_ := json.Marshal(temp)

	hmac := userlib.NewHMAC(E)
	hmac.Write([]byte(str))
	temp.Hmac=hmac.Sum(nil)

	if !userlib.Equal(temp.Hmac, Mapping.Hmac) {
		err3 = errors.New(strings.ToTitle("UserFile record corrupted by server."))
		userlib.DebugMsg("%v",err3)
		return nil,err3
	}

	////////////////////////////////////////////////////////
	////////////////// FileData structure //////////////////
	////////////////////////////////////////////////////////

	//Fetching Address and Key used for FileData structure
	Addr1 := Mapping.Location
	E1 := Mapping.Key
	userlib.DebugMsg("LOAD: User %v File %v stored at Addr1=%v E1=%v",userdata.Username,filename,Addr1,E1)


	//Fetching Encrypted FileData structure from memory
	ciphertext1,valid1 := userlib.DatastoreGet(Addr1)
	if(!valid1){
		err1 := errors.New(strings.ToTitle("File Data lost"))
		return nil,err1
	}

	//Decrypting FileData record
	plaintext1,err11 := decryptAES(ciphertext1, []byte(string(E1))[:16])
	if(err11!=nil) {
		return nil,err11
	}

	err1 := json.Unmarshal(plaintext1, &File)

	if(err1!=nil){
		return nil,err1
	}

	//Verifying HMAC
	var temp1 FileData
	temp1.Blocks=File.Blocks
	temp1.Keys=File.Keys
	temp1.Hmac=File.Hmac

	File.Hmac=nil
	str1,_ := json.Marshal(File)
	hmac1 := userlib.NewHMAC([]byte(string(E1)))
	hmac1.Write([]byte(str1))
	File.Hmac=hmac1.Sum(nil)

	if !userlib.Equal(temp1.Hmac, File.Hmac) {
		err1 = errors.New(strings.ToTitle("FileData record corrupted by server."))
		userlib.DebugMsg("%v",err1)
		return nil,err1
	}

	//////////////////////////////////////////////////////
	////////////// FileBlock structure ///////////////////
	//////////////////////////////////////////////////////

	NumberOfBlocks := len(File.Blocks)

	var Addr2 string
	var E2 []rune

	//Iterating over each block
	for i:=0; i< NumberOfBlocks; i++{

		//Getting Address and Key for this block
		Addr2 = File.Blocks[i]
		E2 = File.Keys[i]
		userlib.DebugMsg("LOAD: User %v File %v stored at Addr2=%v E2=%v",userdata.Username,filename,Addr2,E2)


		//Fetching Encrypted FileBlock structure from memory
		ciphertext2,valid2 := userlib.DatastoreGet(Addr2)
		if(!valid2){
			err2 := errors.New(strings.ToTitle("Block Data lost"))
			return nil,err2
		}

		//Decrypting FileBlock record
		plaintext2,err12 := decryptAES(ciphertext2, []byte(string(E2))[:16])
		if(err12!=nil) {
			return nil,err12
		}

		err2 := json.Unmarshal(plaintext2,&Data)

		if(err2!=nil){
			userlib.DebugMsg("%v",err2)
			return nil,err2
		}

		//Verifying HMAC
		var temp2 FileBlock
		temp2.Data=Data.Data

		str2,_ := json.Marshal(temp2)

		hmac2 := userlib.NewHMAC([]byte(string(E2)))
		hmac2.Write([]byte(str2))
		temp2.Hmac=hmac2.Sum(nil)

		if !userlib.Equal(temp2.Hmac, Data.Hmac) {
			err2 = errors.New(strings.ToTitle("Block Data corrupted by server."))
			userlib.DebugMsg("%v",err2)
			return nil,err2
		}

		data = append(data, []byte(string(Data.Data))...)
	}

	return data,nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Seed1 string
	Seed2 string
	Seed3 string
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	
	
	////////////////// Loading The file //////////////////////////


	var Mapping UserFile
	var Share UserFile

    // Generating address and key for UserFile pair
	Addr,E := UserFileCredentials(userdata.Username,userdata.Password,filename)	
	userlib.DebugMsg("SHARE: User %v File %v stored at Addr=%v E=%v",userdata.Username,filename,Addr,E)

	//Fetching Encrypted UserFile structure from memory
	ciphertext,valid := userlib.DatastoreGet(Addr)
	if(!valid){
		err3 := errors.New(strings.ToTitle("No such file"))
		return msgid,err3
	}

	//Decrypting UserFileData
	plaintext,err10 := decryptAES(ciphertext, E)
	if(err10!=nil) {
		return msgid,err10
	}

	err3 := json.Unmarshal(plaintext,&Mapping)

	if(err!=nil){
		return msgid,err
	}

	//////Verifying HMAC
	var temp UserFile
	temp.Location=Mapping.Location
	temp.Key=Mapping.Key

	str,_ := json.Marshal(temp)

	hmac := userlib.NewHMAC(E)
	hmac.Write([]byte(str))
	temp.Hmac=hmac.Sum(nil)

	if !userlib.Equal(temp.Hmac, Mapping.Hmac) {
		err3 = errors.New(strings.ToTitle("UserFile record corrupted by server."))
		userlib.DebugMsg("%v",err3)
		return msgid,err3
	}

	//Fetching Sender's and recipient's Keys
	Key := userdata.RSAKey
	ReceiverKey,valid := userlib.KeystoreGet(recipient) 
	if(!valid){
		return msgid,errors.New(strings.ToTitle("Recipient not found"))
	}

	/////////////////////////////////////////////////////////////////////////////////////////
	// Storing sharing information
	/////////////////////////////////////////////////////////////////////////////////////////

	seed1 := uuid.New().String()
	seed2 := uuid.New().String()
	seed3 := uuid.New().String() 

    // Generating address and key for record containing sharing information
	RecordLocation := getAddress([]byte(seed1))
	E1 :=[]rune(string(userlib.Argon2Key([]byte(seed2),[]byte(seed3),16)))
	userlib.DebugMsg("SHARE: Sharing Record stored at Addr=%v E=%v",RecordLocation,E1)

	// Populating sharingRecord (message to be sent)
	var Data sharingRecord 
	//Data.Location = RecordLocation
	Data.Seed1 = seed1
	Data.Seed2 = seed2
	Data.Seed3 = seed3

	// Populating Share
	Share.Location = Mapping.Location
	Share.Key=Mapping.Key
	str1,_ := json.Marshal(Share)

	hmac1 := userlib.NewHMAC([]byte(string(E1)))
	hmac1.Write([]byte(str1))
	Share.Hmac=hmac1.Sum(nil)

	//Marshalling FileData structure
	str3,_ := json.Marshal(Share)

	//Encrypting FileData structure with E1
	ciphertext3 := encryptAES([]byte(str3), []byte(string(E1))[:16]) 

	// Storing encrypted FileData structure at Addr1
	userlib.DebugMsg("Stored at %v is %v",RecordLocation,ciphertext3)
	userlib.DatastoreSet(RecordLocation,ciphertext3)

	//Encrypting with recipient's public key
	str2,_ := json.Marshal(Data)
	encrypted,err := userlib.RSAEncrypt(&ReceiverKey,str2,nil)
	if(err!=nil){
		return msgid,err
	}

	//RSA signing
	sign, err := userlib.RSASign(Key, str2)
	if err != nil {
		return msgid,err
	}
	
	msgid = string(encrypted)

	userlib.DatastoreSet(getAddress(encrypted),sign)

	return msgid,nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {

	var Mapping UserFile
	var Share UserFile
	var Data sharingRecord

	//Fetching Receiver's private key and sender's public key
	Key := userdata.RSAKey
	SenderKey,valid := userlib.KeystoreGet(sender)
	if !valid {
		return errors.New(strings.ToTitle("Sender's Key not available"))
	} 


	//Fetching RSA sign
	encrypted := []byte(msgid)
	sign,valid := userlib.DatastoreGet(getAddress(encrypted))
	if !valid {
		return errors.New(strings.ToTitle("Sign verification failed"))
	}
	//encrypted := msg[:(len(msg)-256)]

	//RSA Decrypt
	str,err := userlib.RSADecrypt(Key,encrypted,nil)
	if(err!=nil){
		return err
	}

	//Verifying RSA sign
	err10 := userlib.RSAVerify(&SenderKey, str, sign)
	if(err10!=nil){
		return err10
	}

	//Unmarshalling Decrypted received message
	err1 := json.Unmarshal(str, &Data)
	if(err1!=nil){
		return err1
	}

	///////////////////////////////////////////////////////
	////////// Fetching Sharing Information ///////////////
    ///////////////////////////////////////////////////////
	seed1 := Data.Seed1
	seed2 := Data.Seed2
	seed3 := Data.Seed3

	// Generating Address and Key where record is stored in memory with Sharing details
	RecordLocation := getAddress([]byte(seed1))
	E1 :=[]rune(string(userlib.Argon2Key([]byte(seed2),[]byte(seed3),16)))
	userlib.DebugMsg("RECEIVE: Sharing Record stored at Addr=%v E=%v",RecordLocation,E1)

	//Fetching Encrypted FileData structure from memory
	ciphertext2,valid2 := userlib.DatastoreGet(RecordLocation)
	if(!valid2){
		err2 := errors.New(strings.ToTitle("Sharing Record lost"))
		return err2
	}

	//Decrypting FileData record
	plaintext2,err50 := decryptAES(ciphertext2, []byte(string(E1))[:16])
	if(err50!=nil) {
		return err50
	}

	err2 := json.Unmarshal(plaintext2,&Share)

	if(err2!=nil){
		return err2
	}

	// Verifying HMAC
	var temp2 UserFile
	temp2.Location = Share.Location
	temp2.Key = Share.Key
	str2,_:=json.Marshal(temp2)

	hmac2 := userlib.NewHMAC([]byte(string(E1)))
	hmac2.Write([]byte(str2))
	temp2.Hmac=hmac2.Sum(nil)

	if !userlib.Equal(temp2.Hmac, Share.Hmac) {
		err2 = errors.New(strings.ToTitle("Record corrupted by server."))
		userlib.DebugMsg("%v",err2)
		return err2
	}


	///////////////////////////////////////////////////////////////////
	////////////// Storing this file as Receiver's own file ///////////
	///////////////////////////////////////////////////////////////////
	
	//Populating Mapping structure

	Mapping.Location = Share.Location
	Mapping.Key = Share.Key

	Addr,E := UserFileCredentials(userdata.Username,userdata.Password,filename)	
	userlib.DebugMsg("RECEIVE: User %v File %v stored at Addr=%v E=%v",userdata.Username,filename,Addr,E)

	//Calculating HMAC and updating UserFile structure
	str1,_ := json.Marshal(Mapping)
	hmac1 := userlib.NewHMAC(E)
	hmac1.Write([]byte(str1))
	Mapping.Hmac=hmac1.Sum(nil)

	//Marshalling UserFile structure
	str1,_ = json.Marshal(Mapping)

	//Encrypting UserFile structure with E
	ciphertext1 := encryptAES([]byte(str1),E) 

	// Storing encrypted UserFile structure at Addr
	userlib.DebugMsg("Stored at %v is %v",Addr,ciphertext1)
	userlib.DatastoreSet(Addr,ciphertext1)	

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {

	////////////////////////////////////////////////////////////////////////////////
	////////////////////////// Fetching the Already saved Data /////////////////////
	////////////////////////////////////////////////////////////////////////////////

	var Mapping UserFile
	var File FileData
	var Data FileBlock

	//////////////////////////////////////////////
	//////////// UserFile Record /////////////////
	//////////////////////////////////////////////

	Addr,E := UserFileCredentials(userdata.Username,userdata.Password,filename)	
	userlib.DebugMsg("REVOKE: User %v File %v stored at Addr=%v E=%v",userdata.Username,filename,Addr,E)

	//Fetching Encrypted UserFile structure from memory
	ciphertext,valid := userlib.DatastoreGet(Addr)
	if(!valid){
		err3 := errors.New(strings.ToTitle("No such file"))
		//userlib.DebugMsg("Cipher:%v",ciphertext)
		return err3
	}

	//Decrypting UserFileData
	plaintext,err10 := decryptAES(ciphertext, E)
	if(err10!=nil){
		return err10
	}

	err3 := json.Unmarshal(plaintext,&Mapping)

	if(err!=nil){
		return err
	}

	//Verifying HMAC
	var temp UserFile
	temp.Location=Mapping.Location
	temp.Key=Mapping.Key

	str,_ := json.Marshal(temp)

	hmac := userlib.NewHMAC(E)
	hmac.Write([]byte(str))
	temp.Hmac=hmac.Sum(nil)

	if !userlib.Equal(temp.Hmac, Mapping.Hmac) {
		err3 = errors.New(strings.ToTitle("REVOKE:UserFile record corrupted by server."))
		userlib.DebugMsg("%v",err3)
		return err3
	}

	//Deleting this UserFile mapping
	userlib.DatastoreDelete(Addr)


	////////////////////////////////////////////////////////
	////////////////// FileData structure //////////////////
	////////////////////////////////////////////////////////

	//Fetching Address and Key used for FileData structure
	Addr1 := Mapping.Location
	E1 := Mapping.Key

	//Fetching Encrypted FileData structure from memory
	ciphertext1,valid1 := userlib.DatastoreGet(Addr1)
	if(!valid1){
		err1 := errors.New(strings.ToTitle("File Data lost"))
		return err1
	}

	//Decrypting FileData record
	plaintext1,err11 := decryptAES(ciphertext1, []byte(string(E1))[:16])
	if(err11!=nil){
		return err11
	}
	err1 := json.Unmarshal(plaintext1, &File)

	if(err1!=nil){
		return err1
	}

	//Verifying HMAC
	var temp1 FileData
	temp1.Blocks=File.Blocks
	temp1.Keys=File.Keys
	temp1.Hmac=File.Hmac

	File.Hmac=nil
	
	str1,_ := json.Marshal(File)
	
	hmac1 := userlib.NewHMAC([]byte(string(E1)))
	hmac1.Write([]byte(str1))
	File.Hmac=hmac1.Sum(nil)


	if !userlib.Equal(temp1.Hmac, File.Hmac) {
		err1 = errors.New(strings.ToTitle("FileData record corrupted by server."))
		userlib.DebugMsg("%v",err1)
		return err1
	}

	//Deleting FileData Data
	userlib.DatastoreDelete(Addr1)

	//////////////////////////////////////////////////////
	////////////// FileBlock structure ///////////////////
	//////////////////////////////////////////////////////


	var data []byte
	NumberOfBlocks := len(File.Blocks)

	var Addr2 string
	var E2 []rune

	//Iterating over each block

	for i:=0; i< NumberOfBlocks; i++{

		//Getting Address and Key for this block
		Addr2 = File.Blocks[i]
		E2 = File.Keys[i]

		//Fetching Encrypted FileBlock structure from memory
		ciphertext2,valid2 := userlib.DatastoreGet(Addr2)
		if(!valid2){
			err2 := errors.New(strings.ToTitle("Block Data lost"))
			return err2
		}

		//Decrypting FileBlock record
		plaintext2,err12 := decryptAES(ciphertext2, []byte(string(E2))[:16])
		if(err12!=nil){
			return err12
		}


		err2 := json.Unmarshal(plaintext2,&Data)

		if(err2!=nil){
			userlib.DebugMsg("%v",err2)
			return err2
		}

		//Verifying HMAC
		var temp2 FileBlock
		temp2.Data=Data.Data

		str2,_ := json.Marshal(temp2)

		hmac2 := userlib.NewHMAC([]byte(string(E2)))
		hmac2.Write([]byte(str2))
		temp2.Hmac=hmac2.Sum(nil)

		if !userlib.Equal(temp2.Hmac, Data.Hmac) {
			err2 = errors.New(strings.ToTitle("Block Data corrupted by server."))
			userlib.DebugMsg("%v",err2)
			return err2
		}
		
		// deleting current block from memory
		userlib.DatastoreDelete(Addr2)

		data = append(data, []byte(string(Data.Data))...)
	}

	/////////////////////////////////////////////////////////////////////////////////
	///////////////////// Storing the data back in memory(Access Revoked) ///////////
	/////////////////////////////////////////////////////////////////////////////////

	userdata.StoreFile(filename,data)

	return nil
}