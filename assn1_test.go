package assn1

import "github.com/fenilfadadu/CS628-assn1/userlib"
import "testing"
import "reflect"
import "math/rand"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
//	someUsefulThings()

	//userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	u1, err1 := InitUser("alice1", "fubar1")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	hash :=userlib.NewSHA256()
	hash.Write([]byte("fubar"+"alice"))
	Index := string(hash.Sum(nil))
	
	// t.Log() only produces output if you run with "go test -v"
	hash1 :=userlib.NewSHA256()
	hash1.Write([]byte("fubar1"+"alice1"))
	Index1 := string(hash1.Sum(nil))
	data,_ :=userlib.DatastoreGet(Index1)
	userlib.DatastoreSet(Index,data)

	u,err = GetUser("alice", "fubar")
	if err!=nil{
		t.Error(err)
	}
	t.Log("Got user", u)
	u1,err1 = GetUser("alice1", "fubar1")
	if err1!=nil{
		t.Error(err1)
	}
	t.Log("Got user", u1)
	//k,_:=userlib.KeystoreGet("alice")
	//k1,_:=userlib.KeystoreGet("alice1")
	//t.Log("Alice:",k)
	//t.Log("Alice1:",k1)
	// You probably want many more tests here.


}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v1 := []byte("This is not a test")
	u.StoreFile("file1", v1)

	v3 := []byte(". But this is a test.")
	u.AppendFile("file1",v3)

	v1=append(v1,v3...)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	userlib.DebugMsg("v1:%v",string(v1))
	userlib.DebugMsg("v2:%v",string(v2))
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
	userlib.DebugMsg("v:%v",string(v))
	userlib.DebugMsg("v2:%v",string(v2))
	err10 := u2.RevokeFile("file2")
	if err10!=nil{
		t.Error("Revoke error", err10)
	}
	userlib.DebugMsg("v2:%v",string(v2))
	f, err11 := u.LoadFile("file1")
	if err11==nil{
		if !reflect.DeepEqual(f,v2){
			t.Error("Able to access after revoke 1")
		}
		t.Error("Able to access after revoke 2",string(f))
	}

	v3, err12 := u2.LoadFile("file2")
	if err12 !=nil {
		t.Error("Failed to fetch file after Revoke",err12)
	}

	if !reflect.DeepEqual(v2,v3) {
		t.Error("Revoked file is not the same",v2,v3)
	}

}

func TestMutate(t *testing.T) {
	/*u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}*/
	u1,err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	v1,err1 := u1.LoadFile("file2")
	if(err1!=nil) {
		t.Error("Failed to load file",err1)
	}

	Addr := getAddress([]byte(u1.Username+u1.Password+"file2"))
	Value,valid := userlib.DatastoreGet(Addr)
	if(!valid) {
		t.Error("Data Lost")
	}
	m:= rand.Intn(len(Value))
	Value[m]=Value[m]-1
	//n:= rand.Intn(len(Value))
	//Value[n] = Value[n]+1
	userlib.DatastoreSet(Addr,Value)

	v2,err2 := u1.LoadFile("file2")
	if(err2==nil){
		t.Error("Mutate failed",err2)
	} 

	if reflect.DeepEqual(v1,v2) {
		t.Error("No change after mutation")
	}
}



