package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

type SignupRequest struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	User_type        string `json:"user_type"`
	Teacher_group_id int64  `json:"teacher_group_id"`
}

func main() {
	log.Println("Started")
	rand.Seed(time.Now().Unix())
	for i := 0; i < 2; i++ {
		singRequest := SignupRequest{
			Username:         "user_" + strconv.FormatInt(rand.Int63(), 10),
			Password:         "vocaloid",
			User_type:        "artist",
			Teacher_group_id: 0,
		}
		data, err := json.Marshal(singRequest)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Regesting User %s", singRequest.Username)
		resp, err := http.Post("http://localhost:8000/gallery/api/account/signup/", "application/jsonrequest", bytes.NewReader(data))
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		respData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(string(respData))

	}
}
