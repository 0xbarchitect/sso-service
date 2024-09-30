package service

import (
	"fmt"
	"sync"

	"github.com/bwmarrin/snowflake"
)

var (
	sfInstance *SFGenerator
	mu         sync.Mutex
)

func SetSFGenerator(ins *SFGenerator) {
	mu.Lock()
	defer mu.Unlock()
	sfInstance = ins
}

func GetSFGenerator() *SFGenerator {
	mu.Lock()
	defer mu.Unlock()
	return sfInstance
}

type SFGenerator struct {
}

func (sf *SFGenerator) GenerateID() (int64, error) {
	// Create a new Node with a Node number of 1
	node, err := snowflake.NewNode(1) // TODO
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	// Generate a snowflake ID.
	id := node.Generate()

	// Print out the ID in a few different ways.
	//fmt.Printf("Int64  ID: %d\n", id)
	//fmt.Printf("String ID: %s\n", id)
	//fmt.Printf("Base2  ID: %s\n", id.Base2())
	//fmt.Printf("Base64 ID: %s\n", id.Base64())

	// Print out the ID's timestamp
	//fmt.Printf("ID Time  : %d\n", id.Time())

	// Print out the ID's node number
	//fmt.Printf("ID Node  : %d\n", id.Node())

	// Print out the ID's sequence number
	//fmt.Printf("ID Step  : %d\n", id.Step())

	return id.Int64(), nil
}
