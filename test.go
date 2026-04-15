package main
import (
	"fmt"
	"time"
)
func main() {
	go func() {
		fmt.Println("GOROUTINE")
	}()
	time.Sleep(1 * time.Second)
}
