package main

import (
	"fmt"
	"log"
	"regexp"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	wevtapi       = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	EVT_QUERY_CHANNEL_PATH = 1
	EVT_RENDER_EVENT_XML   = 1
)

func utf16PtrFromString(s string) (*uint16, error) {
	u16 := utf16.Encode([]rune(s))
	return &u16[0], nil
}

func evtQuery(logName, query string) (syscall.Handle, error) {
	logNamePtr, err := utf16PtrFromString(logName)
	if err != nil {
		return 0, err
	}
	queryPtr, err := utf16PtrFromString(query)
	if err != nil {
		return 0, err
	}

	handle, _, err := procEvtQuery.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(logNamePtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		EVT_QUERY_CHANNEL_PATH,
	)
	if handle == 0 {
		return 0, err
	}
	return syscall.Handle(handle), nil
}

func evtNext(hQuery syscall.Handle, eventArray []syscall.Handle) (uint32, error) {
	var returned uint32
	ret, _, err := procEvtNext.Call(
		uintptr(hQuery),
		uintptr(len(eventArray)),
		uintptr(unsafe.Pointer(&eventArray[0])),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 {
		return 0, err
	}
	return returned, nil
}

func evtRender(event syscall.Handle) (string, error) {
	var bufferSize uint32
	procEvtRender.Call(
		uintptr(0),
		uintptr(event),
		EVT_RENDER_EVENT_XML,
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&bufferSize)),
		uintptr(0),
	)
	buffer := make([]uint16, bufferSize/2)
	ret, _, err := procEvtRender.Call(
		uintptr(0),
		uintptr(event),
		EVT_RENDER_EVENT_XML,
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		uintptr(0),
	)
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buffer), nil
}

func evtClose(handle syscall.Handle) error {
	ret, _, err := procEvtClose.Call(uintptr(handle))
	if ret == 0 {
		return err
	}
	return nil
}

func main() {
	logName := "Microsoft-Windows-Windows Defender/Operational"
	eventID := 5007
	query := fmt.Sprintf("*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=%d)]]", eventID)
	pattern := regexp.MustCompile(`HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\[^\s]+`)

	hQuery, err := evtQuery(logName, query)
	if err != nil {
		log.Fatalf("Failed to query event: %v", err)
	}
	defer func(handle syscall.Handle) {
		err := evtClose(handle)
		if err != nil {
			log.Printf("Failed to close event log: %v", err)
		}
	}(hQuery)

	events := make([]syscall.Handle, 10)
	for {
		returned, err := evtNext(hQuery, events)
		if err != nil {
			break
		}
		for i := 0; i < int(returned); i++ {
			event := events[i]
			if event == 0 {
				continue
			}

			messageStr, err := evtRender(event)
			if err != nil {
				log.Printf("Failed to render event: %v", err)
				err := evtClose(event)
				if err != nil {
					log.Printf("Failed to close event: %v", err)
				}
				continue
			}

			if pattern.MatchString(messageStr) {
				match := pattern.FindString(messageStr)
				fmt.Println(match)
			}
			err = evtClose(event)
			if err != nil {
				log.Printf("Failed to close event: %v", err)
			}
		}
	}
}
