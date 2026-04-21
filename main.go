//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

// Layout matches SMCKit.SMCParamStruct (Swift); verified stride 80.
typedef struct {
	uint32_t key;
	uint8_t vers_major;
	uint8_t vers_minor;
	uint8_t vers_build;
	uint8_t vers_reserved;
	uint16_t vers_release;
	uint8_t pad_vers[2];
	uint16_t pLimit_version;
	uint16_t pLimit_length;
	uint32_t pLimit_cpu;
	uint32_t pLimit_gpu;
	uint32_t pLimit_mem;
	uint32_t keyInfo_data_size;
	uint32_t keyInfo_data_type;
	uint8_t keyInfo_data_attributes;
	uint8_t pad_keyInfo;
	uint16_t padding_field;
	uint8_t result;
	uint8_t status;
	uint8_t data8;
	uint8_t pad_before_data32;
	uint32_t data32;
	uint8_t bytes[32];
} smc_param_t;

_Static_assert(sizeof(smc_param_t) == 80, "smc_param_t size");
_Static_assert(offsetof(smc_param_t, key) == 0, "key");
_Static_assert(offsetof(smc_param_t, result) == 40, "result");
_Static_assert(offsetof(smc_param_t, data32) == 44, "data32");
_Static_assert(offsetof(smc_param_t, bytes) == 48, "bytes");

enum {
	SMC_KERNEL_INDEX = 2,
	SMC_READ_BYTES   = 5,
	SMC_WRITE_BYTES  = 6,
	SMC_READ_KEYINFO = 9,
};

typedef struct {
	io_connect_t conn;
} smc_client_t;

static kern_return_t smc_open(smc_client_t *client) {
	io_iterator_t iter = 0;
	kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AppleSMC"), &iter);
	if (kr != KERN_SUCCESS || iter == 0) {
		if (iter) IOObjectRelease(iter);
		return kr != KERN_SUCCESS ? kr : KERN_FAILURE;
	}
	io_service_t service = IOIteratorNext(iter);
	IOObjectRelease(iter);
	if (!service) {
		return KERN_FAILURE;
	}
	kr = IOServiceOpen(service, mach_task_self(), 0, &client->conn);
	IOObjectRelease(service);
	return kr;
}

static void smc_close(smc_client_t *client) {
	if (client->conn) {
		IOServiceClose(client->conn);
		client->conn = MACH_PORT_NULL;
	}
}

static kern_return_t smc_call(smc_client_t *client, const smc_param_t *in, smc_param_t *out) {
	size_t outSize = sizeof(smc_param_t);
	memset(out, 0, sizeof(*out));
	return IOConnectCallStructMethod(
		client->conn,
		SMC_KERNEL_INDEX,
		in,
		sizeof(smc_param_t),
		out,
		&outSize
	);
}

static void smc_param_zero(smc_param_t *p) {
	memset(p, 0, sizeof(*p));
}

static void smc_set_bytes(smc_param_t *p, const uint8_t *src, size_t n) {
	if (n > sizeof(p->bytes)) n = sizeof(p->bytes);
	memcpy(p->bytes, src, n);
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"
	"unsafe"
)

const smcResultSuccess = 0x00

type SMC struct {
	c C.smc_client_t
	// "F%dmd" or "F%dMd"
	modeFormat  string
	ftstPresent bool
}

func Open() (*SMC, error) {
	s := &SMC{}
	if kr := C.smc_open(&s.c); kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("open AppleSMC: 0x%x", uint32(kr))
	}
	mode, ftst, err := s.probeHardware()
	if err != nil {
		C.smc_close(&s.c)
		return nil, err
	}
	s.modeFormat = mode
	s.ftstPresent = ftst
	return s, nil
}

func (s *SMC) Close() {
	C.smc_close(&s.c)
}

func fourCharCode(key string) (C.uint32_t, error) {
	if len(key) != 4 {
		return 0, fmt.Errorf("SMC key %q must be exactly 4 characters", key)
	}
	var k uint32
	for _, b := range []byte(key) {
		k = (k << 8) | uint32(b)
	}
	return C.uint32_t(k), nil
}

func fanKey(template string, fan int) (string, error) {
	formatted := fmt.Sprintf(template, fan)
	if len(formatted) != 4 {
		return "", fmt.Errorf("formatted key %q must be 4 characters (fan index too large?)", formatted)
	}
	return formatted, nil
}

func (s *SMC) callSMC(in *C.smc_param_t) (C.smc_param_t, error) {
	var out C.smc_param_t
	kr := C.smc_call(&s.c, in, &out)
	if kr != C.KERN_SUCCESS {
		return out, fmt.Errorf("IOConnectCallStructMethod: 0x%x", uint32(kr))
	}
	return out, nil
}

func (s *SMC) fetchKeyInfo(key string) (C.smc_param_t, error) {
	kc, err := fourCharCode(key)
	if err != nil {
		return C.smc_param_t{}, err
	}
	var in C.smc_param_t
	C.smc_param_zero(&in)
	in.key = kc
	in.data8 = C.SMC_READ_KEYINFO
	out, err := s.callSMC(&in)
	if err != nil {
		return C.smc_param_t{}, err
	}
	if out.result != smcResultSuccess {
		return out, fmt.Errorf("SMC readKeyInfo %s: firmware 0x%x", key, uint8(out.result))
	}
	return out, nil
}

func (s *SMC) readKey(key string) ([]byte, uint32, error) {
	info, err := s.fetchKeyInfo(key)
	if err != nil {
		return nil, 0, err
	}
	dataSize := uint32(info.keyInfo_data_size)
	if dataSize == 0 || dataSize > 32 {
		return nil, 0, fmt.Errorf("SMC key %s: unexpected data size %d", key, dataSize)
	}

	var in C.smc_param_t
	C.smc_param_zero(&in)
	kc, err := fourCharCode(key)
	if err != nil {
		return nil, 0, err
	}
	in.key = kc
	in.data8 = C.SMC_READ_BYTES
	in.keyInfo_data_size = C.uint32_t(dataSize)

	out, err := s.callSMC(&in)
	if err != nil {
		return nil, 0, err
	}
	buf := C.GoBytes(unsafe.Pointer(&out.bytes[0]), C.int(dataSize))
	return buf, dataSize, nil
}

func (s *SMC) writeKey(key string, bytes []byte) error {
	info, err := s.fetchKeyInfo(key)
	if err != nil {
		return err
	}
	dataSize := uint32(info.keyInfo_data_size)
	if len(bytes) != int(dataSize) {
		return fmt.Errorf("SMC write %s: got %d bytes, SMC expects %d", key, len(bytes), dataSize)
	}

	var in C.smc_param_t
	C.smc_param_zero(&in)
	kc, err := fourCharCode(key)
	if err != nil {
		return err
	}
	in.key = kc
	in.data8 = C.SMC_WRITE_BYTES
	in.keyInfo_data_size = C.uint32_t(dataSize)
	C.smc_set_bytes(&in, (*C.uint8_t)(unsafe.Pointer(&bytes[0])), C.size_t(len(bytes)))

	out, err := s.callSMC(&in)
	if err != nil {
		return err
	}
	if out.result != smcResultSuccess {
		// 0x87 on F0Tg
		if len(key) == 4 && key[2] == 'T' && key[3] == 'g' && out.result == 0x87 {
			return nil
		}
		return fmt.Errorf("SMC write %s: firmware 0x%x", key, uint8(out.result))
	}
	return nil
}

func (s *SMC) probeHardware() (modeFormat string, ftst bool, err error) {
	var mode string
	for _, cand := range []struct {
		key, format string
	}{
		{"F0md", "F%dmd"},
		{"F0Md", "F%dMd"},
	} {
		if _, _, e := s.readKey(cand.key); e == nil {
			mode = cand.format
			break
		}
	}
	if mode == "" {
		return "", false, errors.New("could not read fan mode key F0md or F0Md")
	}
	if _, _, e := s.readKey("Ftst"); e == nil {
		ftst = true
	}
	return mode, ftst, nil
}

func floatBytesAppleSilicon(rpm float32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, math.Float32bits(rpm))
	return b
}

func (s *SMC) enableManualMode(fanIndex int) error {
	modeKey, err := fanKey(s.modeFormat, fanIndex)
	if err != nil {
		return err
	}
	if err := s.writeKey(modeKey, []byte{1}); err == nil {
		return nil
	}
	directErr := err
	if !s.ftstPresent {
		return directErr
	}
	if err := s.writeKey("Ftst", []byte{1}); err != nil {
		return fmt.Errorf("Ftst=1: %w (after direct mode error: %v)", err, directErr)
	}
	time.Sleep(500 * time.Millisecond)

	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < 100 && time.Now().Before(deadline); i++ {
		if err := s.writeKey(modeKey, []byte{1}); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("Ftst unlock: could not set manual mode within timeout")
}

func (s *SMC) FanCount() (int, error) {
	b, _, err := s.readKey("FNum")
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, errors.New("empty FNum")
	}
	return int(b[0]), nil
}

func (s *SMC) SetFanRPM(fanIndex int, rpm float32) error {
	if fanIndex < 0 {
		return errors.New("invalid fan index")
	}
	if rpm < 0 {
		return errors.New("invalid rpm")
	}

	modeKey, err := fanKey(s.modeFormat, fanIndex)
	if err != nil {
		return err
	}
	manual := false
	if modeBytes, _, e := s.readKey(modeKey); e == nil && len(modeBytes) > 0 && modeBytes[0] == 1 {
		manual = true
	}
	if !manual {
		if err := s.enableManualMode(fanIndex); err != nil {
			return fmt.Errorf("enable manual: %w", err)
		}
	}

	targetKey, err := fanKey("F%dTg", fanIndex)
	if err != nil {
		return err
	}
	return s.writeKey(targetKey, floatBytesAppleSilicon(rpm))
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This program must run as root to talk to AppleSMC.")
		os.Exit(1)
	}

	rpm := float32(2000)
	if len(os.Args) >= 2 {
		v, err := strconv.ParseFloat(os.Args[1], 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "usage: %s [rpm]\n", os.Args[0])
			os.Exit(1)
		}
		rpm = float32(v)
		if rpm < 0 {
			rpm = 0
			fmt.Fprintf(os.Stderr, "rpm is too low, clamping to 0\n")
		}
		if rpm > 5200 {
			rpm = 5200
			fmt.Fprintf(os.Stderr, "rpm is too high, clamping to 5200\n")
		}
	}

	smc, err := Open()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer smc.Close()

	n, err := smc.FanCount()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i := 0; i < n; i++ {
		if err := smc.SetFanRPM(i, rpm); err != nil {
			fmt.Fprintf(os.Stderr, "fan %d: %v\n", i, err)
			os.Exit(1)
		}
	}
	fmt.Printf("Set %d fan(s) to %.0f RPM.\n", n, rpm)
}
