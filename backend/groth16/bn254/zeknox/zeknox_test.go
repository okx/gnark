//go:build zeknox

package zeknox_bn254

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/okx/zeknox/wrappers/go/device"
)

func re_run_msm(filename string) {
	// read data from file
	f, err := os.Open(filename)
	if err != nil {
		fmt.Errorf("Couldn't open file")
	}
	defer f.Close()
	// wires A
	var lenA uint64
	err = binary.Read(f, binary.LittleEndian, &lenA)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	fmt.Printf("Wire A length: %d\n", lenA)
	wireValuesA := make([]fr.Element, lenA)
	err = binary.Read(f, binary.LittleEndian, &wireValuesA)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	// wires B
	var lenB uint64
	err = binary.Read(f, binary.LittleEndian, &lenB)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	fmt.Printf("Wire B length: %d\n", lenB)
	wireValuesB := make([]fr.Element, lenB)
	err = binary.Read(f, binary.LittleEndian, &wireValuesB)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	// pk A and B
	err = binary.Read(f, binary.LittleEndian, &lenA)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	fmt.Printf("G1 A length: %d\n", lenA)
	G1A := make([]curve.G1Affine, lenA)
	err = binary.Read(f, binary.LittleEndian, &G1A)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	err = binary.Read(f, binary.LittleEndian, &lenB)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	fmt.Printf("G1 B length: %d\n", lenB)
	G1B := make([]curve.G1Affine, lenB)
	err = binary.Read(f, binary.LittleEndian, &G1B)
	if err != nil {
		fmt.Errorf("Read failed %v\n", err)
	}
	// Compute on CPU
	n := runtime.NumCPU()
	var bs1_cpu, ar_cpu curve.G1Jac
	_, err = bs1_cpu.MultiExp(G1B, wireValuesB, ecc.MultiExpConfig{NbTasks: n / 2})
	if err != nil {
		fmt.Errorf("BS1 CPU MultiExp failed")
	}
	_, err = ar_cpu.MultiExp(G1A, wireValuesA, ecc.MultiExpConfig{NbTasks: n / 2})
	if err != nil {
		fmt.Errorf("AR CPU MultiExp failed")
	}

	// Compute on GPU
	var bs1_gpu, ar_gpu curve.G1Jac

	deviceA := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	CopyToDevice(G1A, deviceA)
	deviceG1B := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	CopyToDevice(G1B, deviceG1B)

	G1DeviceA := DevicePoints[curve.G1Affine]{
		HostOrDeviceSlice: <-deviceA,
		Mont:              true,
	}
	G1DeviceB := DevicePoints[curve.G1Affine]{
		HostOrDeviceSlice: <-deviceG1B,
		Mont:              true,
	}

	computeBS1 := func() error {
		var wireB *device.HostOrDeviceSlice[fr.Element]
		chWireB := make(chan *device.HostOrDeviceSlice[fr.Element], 1)
		if err := CopyToDevice(wireValuesB, chWireB); err != nil {
			return err
		}
		wireB = <-chWireB
		defer wireB.Free()
		if err := gpuMsm(&bs1_gpu, &G1DeviceB, wireB); err != nil {
			return err
		}
		return nil
	}
	computeAR1 := func() error {
		var wireA *device.HostOrDeviceSlice[fr.Element]
		chWireA := make(chan *device.HostOrDeviceSlice[fr.Element], 1)
		if err := CopyToDevice(wireValuesA, chWireA); err != nil {
			return err
		}
		wireA = <-chWireA
		defer wireA.Free()
		if err := gpuMsm(&ar_gpu, &G1DeviceA, wireA); err != nil {
			return err
		}
		return nil
	}

	computeBS1()
	computeAR1()

	fmt.Printf("AR are equal? %v\n", ar_cpu.Equal(&ar_gpu))
	fmt.Printf("BS1 are equal? %v\n", bs1_cpu.Equal(&bs1_gpu))
}

func TestMSM(t *testing.T) {
	// test code
	re_run_msm("dump_20250116105350.bin")
}
