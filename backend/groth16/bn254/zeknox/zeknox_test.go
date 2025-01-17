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
		panic(err)
	}
	defer f.Close()
	// wires A
	var lenA uint64
	err = binary.Read(f, binary.LittleEndian, &lenA)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wire A length: %d\n", lenA)
	wireValuesA := make([]fr.Element, lenA)
	err = binary.Read(f, binary.LittleEndian, &wireValuesA)
	if err != nil {
		panic(err)
	}
	// wires B
	var lenB uint64
	err = binary.Read(f, binary.LittleEndian, &lenB)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wire B length: %d\n", lenB)
	wireValuesB := make([]fr.Element, lenB)
	err = binary.Read(f, binary.LittleEndian, &wireValuesB)
	if err != nil {
		panic(err)
	}
	// KRS
	var sizeH uint64
	err = binary.Read(f, binary.LittleEndian, &sizeH)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wire H length: %d\n", sizeH)
	h := make([]fr.Element, sizeH)
	err = binary.Read(f, binary.LittleEndian, &h)
	if err != nil {
		panic(err)
	}
	// pk A and B and Z
	err = binary.Read(f, binary.LittleEndian, &lenA)
	if err != nil {
		panic(err)
	}
	fmt.Printf("G1 A length: %d\n", lenA)
	G1A := make([]curve.G1Affine, lenA)
	err = binary.Read(f, binary.LittleEndian, &G1A)
	if err != nil {
		panic(err)
	}
	err = binary.Read(f, binary.LittleEndian, &lenB)
	if err != nil {
		panic(err)
	}
	fmt.Printf("G1 B length: %d\n", lenB)
	G1B := make([]curve.G1Affine, lenB)
	err = binary.Read(f, binary.LittleEndian, &G1B)
	if err != nil {
		panic(err)
	}
	var lenZ uint64
	err = binary.Read(f, binary.LittleEndian, &lenZ)
	if err != nil {
		panic(err)
	}
	fmt.Printf("G1 Z length: %d\n", lenZ)
	G1Z := make([]curve.G1Affine, lenZ)
	err = binary.Read(f, binary.LittleEndian, &G1Z)
	if err != nil {
		panic(err)
	}

	// Compute on CPU
	n := runtime.NumCPU()
	var bs1_cpu, ar_cpu, krs2_cpu curve.G1Jac
	_, err = bs1_cpu.MultiExp(G1B, wireValuesB, ecc.MultiExpConfig{NbTasks: n / 2})
	if err != nil {
		panic(err)
	}
	_, err = ar_cpu.MultiExp(G1A, wireValuesA, ecc.MultiExpConfig{NbTasks: n / 2})
	if err != nil {
		panic(err)
	}
	_, err = krs2_cpu.MultiExp(G1Z, h[:sizeH], ecc.MultiExpConfig{NbTasks: n / 2})
	if err != nil {
		panic(err)
	}

	// Compute on GPU
	var bs1_gpu, ar_gpu, krs2_gpu curve.G1Jac

	deviceG1A := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	CopyToDevice(G1A, deviceG1A)
	deviceG1B := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	CopyToDevice(G1B, deviceG1B)
	deviceG1Z := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	CopyToDevice(G1Z, deviceG1Z)

	G1DeviceA := DevicePoints[curve.G1Affine]{
		HostOrDeviceSlice: <-deviceG1A,
		Mont:              true,
	}
	G1DeviceB := DevicePoints[curve.G1Affine]{
		HostOrDeviceSlice: <-deviceG1B,
		Mont:              true,
	}
	G1DeviceZ := DevicePoints[curve.G1Affine]{
		HostOrDeviceSlice: <-deviceG1Z,
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

	computeKRS2 := func() error {
		// Copy h poly to device, since we haven't implemented FFT on device
		var deviceH *device.HostOrDeviceSlice[fr.Element]
		chDeviceH := make(chan *device.HostOrDeviceSlice[fr.Element], 1)
		// sizeH := int(pk.Domain.Cardinality - 1) // comes from the fact the deg(H)=(n-1)+(n-1)-n=n-2
		if err := CopyToDevice(h[:sizeH], chDeviceH); err != nil {
			return err
		}
		deviceH = <-chDeviceH
		defer deviceH.Free()
		// MSM G1 Krs2
		if err := gpuMsm(&krs2_gpu, &G1DeviceZ, deviceH); err != nil {
			return err
		}
		return nil
	}

	computeBS1()
	computeAR1()
	computeKRS2()

	fmt.Printf("AR are equal? %v\n", ar_cpu.Equal(&ar_gpu))
	fmt.Printf("BS1 are equal? %v\n", bs1_cpu.Equal(&bs1_gpu))
	fmt.Printf("KRS2 are equal? %v\n", krs2_cpu.Equal(&krs2_gpu))
}

func TestMSM(t *testing.T) {
	// test code
	re_run_msm("dump_20250116061447.bin")
}
