// main.go

package main

import (
	"flag"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test/unsafekzg"
	cryptosha3 "golang.org/x/crypto/sha3"
)

type sha3Circuit struct {
	In       []uints.U8   `gnark:",secret"`
	Expected [32]uints.U8 `gnark:",public"`
}

func (c *sha3Circuit) Define(api frontend.API) error {
	h, err := sha3.New256(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	h.Write(c.In)
	res := h.Sum()

	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

const inputLength = 128

func compileCircuit() (constraint.ConstraintSystem, error) {
	circuit := sha3Circuit{
		In: make([]uints.U8, inputLength),
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		return nil, err
	}
	return r1cs, nil
}

func generateWitness() (witness.Witness, error) {
	input := make([]byte, inputLength)
	dgst := cryptosha3.Sum256(input)
	witness := sha3Circuit{
		In: uints.NewU8Array(input[:]),
	}
	copy(witness.Expected[:], uints.NewU8Array(dgst[:]))

	witnessData, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	return witnessData, nil
}

func main() {
	// logger.Disable()
	/*
		f, err := os.Create("cpu.prof")
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	*/

	nRuns := flag.Int("r", 5, "number of runs")
	flag.Parse()
	log.Printf("Number of runs: %d", *nRuns)

	r1cs, err := compileCircuit()
	if err != nil {
		panic(err)
	}

	// This is a toy example: taken from ../plonk/main.go
	scs := r1cs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	pk, vk, err := plonk.Setup(r1cs, srs, srsLagrange)
	if err != nil {
		log.Fatal(err)
	}

	// Witness generation
	witnessData, err := generateWitness()
	if err != nil {
		panic(err)
	}
	publicWitness, err := witnessData.Public()
	if err != nil {
		panic(err)
	}

	/*
		// GPU Prove & Verify
		// Warmup GPU
		proofZeknox, err := plonk.Prove(r1cs, pk, witnessData, backend.WithZeknoxAcceleration())
		if err != nil {
			panic(err)
		}
		if err := plonk.Verify(proofZeknox, vk, publicWitness); err != nil {
			panic(err)
		}
		// Actual run
		tgpu := float64(0)
		for i := 0; i < *nRuns; i++ {
			start := time.Now()
			proofZeknox, err = plonk.Prove(r1cs, pk, witnessData, backend.WithZeknoxAcceleration())
			if err != nil {
				panic(err)
			}
			tgpu += float64(time.Since(start).Milliseconds())
			if err := plonk.Verify(proofZeknox, vk, publicWitness); err != nil {
				panic(err)
			}
		}
		tgpu /= float64(*nRuns)
		log.Printf("zeknox GPU prove average time: %v ms", tgpu)
	*/

	// CPU Prove & Verify
	// Warmup CPU
	proof, err := plonk.Prove(r1cs, pk, witnessData)
	if err != nil {
		panic(err)
	}
	if err := plonk.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}
	// Actual run
	tcpu := float64(0)
	for i := 0; i < *nRuns; i++ {
		start := time.Now()
		proof, err = plonk.Prove(r1cs, pk, witnessData)
		if err != nil {
			panic(err)
		}
		tcpu += float64(time.Since(start).Milliseconds())
		if err := plonk.Verify(proof, vk, publicWitness); err != nil {
			panic(err)
		}
	}
	tcpu /= float64(*nRuns)
	log.Printf("CPU prove average time: %v ms", tcpu)

	// log.Printf("Speedup: %f", tcpu/tgpu)
}
