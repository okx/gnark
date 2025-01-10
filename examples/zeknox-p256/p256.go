package main

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	zeknox_bn254 "github.com/consensys/gnark/backend/groth16/bn254/zeknox"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnark_io "github.com/consensys/gnark/io"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/math/emulated"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/sha3"
)

const NumSignatures = 10

var circuitName string

func init() {
	circuitName = "p256-" + strconv.Itoa(NumSignatures)
}

func compileCircuit(newBuilder frontend.NewBuilder) (constraint.ConstraintSystem, error) {
	circuit := EcdsaCircuit[emulated.P256Fp, emulated.P256Fr]{}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), newBuilder, &circuit)
	if err != nil {
		return nil, err
	}
	return r1cs, nil
}

func generateWitnessCircuit() EcdsaCircuit[emulated.P256Fp, emulated.P256Fr] {
	witness := EcdsaCircuit[emulated.P256Fp, emulated.P256Fr]{}
	perSignatureHashSize := 2*emulated.P256Fp{}.NbLimbs() + emulated.P256Fr{}.NbLimbs()
	hashIn := make([]byte, 0, NumSignatures*perSignatureHashSize)
	for i := 0; i < NumSignatures; i++ {
		// Keygen
		privKey, _ := cryptoecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		publicKey := privKey.PublicKey

		// Sign
		msg, err := genRandomBytes(i + 20)
		if err != nil {
			panic(err)
		}
		msgHash := keccak256(msg)
		sigBin, _ := privKey.Sign(rand.Reader, msgHash[:], nil)

		// Try verify
		var (
			r, s  = &big.Int{}, &big.Int{}
			inner cryptobyte.String
		)
		input := cryptobyte.String(sigBin)
		if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(r) ||
			!inner.ReadASN1Integer(s) ||
			!inner.Empty() {
			log.Panicf("Invalid signature.")
		}
		flag := cryptoecdsa.Verify(&publicKey, msgHash[:], r, s)
		if !flag {
			log.Panicf("Can't verify signature.")
		}

		// hashIn += Pub[i].X + Pub[i].Y + Msg[i]
		pubX := publicKey.X.Bytes()
		pubY := publicKey.Y.Bytes()
		hashIn = append(hashIn, pubX[:]...)
		hashIn = append(hashIn, pubY[:]...)
		hashIn = append(hashIn, msgHash[:]...)

		// Assign to circuit witness
		witness.Sig[i] = Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		}
		witness.Msg[i] = emulated.ValueOf[emulated.P256Fr](msgHash[:])
		witness.Pub[i] = PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](publicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](publicKey.Y),
		}
	}
	hashOut := keccak256(hashIn)
	hashOut[0] = 0 // ignore the first byte, since BN254 order < uint256
	witness.Commitment = hashOut[:]
	return witness
}

func generateWitness() (witness.Witness, error) {
	witness := generateWitnessCircuit()
	witnessData, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	return witnessData, nil
}

func setup(fileDir string) {
	_, err := os.Stat(fileDir)
	if err == nil {
		return
	}

	r1cs, err := compileCircuit(r1cs.NewBuilder)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}
	// Write to file
	if _, err := os.Stat(fileDir); os.IsNotExist(err) {
		err := os.MkdirAll(fileDir, os.ModePerm)
		if err != nil {
			panic(err)
		}
	}
	writeToFile(pk, fileDir+circuitName+".zkey")
	writeToFile(r1cs, fileDir+circuitName+".r1cs")
	writeToFile(vk, fileDir+circuitName+".vkey")
}

func genRandomBytes(size int) ([]byte, error) {
	blk := make([]byte, size)
	_, err := rand.Read(blk)
	if err != nil {
		return nil, err
	}
	return blk, nil
}

func keccak256(data []byte) (digest [32]byte) {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	h.Sum(digest[:0])
	return
}

func writeToFile(data io.WriterTo, fileName string) {
	file, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	_, err = data.WriteTo(file)
	if err != nil {
		panic(err)
	}
}

func readFromFile(data io.ReaderFrom, fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	// Use the ReadFrom method to read the file's content into data.
	if _, err := data.ReadFrom(file); err != nil {
		panic(err)
	}
}

// faster than readFromFile
func unsafeReadFromFile(data gnark_io.UnsafeReaderFrom, fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if _, err := data.UnsafeReadFrom(file); err != nil {
		panic(err)
	}
}

func main() {
	logger.Disable()

	nRuns := flag.Int("r", 5, "number of runs")
	flag.Parse()
	log.Printf("Number of runs: %d", *nRuns)

	// setup if data does not exists
	fileDir := "data/"
	setup(fileDir)

	// read r1cs
	start := time.Now()
	r1cs := groth16.NewCS(ecc.BN254)
	readFromFile(r1cs, fileDir+circuitName+".r1cs")
	elapsed := time.Since(start)
	log.Printf("Read r1cs: %d ms", elapsed.Milliseconds())

	// read zkey
	start = time.Now()
	pk := groth16.NewProvingKey(ecc.BN254)
	if zeknox_bn254.HasZeknox {
		defer pk.(*zeknox_bn254.ProvingKey).Free()
	}
	unsafeReadFromFile(pk, fileDir+circuitName+".zkey")
	elapsed = time.Since(start)
	log.Printf("Read zkey: %d ms", elapsed.Milliseconds())

	// Proof generation & verification
	vk := groth16.NewVerifyingKey(ecc.BN254)
	readFromFile(vk, fileDir+circuitName+".vkey")

	witnessData, err := generateWitness()
	if err != nil {
		panic(err)
	}
	publicWitness, err := witnessData.Public()
	if err != nil {
		panic(err)
	}

	// CPU
	// Warmup
	proof, err := groth16.Prove(r1cs, pk, witnessData, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		panic(err)
	}

	if err := groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
		panic(err)
	}
	// Actual run
	tcpu := float64(0)
	for i := 0; i < *nRuns; i++ {
		start := time.Now()
		proof, err := groth16.Prove(r1cs, pk, witnessData, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
		if err != nil {
			panic(err)
		}
		tcpu += float64(time.Since(start).Milliseconds())
		if err := groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
			panic(err)
		}
	}
	tcpu /= float64(*nRuns)
	log.Printf("CPU prove average time: %v ms", tcpu)

	// GPU
	// Warmup
	proof, err = groth16.Prove(r1cs, pk, witnessData, solidity.WithProverTargetSolidityVerifier(backend.GROTH16), backend.WithZeknoxAcceleration())
	if err != nil {
		panic(err)
	}
	if err := groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
		log.Panicf("\nError in GPU Verify %d: %s\n\n", 0, err)
	}
	// Actual run
	tgpu := float64(0)
	for i := 0; i < *nRuns; i++ {
		start := time.Now()
		proof, err := groth16.Prove(r1cs, pk, witnessData, solidity.WithProverTargetSolidityVerifier(backend.GROTH16), backend.WithZeknoxAcceleration())
		if err != nil {
			panic(err)
		}
		tgpu += float64(time.Since(start).Milliseconds())
		if err := groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
			log.Panicf("\nError in GPU Verify %d: %s\n\n", i+1, err)
		}
	}
	tgpu /= float64(*nRuns)
	log.Printf("zeknox GPU prove average time: %v ms", tgpu)
	log.Printf("Speedup: %f", tcpu/tgpu)
}
