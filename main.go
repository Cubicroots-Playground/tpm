package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/ssh"
)

var eccSigTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		CurveID: tpm2.TPMECCNistP256,
		Scheme: tpm2.TPMTECCScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
	}),
}

func main() {
	// Open TPM.
	tpm, err := linuxtpm.Open(`/dev/tpmrm0`)
	if err != nil {
		panic(err)
	}
	defer tpm.Close()

	// Create SRK, the parent key. It is deterministic, no need to persist it.
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		panic(err)
	}
	defer tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(tpm)

	// Make handle from SRK.
	parent := tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name}

	// Create SSH key.
	pk, err := tpm2.Create{
		ParentHandle: parent,
		InPublic:     tpm2.New2B(eccSigTemplate),
	}.Execute(tpm)
	if err != nil {
		panic(err)
	}

	// Convert the TPM public key to an SSH public key.
	pub, _ := pk.OutPublic.Contents()
	pt, _ := pub.Unique.ECC()
	ecPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pt.X.Buffer),
		Y:     new(big.Int).SetBytes(pt.Y.Buffer),
	}
	sshPub, _ := ssh.NewPublicKey(ecPub)
	fmt.Print(string(ssh.MarshalAuthorizedKey(sshPub)))
}
