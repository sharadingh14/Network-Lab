// OPTIONAL PORT TO HYPERLEDGER FABRIC (v2.5). NOT EXECUTED IN THE STUDY.
//
// The results reported in the paper were produced with the Python ledger in hbids/ledger.
// This chaincode shows how the same signature transaction and validation rule map onto Fabric:
//   * each organisation (IDS site) is an endorsing peer;
//   * a peer endorses SubmitSignature only if the signature matches no more than the configured
//     fraction of that organisation's benign reference keys, held in its implicit private data
//     collection (raw traffic never leaves the organisation);
//   * the channel endorsement policy should be MAJORITY Endorsement (or an explicit 2f+1-of-n rule),
//     which plays the role of the 2f+1 endorsement quorum in hbids/ledger/node.py.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type Signature struct {
	SigID   string  `json:"sig_id"`
	Key     []int64 `json:"key"`
	Fields  []string `json:"fields"`
	Support int     `json:"support"`
	Origin  string  `json:"origin"`
	Created float64 `json:"created"`
}

type BenignSummary struct {
	Counts map[string]int `json:"counts"` // key hash (decimal string) -> number of benign flows
	Total  int            `json:"total"`
}

type SignatureContract struct {
	contractapi.Contract
}

const minSupport = 20
const tolerance = 0.0005

func keyHash(k []int64) string {
	var h int64 = 0
	for _, v := range k {
		h = h*1000003 + v + 7919 // identical to hbids.signatures.key_hash (wrapping int64 arithmetic)
	}
	return fmt.Sprintf("%d", h)
}

// SubmitSignature is executed by every endorsing peer; it fails (no endorsement) if the
// signature is under-supported or matches too much of this peer's benign reference traffic.
func (c *SignatureContract) SubmitSignature(ctx contractapi.TransactionContextInterface, sigJSON string) error {
	var s Signature
	if err := json.Unmarshal([]byte(sigJSON), &s); err != nil {
		return err
	}
	if s.Support < minSupport {
		return fmt.Errorf("support %d below minimum", s.Support)
	}
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return err
	}
	_ = mspID
	peerMSP, err := ctx.GetStub().GetMSPID()
	if err != nil {
		return err
	}
	raw, err := ctx.GetStub().GetPrivateData("_implicit_org_"+peerMSP, "benign_summary")
	if err != nil || raw == nil {
		return fmt.Errorf("benign reference unavailable on this peer")
	}
	var b BenignSummary
	if err := json.Unmarshal(raw, &b); err != nil {
		return err
	}
	if b.Total > 0 && float64(b.Counts[keyHash(s.Key)])/float64(b.Total) > tolerance {
		return fmt.Errorf("signature matches benign traffic of %s", peerMSP)
	}
	return ctx.GetStub().PutState("sig_"+s.SigID, []byte(sigJSON))
}

// LoadBenignSummary stores this organisation's benign key counts in its implicit private collection.
func (c *SignatureContract) LoadBenignSummary(ctx contractapi.TransactionContextInterface) error {
	t, err := ctx.GetStub().GetTransient()
	if err != nil {
		return err
	}
	peerMSP, _ := ctx.GetStub().GetMSPID()
	return ctx.GetStub().PutPrivateData("_implicit_org_"+peerMSP, "benign_summary", t["benign_summary"])
}

func (c *SignatureContract) GetAllSignatures(ctx contractapi.TransactionContextInterface) ([]*Signature, error) {
	it, err := ctx.GetStub().GetStateByRange("sig_", "sig_~")
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []*Signature
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		var s Signature
		if json.Unmarshal(kv.Value, &s) == nil {
			out = append(out, &s)
		}
	}
	return out, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&SignatureContract{})
	if err != nil {
		panic(err)
	}
	if err := cc.Start(); err != nil {
		panic(err)
	}
}
