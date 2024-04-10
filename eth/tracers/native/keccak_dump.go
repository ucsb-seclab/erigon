package native

import (
	"encoding/json"

	"github.com/ledgerwatch/erigon-lib/common/hexutility"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/eth/tracers"
)

func init() {
	register("keccak_dump", newKeccakDumpTracer)
}

type keccakAction struct {
	ShaPreimage []byte `json:"sha_preimage"`
	ShaResult   []byte `json:"sha_result"`
}

//go:generate go run github.com/fjl/gencodec -type keccakAction -field-override keccakActionMarshalling -out gen_keccakAction_json.go

type keccakActionMarshalling struct {
	ShaPreimage hexutility.Bytes
	ShaResult   hexutility.Bytes
}

type keccakDumpTracer struct {
	noopTracer
	myError       bool
	grabShaResult bool
	shaPreimage   []byte
	actions       []keccakAction
}

func newKeccakDumpTracer(ctx *tracers.Context, _ json.RawMessage) (tracers.Tracer, error) {
	return &keccakDumpTracer{}, nil
}

func (t *keccakDumpTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if t.myError {
		t.myError = false
		t.grabShaResult = false
		return
	}

	if t.grabShaResult {
		sha_result := scope.Stack.Peek().Bytes()
		sha_preimage := t.shaPreimage

		t.actions = append(t.actions, keccakAction{
			ShaPreimage: sha_preimage,
			ShaResult:   sha_result,
		})

		t.grabShaResult = false

	}

	if op == vm.KECCAK256 {
		offset := scope.Stack.Data[len(scope.Stack.Data)-1]
		size := scope.Stack.Data[len(scope.Stack.Data)-2]

		// only if size is exactly 32 or 64
		if size.ToBig().Int64() == 32 || size.ToBig().Int64() == 64 {
			// We need to grab the preimage from memory.
			preimage := scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
			t.shaPreimage = preimage
			t.grabShaResult = true
		}
	}
}

func (t *keccakDumpTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, _ *vm.ScopeContext, depth int, err error) {
	t.myError = true
}

func (t *keccakDumpTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if err != nil {
		t.myError = true
	}
}

func (t *keccakDumpTracer) GetResult() (json.RawMessage, error) {
	ret, err := json.Marshal(t.actions)
	if err != nil {
		return nil, err
	}

	return json.RawMessage(ret), nil
}
