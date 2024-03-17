// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync/atomic"

	"github.com/holiman/uint256"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/hexutil"
	"github.com/ledgerwatch/erigon-lib/common/hexutility"

	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/eth/tracers"
)

type houstonConfiguration struct {
	SVMap map[libcommon.Address][]libcommon.Hash `json:"sv_map"`
}

type houstonConfigurationJSON struct {
	SVMap map[string][]string `json:"sv_map"`
}

// Caches the houstonConfiguration for each file name.
var cachedHoustonConfigurations = make(map[string]*houstonConfiguration)

func getHoustonConfiguration(fileName string) (*houstonConfiguration, error) {
	if config, ok := cachedHoustonConfigurations[fileName]; ok {
		return config, nil
	}

	// Read the file
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Decode the JSON
	decoder := json.NewDecoder(file)
	var jsonConfig houstonConfigurationJSON
	err = decoder.Decode(&jsonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	// Convert the JSON to the houstonConfiguration
	config := houstonConfiguration{SVMap: make(map[libcommon.Address][]libcommon.Hash)}
	for address, hashes := range jsonConfig.SVMap {
		// Convert the address
		convertedAddress := libcommon.HexToAddress(address)
		config.SVMap[convertedAddress] = make([]libcommon.Hash, len(hashes))
		for i, hash := range hashes {
			// Convert the hash
			bigHash := new(big.Int).SetBytes(hexutility.FromHex(hash))
			config.SVMap[convertedAddress][i] = libcommon.BigToHash(bigHash)
		}
	}

	for address, _ := range config.SVMap {
		fmt.Printf("Address: %v\n", address)
	}

	// Cache the configuration
	cachedHoustonConfigurations[fileName] = &config

	return &config, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

//go:generate go run github.com/fjl/gencodec -type houstonCallFrame -field-override houstonCallFrameMarshaling -out gen_houstonCallFrame_json.go

type houstonCallLog struct {
	Index   uint64            `json:"index"`
	Address libcommon.Address `json:"address"`
	Topics  []libcommon.Hash  `json:"topics"`
	Data    hexutility.Bytes  `json:"data"`
}

type SV struct {
	Slot  *big.Int `json:"slot"`
	Value *big.Int `json:"value"`
}

//go:generate go run github.com/fjl/gencodec -type SV -field-override SVmarshalling -out gen_houstonSV_json.go

type SVmarshalling struct {
	Slot  *hexutil.Big
	Value *hexutil.Big
}

type houstonCallFrame struct {
	Id       uint64             `json:"id"`
	EventId  uint64             `json:"event_id"`
	Type     vm.OpCode          `json:"-"`
	From     libcommon.Address  `json:"from"`
	Gas      uint64             `json:"gas"`
	GasUsed  uint64             `json:"gasUsed"`
	To       libcommon.Address  `json:"to" rlp:"optional"`
	Input    []byte             `json:"input" rlp:"optional"`
	Error    string             `json:"error,omitempty" rlp:"optional"`
	Revertal string             `json:"revertReason,omitempty"`
	Calls    []houstonCallFrame `json:"calls" rlp:"optional"`
	Logs     []houstonCallLog   `json:"logs,omitempty" rlp:"optional"`
	Pc       uint64             `json:"pc,omitempty" rlp:"optional"`
	SvsEntry []SV               `json:"svs_entry" rlp:"optional"`
	SvsExit  []SV               `json:"svs_exit" rlp:"optional"`
	// Placed at end on purpose. The RLP will be decoded to 0 instead of
	// nil if there are non-empty elements after in the struct.
	Value *big.Int `json:"value,omitempty" rlp:"optional"`
	StorageAddress libcommon.Address `json:"storage_address"`
}

func (f houstonCallFrame) TypeString() string {
	return f.Type.String()
}

func (f *houstonCallFrame) processOutput(output []byte, err error) {
	output = libcommon.CopyBytes(output)
	if err == nil {
		return
	}
	f.Error = err.Error()
	
	// Updating CREATE/CREATE2 "to" address
	if f.Type == vm.CREATE || f.Type == vm.CREATE2 {
		f.To = libcommon.Address{}
	}
	if !errors.Is(err, vm.ErrExecutionReverted) || len(output) == 0 {
		return
	}

	if len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		f.Revertal = unpacked
	}
}

type houstonCallFrameMarshaling struct {
	TypeString string `json:"type"`
	Gas        hexutil.Uint64
	GasUsed    hexutil.Uint64
	Value      *hexutil.Big
	Input      hexutility.Bytes
}

type houstonCallTracer struct {
	noopTracer
	nextCallId            uint64
	callstack             []houstonCallFrame
	config                *houstonConfiguration
	gasLimit              uint64
	interrupt             uint32 // Atomic flag to signal execution interruption
	reason                error  // Textual reason for the interruption
	logIndex              uint64
	logGaps               map[uint64]int
	lastPc                uint64
	lastCallWasPrecompile bool
	env                   *vm.EVM
	nextEventId           uint64
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *houstonCallTracer) CaptureStart(env *vm.EVM, from libcommon.Address, to libcommon.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {

	t.callstack[0] = houstonCallFrame{
		Type:    vm.CALL,
		From:    from,
		To:      to,
		Input:   libcommon.CopyBytes(input),
		Gas:     t.gasLimit, // gas has intrinsicGas already subtracted
		Pc:      0,
		Value:   value.ToBig(),
		EventId: 0,
		StorageAddress: to,
	}
	if value != nil {
		t.callstack[0].Value = value.ToBig()
	}
	if create {
		t.callstack[0].Type = vm.CREATE
	}
	t.nextCallId = 1
	t.nextEventId = 1

	// if it was not a transaction that created a contract
	if !create{

		// if this is in the sv_map, dump its storage
		if l, ok := t.config.SVMap[to]; ok {
			// get the storage
			storage := make([]SV, 0)
			for _, s := range l {
				var value uint256.Int
				env.IntraBlockState().GetState(to, &s, &value)
				storage = append(storage, SV{
					Slot:  s.Big(),
					Value: value.ToBig(),
				})
			}
			t.callstack[0].SvsEntry = storage
		}
	}

	t.env = env
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *houstonCallTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {

    call := t.callstack[0]

	if call.Type != vm.CREATE {

		if l, ok := t.config.SVMap[call.To]; ok {
			// get the storage
			storage := make([]SV, 0)
			for _, s := range l {
				var value uint256.Int
				t.env.IntraBlockState().GetState(call.To, &s, &value)
				storage = append(storage, SV{
					Slot:  s.Big(),
					Value: value.ToBig(),
				})
			}
			t.callstack[0].SvsExit = storage
		}
	}

    t.callstack[0].processOutput(output, err)
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *houstonCallTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	t.lastPc = pc
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *houstonCallTracer) CaptureEnter(typ vm.OpCode, from libcommon.Address, to libcommon.Address, precompile, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		return
	}

	if precompile {
		t.lastCallWasPrecompile = true
		return
	}

	id := t.nextCallId
	t.nextCallId++
	eventId := t.nextEventId
	t.nextEventId++

	if len(t.callstack) > 1 {
		from = t.callstack[len(t.callstack)-1].To
	}

	call := houstonCallFrame{
		Id:      id,
		EventId: eventId,
		Type:    typ,
		From:    from,
		To:      to,
		Input:   libcommon.CopyBytes(input),
		Gas:     gas,
		Pc:      t.lastPc,
	}
	if value != nil {
		call.Value = value.ToBig()
	}
	t.callstack = append(t.callstack, call)

	// We delay the definition of svs_entry to the CaptureState (we need to know the storage address)
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *houstonCallTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if t.lastCallWasPrecompile {
		t.lastCallWasPrecompile = false
		return
	}

	size := len(t.callstack)
	if size <= 1 {
		return
	}
	// pop call
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size -= 1

	call.GasUsed = gasUsed
	call.processOutput(output, err)
	
	ref_addr := call.StorageAddress

	if l, ok := t.config.SVMap[ref_addr]; ok {
		// get the storage
		storage := make([]SV, 0)
		for _, s := range l {
			var value uint256.Int
			t.env.IntraBlockState().GetState(ref_addr, &s, &value)
			storage = append(storage, SV{
				Slot:  s.Big(),
				Value: value.ToBig(),
			})
		}
		call.SvsExit = storage
	}

	t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
}

func (t *houstonCallTracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
	t.logIndex = 0
	t.logGaps = make(map[uint64]int)
}

func (t *houstonCallTracer) CaptureTxEnd(restGas uint64) {
	t.callstack[0].GasUsed = t.gasLimit - restGas
	t.logIndex = 0
	t.logGaps = nil
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *houstonCallTracer) GetResult() (json.RawMessage, error) {
	if len(t.callstack) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}
	res, err := json.Marshal(t.callstack[0])
	if err != nil {
		return nil, err
	}
	return json.RawMessage(res), t.reason
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *houstonCallTracer) Stop(err error) {
	t.reason = err
	atomic.StoreUint32(&t.interrupt, 1)
}

func init() {
	register("houston", newHoustonTracer)
}

type ShaAction struct {
	EventId        uint64            `json:"event_id"`
	ShaPreimage    []byte            `json:"sha_preimage"`
	Result         []byte            `json:"result"`
	CallId         uint64            `json:"call_id"`
	Pc             uint64            `json:"pc"`
	Address        libcommon.Address `json:"address"`
	StorageAddress libcommon.Address `json:"storage_address"`
}

//go:generate go run github.com/fjl/gencodec -type ShaAction -field-override ShaActionMarshalling -out gen_houstonShaAction_json.go

type ShaActionMarshalling struct {
	EventId        uint64
	ShaPreimage    hexutility.Bytes
	Result         hexutility.Bytes
	CallId         uint64
	Pc             hexutil.Uint64
	Address        libcommon.Address
	StorageAddress libcommon.Address
}

type SstoreAction struct {
	EventId        uint64            `json:"event_id"`
	Key            *big.Int          `json:"key"`
	Value          *big.Int          `json:"value"`
	OldValue       *big.Int          `json:"old_value"`
	Pc             uint64            `json:"pc"`
	Address        libcommon.Address `json:"address"`
	StorageAddress libcommon.Address `json:"storage_address"`
	Depth          int               `json:"depth"`
	CallId         uint64            `json:"call_id"`
	FID            []byte            `json:"fid"`
}

//go:generate go run github.com/fjl/gencodec -type SstoreAction -field-override SstoreActionMarshalling -out gen_houstonSstoreAction_json.go

type SstoreActionMarshalling struct {
	EventId        uint64
	Key            *hexutil.Big
	Value          *hexutil.Big
	OldValue       *hexutil.Big
	Pc             hexutil.Uint64
	Address        libcommon.Address
	StorageAddress libcommon.Address
	Depth          int
	CallId         uint64
	FID            hexutility.Bytes
}

type HoustonResult struct {
	CallTracerResult json.RawMessage `json:"call_tracer_result"`
	ShaActions       []ShaAction     `json:"sha_actions"`
	SstoreActions    []SstoreAction  `json:"sstore_actions"`
}

type houstonTracer struct {
	env                 *vm.EVM
	myhoustonCallTracer houstonCallTracer
	grabShaResult       bool
	shaPreimage         []byte
	foundCall           bool
	myError             bool
	shaActions          []ShaAction
	sstoreActions       []SstoreAction
}

type houstonTracerConfig struct {
	FileName string `json:"config_file_name"`
}

func newHoustonTracer(ctx *tracers.Context, cfg json.RawMessage) (tracers.Tracer, error) {
	var config houstonTracerConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}

	houstonConfig, err := getHoustonConfiguration(config.FileName)
	if err != nil {
		return nil, err
	}

	// First houstonCallFrame contains tx context info
	// and is populated on start and end.
	ct := houstonCallTracer{callstack: make([]houstonCallFrame, 1), config: houstonConfig}

	ret := &houstonTracer{myhoustonCallTracer: ct}

	return ret, nil
}

func (t *houstonTracer) CaptureStart(env *vm.EVM, from libcommon.Address, to libcommon.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	t.myhoustonCallTracer.CaptureStart(env, from, to, precompile, create, input, gas, value, code)
	t.env = env
	t.grabShaResult = false
	t.foundCall = false
}

func (t *houstonTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	t.myhoustonCallTracer.CaptureEnd(output, gasUsed, err)
}

func (t *houstonTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	t.myhoustonCallTracer.CaptureState(pc, op, gas, cost, scope, rData, depth, err)

	if t.myError {
		// do nothing; we just hit a fault (out of gas, etc) so control flow just got whacky
		t.myError = false
		t.grabShaResult = false
		return
	}

	if t.foundCall {
		
		t.foundCall = false
		
		// We'll stick the storageAddress to the currentCall in the callstack
		currentCall := t.myhoustonCallTracer.callstack[len(t.myhoustonCallTracer.callstack)-1]
		currentCall.StorageAddress = scope.Contract.Address()

		if op == vm.CREATE || op == vm.CREATE2 {
			currentCall.To = currentCall.StorageAddress
			return
		}
		
		// Now that we know what is the reference address for the variables
		// we can add them in the svs_enter
		if l, ok := t.config.SVMap[currentCall.StorageAddress]; ok {
			// get the storage
			storage := make([]SV, 0)
			for _, s := range l {
				var value uint256.Int
				t.env.IntraBlockState().GetState(currentCall.StorageAddress, &s, &value)
				storage = append(storage, SV{
					Slot:  s.Big(),
					Value: value.ToBig(),
				})
			}
			t.myhoustonCallTracer.callstack[len(t.myhoustonCallTracer.callstack)-1].SvsEntry = storage
		}
		
		// We are done here :)
		return
	}

	currentCall := t.myhoustonCallTracer.callstack[len(t.myhoustonCallTracer.callstack)-1]
	currentCallId := currentCall.Id
	currentCodeAddress := *scope.Contract.CodeAddr
	currentStorageAddress := scope.Contract.Address()

	if t.grabShaResult {
		event_id := t.myhoustonCallTracer.nextEventId
		t.myhoustonCallTracer.nextEventId++

		sha_result := scope.Stack.Peek().Bytes()
		sha_preimage := t.shaPreimage

		t.shaActions = append(t.shaActions, ShaAction{
			EventId:        event_id,
			ShaPreimage:    sha_preimage,
			Result:         sha_result,
			CallId:         currentCallId,
			Pc:             pc,
			Address:        currentCodeAddress,
			StorageAddress: currentStorageAddress,
		})

		t.grabShaResult = false
	} 

	if op == vm.KECCAK256 {
		offset := scope.Stack.Data[len(scope.Stack.Data)-1]
		size := scope.Stack.Data[len(scope.Stack.Data)-2]

		// We need to grab the preimage from memory.
		preimage := scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		t.shaPreimage = preimage
		t.grabShaResult = true
	} else if op == vm.SSTORE {
		key := scope.Stack.Data[len(scope.Stack.Data)-1]
		value := scope.Stack.Data[len(scope.Stack.Data)-2]
		var oldValue uint256.Int
		hash := libcommon.BytesToHash(key.Bytes())
		t.env.IntraBlockState().GetState(currentStorageAddress, &hash, &oldValue)

		event_id := t.myhoustonCallTracer.nextEventId
		t.myhoustonCallTracer.nextEventId++

		t.sstoreActions = append(t.sstoreActions, SstoreAction{
			EventId:        event_id,
			Key:            key.ToBig(),
			Value:          value.ToBig(),
			OldValue:       oldValue.ToBig(),
			Pc:             pc,
			Address:        currentCodeAddress,
			StorageAddress: currentStorageAddress,
			Depth:          depth,
			CallId:         currentCallId,
			FID:            currentCall.Input[:min(len(currentCall.Input), 4)],
		})

	}
}

func (t *houstonTracer) CaptureEnter(typ vm.OpCode, from libcommon.Address, to libcommon.Address, precompile, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	t.myhoustonCallTracer.CaptureEnter(typ, from, to, precompile, create, input, gas, value, code)
	t.foundCall = true
}

func (t *houstonTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	t.myhoustonCallTracer.CaptureExit(output, gasUsed, err)
	if err != nil {
		t.myError = true
	}
}

func (t *houstonTracer) CaptureTxStart(gasLimit uint64) {
	t.myhoustonCallTracer.CaptureTxStart(gasLimit)
}

func (t *houstonTracer) CaptureTxEnd(restGas uint64) {
	t.myhoustonCallTracer.CaptureTxEnd(restGas)
}

func (t *houstonTracer) GetResult() (json.RawMessage, error) {
	callTracerResult, err := t.myhoustonCallTracer.GetResult()
	if err != nil {
		return nil, err
	}

	result := HoustonResult{
		CallTracerResult: callTracerResult,
		ShaActions:       t.shaActions,
		SstoreActions:    t.sstoreActions,
	}

	ret, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(ret), nil
}

func (t *houstonTracer) Stop(err error) {
	t.myhoustonCallTracer.Stop(err)
}

func (t *houstonTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, _ *vm.ScopeContext, depth int, err error) {
	t.myhoustonCallTracer.CaptureFault(pc, op, gas, cost, nil, depth, err)
	t.myError = true
}
