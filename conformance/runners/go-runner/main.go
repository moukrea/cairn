// Package main implements the cairn conformance test runner for Go.
//
// It reads scenario names from stdin (one per line), locates the
// corresponding YAML file under /conformance/tests/, executes the
// test actions using cairn-p2p protocol objects, and outputs a JSON-lines
// result for each scenario.
package main

import (
	"bufio"
	chmac "crypto/hmac"
	crand "crypto/rand"
	csha256 "crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cairncrypto "github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/moukrea/cairn/packages/go/cairn-p2p/protocol"
	"github.com/fxamacker/cbor/v2"
	"gopkg.in/yaml.v3"
)

// testsDir is the base directory for test scenario YAML files.
var testsDir = "/conformance/tests"

// vectorsDir is the base directory for deterministic test vectors.
var vectorsDir = "/conformance/vectors"

func init() {
	if d := os.Getenv("CAIRN_TESTS_DIR"); d != "" {
		testsDir = d
	}
	if d := os.Getenv("CAIRN_VECTORS_DIR"); d != "" {
		vectorsDir = d
	}
}

// --- YAML schema types ---

type ScenarioFile struct {
	Scenarios []Scenario `yaml:"scenarios"`
}

type Scenario struct {
	Name         string        `yaml:"scenario"`
	Description  string        `yaml:"description"`
	Tier         int           `yaml:"tier"`
	Category     string        `yaml:"category"`
	Participants []Participant `yaml:"participants"`
	Network      Network       `yaml:"network"`
	Actions      []Action      `yaml:"actions"`
	Expected     []Expected    `yaml:"expected"`
	TimeoutMs    int           `yaml:"timeout_ms"`
	BudgetMs     int           `yaml:"budget_ms"`
}

type Participant struct {
	Role string `yaml:"role"`
	Lang string `yaml:"lang"`
}

type Network struct {
	NATProfile string      `yaml:"nat_profile"`
	Netem      *Netem      `yaml:"netem,omitempty"`
	Disconnect *Disconnect `yaml:"disconnect,omitempty"`
}

type Netem struct {
	DelayMs  int     `yaml:"delay_ms"`
	JitterMs int     `yaml:"jitter_ms"`
	LossPct  float64 `yaml:"loss_pct"`
}

type Disconnect struct {
	AfterMs    int `yaml:"after_ms"`
	DurationMs int `yaml:"duration_ms"`
}

type Action struct {
	Type   string                 `yaml:"type"`
	Actor  string                 `yaml:"actor"`
	Params map[string]interface{} `yaml:"params"`
}

type Expected struct {
	Type   string                 `yaml:"type"`
	Actor  string                 `yaml:"actor"`
	Params map[string]interface{} `yaml:"params"`
}

// --- JSON-lines output ---

type Result struct {
	Scenario    string      `json:"scenario"`
	Status      string      `json:"status"`
	DurationMs  int64       `json:"duration_ms"`
	Diagnostics interface{} `json:"diagnostics"`
}

// --- Test vector file types ---

type HKDFVectors struct {
	Description string       `json:"description"`
	Vectors     []HKDFVector `json:"vectors"`
}

type HKDFVector struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Input       HKDFInput     `json:"input"`
	Expected    HKDFExpected  `json:"expected_output"`
}

type HKDFInput struct {
	IKMHex       string `json:"ikm_hex"`
	SaltHex      string `json:"salt_hex"`
	Info         string `json:"info"`
	OutputLength int    `json:"output_length"`
}

type HKDFExpected struct {
	OKMHex string `json:"okm_hex"`
}

type AEADVectors struct {
	Description string       `json:"description"`
	Vectors     []AEADVector `json:"vectors"`
}

type AEADVector struct {
	ID          string       `json:"id"`
	Description string       `json:"description"`
	Input       AEADInput    `json:"input"`
	Expected    AEADExpected `json:"expected_output"`
}

type AEADInput struct {
	Algorithm    string `json:"algorithm"`
	KeyHex       string `json:"key_hex"`
	NonceHex     string `json:"nonce_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	AADHex       string `json:"aad_hex"`
}

type AEADExpected struct {
	CiphertextAndTagHex string `json:"ciphertext_and_tag_hex"`
}

type CBOREnvelopeVectors struct {
	Description string               `json:"description"`
	Vectors     []CBOREnvelopeVector `json:"vectors"`
}

type CBOREnvelopeVector struct {
	ID          string              `json:"id"`
	Description string              `json:"description"`
	Input       CBOREnvelopeInput   `json:"input"`
	Expected    CBOREnvelopeExpect  `json:"expected_output"`
}

type CBOREnvelopeInput struct {
	Version      int     `json:"version"`
	MsgType      string  `json:"msg_type"`
	MsgIDHex     string  `json:"msg_id_hex"`
	SessionIDHex *string `json:"session_id_hex"`
	PayloadHex   string  `json:"payload_hex"`
	AuthTagHex   *string `json:"auth_tag_hex"`
}

type CBOREnvelopeExpect struct {
	CBORHex       string `json:"cbor_hex"`
	MapEntryCount int    `json:"map_entry_count"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" {
			continue
		}

		start := time.Now()
		status, diag := runScenario(name)
		elapsed := time.Since(start).Milliseconds()

		_ = encoder.Encode(Result{
			Scenario:    name,
			Status:      status,
			DurationMs:  elapsed,
			Diagnostics: diag,
		})
	}
}

func runScenario(name string) (string, interface{}) {
	scenario, err := findAndParseScenario(name)
	if err != nil {
		return "fail", map[string]string{"error": err.Error()}
	}

	// Check if Go is a participant.
	hasGoParticipant := false
	for _, p := range scenario.Participants {
		if p.Lang == "go" || p.Lang == "any" {
			hasGoParticipant = true
			break
		}
	}
	if !hasGoParticipant {
		return "skip", map[string]string{"skip": "no Go or any-lang participant"}
	}

	return executeActions(scenario)
}

func executeActions(s *Scenario) (string, interface{}) {
	diag := make(map[string]interface{})
	overallStatus := "pass"

	for i, action := range s.Actions {
		// Only execute actions for Go or any-lang participants.
		actorParticipant := findParticipant(s.Participants, action.Actor)
		if actorParticipant != nil && actorParticipant.Lang != "any" && actorParticipant.Lang != "go" {
			continue
		}

		key := fmt.Sprintf("action_%d_%s", i, action.Type)
		actionDiag := make(map[string]interface{})
		var actionStatus string

		switch action.Type {
		case "verify_cbor":
			actionStatus = dispatchVerifyCBOR(action.Params, actionDiag)
		case "verify_crypto":
			actionStatus = dispatchVerifyCrypto(action.Params, actionDiag)
		case "pair":
			actionStatus = dispatchPair(action.Params, actionDiag)
		case "establish_session", "send_data", "open_channel",
			"disconnect", "reconnect", "apply_nat", "send_forward", "wait":
			actionStatus = "skip"
			actionDiag["skip"] = fmt.Sprintf("action '%s' requires multi-process orchestration", action.Type)
		default:
			actionStatus = "skip"
			actionDiag["skip"] = fmt.Sprintf("unknown action type: %s", action.Type)
		}

		diag[key] = actionDiag
		if actionStatus == "fail" {
			overallStatus = "fail"
		} else if actionStatus == "skip" && overallStatus == "pass" {
			overallStatus = "skip"
		}
	}

	return overallStatus, diag
}

func findParticipant(participants []Participant, role string) *Participant {
	for i := range participants {
		if participants[i].Role == role {
			return &participants[i]
		}
	}
	return nil
}

// --- Scenario finding ---

func findAndParseScenario(name string) (*Scenario, error) {
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read tests dir %s: %w", testsDir, err)
	}

	// Search all YAML files in all subdirectories.
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirPath := filepath.Join(testsDir, entry.Name())
		files, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			fname := f.Name()
			if !strings.HasSuffix(fname, ".yml") && !strings.HasSuffix(fname, ".yaml") {
				continue
			}
			s, err := parseScenarioFromFile(filepath.Join(dirPath, fname), name)
			if err == nil {
				return s, nil
			}
		}
	}

	return nil, fmt.Errorf("scenario not found: %s", name)
}

func parseScenarioFromFile(path, name string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var file ScenarioFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("YAML parse error in %s: %w", path, err)
	}

	for i := range file.Scenarios {
		if file.Scenarios[i].Name == name {
			return &file.Scenarios[i], nil
		}
	}
	return nil, fmt.Errorf("scenario %s not found in %s", name, path)
}

// --- verify_cbor dispatch ---

func dispatchVerifyCBOR(params map[string]interface{}, diag map[string]interface{}) string {
	op, _ := params["operation"].(string)

	switch op {
	case "roundtrip":
		return verifyCBORRoundtrip(params, diag)
	case "field_types":
		return verifyCBORFieldTypes(diag)
	case "deterministic":
		return verifyCBORDeterministic(diag)
	default:
		return verifyCBORVectors(diag)
	}
}

func verifyCBORRoundtrip(params map[string]interface{}, diag map[string]interface{}) string {
	msgTypes := []uint16{0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700}

	// Parse message_types from params if present.
	if mt, ok := params["message_types"]; ok {
		if slice, ok := mt.([]interface{}); ok {
			msgTypes = nil
			for _, v := range slice {
				switch val := v.(type) {
				case int:
					msgTypes = append(msgTypes, uint16(val))
				case float64:
					msgTypes = append(msgTypes, uint16(val))
				}
			}
		}
	}

	// CBOR-encode a test payload since Payload is cbor.RawMessage (pre-encoded CBOR).
	testPayload, err := cborMarshal([]byte{0x01, 0x02, 0x03})
	if err != nil {
		diag["error"] = fmt.Sprintf("payload encode failed: %v", err)
		return "fail"
	}

	var failures []string
	for _, msgType := range msgTypes {
		env := &protocol.MessageEnvelope{
			Version: 1,
			Type:    msgType,
			MsgID:   [16]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42},
			Payload: testPayload,
		}

		encoded, err := env.Encode()
		if err != nil {
			failures = append(failures, fmt.Sprintf("type 0x%04x: encode failed: %v", msgType, err))
			continue
		}

		decoded, err := protocol.DecodeEnvelope(encoded)
		if err != nil {
			failures = append(failures, fmt.Sprintf("type 0x%04x: decode failed: %v", msgType, err))
			continue
		}

		if decoded.Version != env.Version {
			failures = append(failures, fmt.Sprintf("type 0x%04x: version mismatch", msgType))
		}
		if decoded.Type != env.Type {
			failures = append(failures, fmt.Sprintf("type 0x%04x: type mismatch", msgType))
		}
	}

	if len(failures) > 0 {
		diag["failures"] = failures
		return "fail"
	}
	return "pass"
}

func verifyCBORFieldTypes(diag map[string]interface{}) string {
	payload, _ := cborMarshal([]byte{0xca, 0xfe})
	sid := make([]byte, 32)
	for i := range sid {
		sid[i] = 0xab
	}
	env := &protocol.MessageEnvelope{
		Version:   1,
		Type:      0x0300,
		MsgID:     [16]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		SessionID: sid,
		Payload:   payload,
		AuthTag:   []byte{0xde, 0xad},
	}

	encoded, err := env.Encode()
	if err != nil {
		diag["error"] = fmt.Sprintf("encode failed: %v", err)
		return "fail"
	}

	decoded, err := protocol.DecodeEnvelope(encoded)
	if err != nil {
		diag["error"] = fmt.Sprintf("decode failed: %v", err)
		return "fail"
	}

	var failures []string
	if decoded.MsgID == [16]byte{} {
		failures = append(failures, "msgId is zero")
	}
	if len(decoded.SessionID) != 32 {
		failures = append(failures, fmt.Sprintf("sessionId: expected 32 bytes, got %d", len(decoded.SessionID)))
	}
	if len(decoded.Payload) == 0 {
		failures = append(failures, "payload is empty")
	}

	if len(failures) > 0 {
		diag["failures"] = failures
		return "fail"
	}
	return "pass"
}

func verifyCBORDeterministic(diag map[string]interface{}) string {
	payload, _ := cborMarshal([]byte{0xca, 0xfe})
	env := &protocol.MessageEnvelope{
		Version: 1,
		Type:    0x0300,
		MsgID:   [16]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		Payload: payload,
	}

	enc1, err := env.EncodeDeterministic()
	if err != nil {
		diag["error"] = err.Error()
		return "fail"
	}
	enc2, err := env.EncodeDeterministic()
	if err != nil {
		diag["error"] = err.Error()
		return "fail"
	}

	if hex.EncodeToString(enc1) != hex.EncodeToString(enc2) {
		diag["error"] = "deterministic encoding not stable"
		diag["enc1"] = hex.EncodeToString(enc1)
		diag["enc2"] = hex.EncodeToString(enc2)
		return "fail"
	}
	return "pass"
}

func verifyCBORVectors(diag map[string]interface{}) string {
	vectorPath := filepath.Join(vectorsDir, "cbor", "envelope_encoding.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		diag["skip"] = "envelope_encoding.json not found"
		return "skip"
	}

	var vectors CBOREnvelopeVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		diag["error"] = fmt.Sprintf("JSON parse error: %v", err)
		return "fail"
	}

	var failures []map[string]string
	for _, vec := range vectors.Vectors {
		msgType := parseMsgType(vec.Input.MsgType)
		msgID, _ := hex.DecodeString(vec.Input.MsgIDHex)
		payloadRaw, _ := hex.DecodeString(vec.Input.PayloadHex)

		// Payload must be CBOR-encoded (RawMessage) — encode the raw bytes as a CBOR byte string.
		payloadCBOR, err := cborMarshal(payloadRaw)
		if err != nil {
			failures = append(failures, map[string]string{"id": vec.ID, "error": fmt.Sprintf("payload cbor encode: %v", err)})
			continue
		}

		var msgIDArr [16]byte
		copy(msgIDArr[:], msgID)

		env := &protocol.MessageEnvelope{
			Version: uint8(vec.Input.Version),
			Type:    msgType,
			MsgID:   msgIDArr,
			Payload: payloadCBOR,
		}

		if vec.Input.SessionIDHex != nil && *vec.Input.SessionIDHex != "" {
			sid, _ := hex.DecodeString(*vec.Input.SessionIDHex)
			env.SessionID = sid
		}
		if vec.Input.AuthTagHex != nil && *vec.Input.AuthTagHex != "" {
			tag, _ := hex.DecodeString(*vec.Input.AuthTagHex)
			env.AuthTag = tag
		}

		encoded, err := env.EncodeDeterministic()
		if err != nil {
			failures = append(failures, map[string]string{"id": vec.ID, "error": err.Error()})
			continue
		}

		actualHex := hex.EncodeToString(encoded)
		if actualHex != vec.Expected.CBORHex {
			failures = append(failures, map[string]string{
				"id":       vec.ID,
				"expected": vec.Expected.CBORHex,
				"actual":   actualHex,
			})
		}
	}

	if len(failures) > 0 {
		diag["failures"] = failures
		diag["total"] = len(vectors.Vectors)
		diag["failed"] = len(failures)
		return "fail"
	}
	diag["verified"] = len(vectors.Vectors)
	return "pass"
}

func parseMsgType(s string) uint16 {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var v uint16
	fmt.Sscanf(s, "%x", &v)
	return v
}

// cborMarshal encodes a value as CBOR bytes.
func cborMarshal(v interface{}) ([]byte, error) {
	return cbor.Marshal(v)
}

// --- verify_crypto dispatch ---

func dispatchVerifyCrypto(params map[string]interface{}, diag map[string]interface{}) string {
	op, _ := params["operation"].(string)

	switch op {
	case "hkdf_sha256", "hkdf_sha256_batch":
		return verifyCryptoHKDF(params, diag)
	case "aead_encrypt":
		return verifyCryptoAEADEncrypt(params, diag)
	case "aead_decrypt":
		return verifyCryptoAEADDecrypt(params, diag)
	default:
		diag["skip"] = fmt.Sprintf("unsupported crypto operation: %s", op)
		return "skip"
	}
}

func verifyCryptoHKDF(params map[string]interface{}, diag map[string]interface{}) string {
	vectorPath := filepath.Join(vectorsDir, "crypto", "hkdf_vectors.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		diag["skip"] = "hkdf_vectors.json not found"
		return "skip"
	}

	var vectors HKDFVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		diag["error"] = fmt.Sprintf("JSON parse error: %v", err)
		return "fail"
	}

	// Collect info constants to filter on (if specified).
	infoFilter := make(map[string]bool)
	if infoStr, ok := params["info"].(string); ok {
		infoFilter[infoStr] = true
	}
	if infoList, ok := params["info_constants"].([]interface{}); ok {
		for _, v := range infoList {
			if s, ok := v.(string); ok {
				infoFilter[s] = true
			}
		}
	}

	var failures []map[string]string
	testedCount := 0

	for _, vec := range vectors.Vectors {
		if len(infoFilter) > 0 && !infoFilter[vec.Input.Info] {
			continue
		}
		testedCount++

		ikm, _ := hex.DecodeString(vec.Input.IKMHex)
		var salt []byte
		if vec.Input.SaltHex != "" {
			salt, _ = hex.DecodeString(vec.Input.SaltHex)
		}
		info := []byte(vec.Input.Info)
		length := vec.Input.OutputLength

		result, err := cairncrypto.HkdfSHA256(ikm, salt, info, length)
		if err != nil {
			failures = append(failures, map[string]string{"id": vec.ID, "error": err.Error()})
			continue
		}

		actualHex := hex.EncodeToString(result)
		if actualHex != vec.Expected.OKMHex {
			failures = append(failures, map[string]string{
				"id":       vec.ID,
				"info":     vec.Input.Info,
				"expected": vec.Expected.OKMHex,
				"actual":   actualHex,
			})
		}
	}

	if len(failures) > 0 {
		diag["failures"] = failures
		return "fail"
	}
	diag["verified"] = testedCount
	return "pass"
}

func verifyCryptoAEADEncrypt(params map[string]interface{}, diag map[string]interface{}) string {
	vectorPath := filepath.Join(vectorsDir, "crypto", "aead_vectors.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		diag["skip"] = "aead_vectors.json not found"
		return "skip"
	}

	var vectors AEADVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		diag["error"] = fmt.Sprintf("JSON parse error: %v", err)
		return "fail"
	}

	cipherFilter, _ := params["cipher"].(string)
	algMap := map[string]string{
		"aes_256_gcm":       "AES-256-GCM",
		"chacha20_poly1305": "ChaCha20-Poly1305",
	}

	var failures []map[string]string
	testedCount := 0

	for _, vec := range vectors.Vectors {
		if cipherFilter != "" {
			expected := algMap[cipherFilter]
			if expected == "" {
				expected = cipherFilter
			}
			if vec.Input.Algorithm != expected {
				continue
			}
		}
		testedCount++

		keyBytes, _ := hex.DecodeString(vec.Input.KeyHex)
		nonceBytes, _ := hex.DecodeString(vec.Input.NonceHex)
		plaintext, _ := hex.DecodeString(vec.Input.PlaintextHex)
		aad, _ := hex.DecodeString(vec.Input.AADHex)

		var key [32]byte
		var nonce [12]byte
		copy(key[:], keyBytes)
		copy(nonce[:], nonceBytes)

		var cs cairncrypto.CipherSuite
		if vec.Input.Algorithm == "AES-256-GCM" {
			cs = cairncrypto.CipherAes256Gcm
		} else {
			cs = cairncrypto.CipherChaCha20Poly1305
		}

		result, err := cairncrypto.AeadEncrypt(cs, key, nonce, plaintext, aad)
		if err != nil {
			failures = append(failures, map[string]string{"id": vec.ID, "error": err.Error()})
			continue
		}

		actualHex := hex.EncodeToString(result)
		if actualHex != vec.Expected.CiphertextAndTagHex {
			failures = append(failures, map[string]string{
				"id":        vec.ID,
				"algorithm": vec.Input.Algorithm,
				"expected":  vec.Expected.CiphertextAndTagHex,
				"actual":    actualHex,
			})
		}
	}

	if len(failures) > 0 {
		diag["failures"] = failures
		return "fail"
	}
	diag["verified"] = testedCount
	return "pass"
}

func verifyCryptoAEADDecrypt(params map[string]interface{}, diag map[string]interface{}) string {
	vectorPath := filepath.Join(vectorsDir, "crypto", "aead_vectors.json")
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		diag["skip"] = "aead_vectors.json not found"
		return "skip"
	}

	var vectors AEADVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		diag["error"] = fmt.Sprintf("JSON parse error: %v", err)
		return "fail"
	}

	var failures []map[string]string
	for _, vec := range vectors.Vectors {
		if vec.Input.PlaintextHex == "" {
			continue
		}

		keyBytes, _ := hex.DecodeString(vec.Input.KeyHex)
		nonceBytes, _ := hex.DecodeString(vec.Input.NonceHex)
		plaintext, _ := hex.DecodeString(vec.Input.PlaintextHex)
		aad, _ := hex.DecodeString(vec.Input.AADHex)
		expectedCT, _ := hex.DecodeString(vec.Expected.CiphertextAndTagHex)

		var key [32]byte
		var nonce [12]byte
		copy(key[:], keyBytes)
		copy(nonce[:], nonceBytes)

		var cs cairncrypto.CipherSuite
		if vec.Input.Algorithm == "AES-256-GCM" {
			cs = cairncrypto.CipherAes256Gcm
		} else {
			cs = cairncrypto.CipherChaCha20Poly1305
		}

		decrypted, err := cairncrypto.AeadDecrypt(cs, key, nonce, expectedCT, aad)
		if err != nil {
			failures = append(failures, map[string]string{"id": vec.ID, "error": err.Error()})
			continue
		}

		if hex.EncodeToString(decrypted) != hex.EncodeToString(plaintext) {
			failures = append(failures, map[string]string{
				"id":       vec.ID,
				"expected": hex.EncodeToString(plaintext),
				"actual":   hex.EncodeToString(decrypted),
			})
		}
	}

	if len(failures) > 0 {
		diag["failures"] = failures
		return "fail"
	}
	return "pass"
}

// --- pair dispatch ---

func dispatchPair(params map[string]interface{}, diag map[string]interface{}) string {
	mechanism, _ := params["mechanism"].(string)
	flow, _ := params["flow"].(string)
	if flow == "" {
		flow = "initiation"
	}

	if mechanism == "psk" && flow == "initiation" {
		return verifyPSKPairing(params, diag)
	}

	diag["skip"] = fmt.Sprintf("pairing mechanism '%s' (flow: %s) not yet implemented in runner", mechanism, flow)
	return "skip"
}

func verifyPSKPairing(params map[string]interface{}, diag map[string]interface{}) string {
	pskStr, _ := params["psk"].(string)
	if pskStr == "" {
		diag["skip"] = "no psk param (bulk/specialized pairing scenario)"
		return "skip"
	}

	psk := []byte(pskStr)
	hkdfInfoPairingSession := []byte("cairn-pairing-session-key-v1")
	hkdfInfoKeyConfirm := []byte("cairn-pairing-key-confirm-v1")

	// Create SPAKE2 sessions for initiator and responder.
	spakeA, initMsg, err := cairncrypto.NewSpake2(cairncrypto.RoleInitiator, psk)
	if err != nil {
		diag["error"] = fmt.Sprintf("SPAKE2 init A failed: %v", err)
		return "fail"
	}
	spakeB, respMsg, err := cairncrypto.NewSpake2(cairncrypto.RoleResponder, psk)
	if err != nil {
		diag["error"] = fmt.Sprintf("SPAKE2 init B failed: %v", err)
		return "fail"
	}

	// Generate nonces.
	nonceA := make([]byte, 16)
	nonceB := make([]byte, 16)
	crand.Read(nonceA)
	crand.Read(nonceB)

	// Responder finishes SPAKE2 with initiator's message.
	rawKeyB, err := spakeB.Finish(initMsg)
	if err != nil {
		diag["error"] = fmt.Sprintf("SPAKE2 finish B failed: %v", err)
		return "fail"
	}

	// Initiator finishes SPAKE2 with responder's message.
	rawKeyA, err := spakeA.Finish(respMsg)
	if err != nil {
		diag["error"] = fmt.Sprintf("SPAKE2 finish A failed: %v", err)
		return "fail"
	}

	// Derive session keys: salt = initiator_nonce || responder_nonce
	salt := append(append([]byte{}, nonceA...), nonceB...)

	sessionKeyA, err := cairncrypto.HkdfSHA256(rawKeyA[:], salt, hkdfInfoPairingSession, 32)
	if err != nil {
		diag["error"] = fmt.Sprintf("HKDF session key A failed: %v", err)
		return "fail"
	}
	sessionKeyB, err := cairncrypto.HkdfSHA256(rawKeyB[:], salt, hkdfInfoPairingSession, 32)
	if err != nil {
		diag["error"] = fmt.Sprintf("HKDF session key B failed: %v", err)
		return "fail"
	}

	// Verify shared keys match.
	if hex.EncodeToString(sessionKeyA) != hex.EncodeToString(sessionKeyB) {
		diag["error"] = "session key mismatch after SPAKE2"
		diag["initiator_key"] = hex.EncodeToString(sessionKeyA)
		diag["responder_key"] = hex.EncodeToString(sessionKeyB)
		return "fail"
	}

	// Verify key confirmation (HMAC-SHA256 with HKDF-derived confirm key).
	confirmKeyA, _ := cairncrypto.HkdfSHA256(sessionKeyA, nil, hkdfInfoKeyConfirm, 32)
	confirmKeyB, _ := cairncrypto.HkdfSHA256(sessionKeyB, nil, hkdfInfoKeyConfirm, 32)

	macA := hmacSHA256(confirmKeyA, []byte("initiator"))
	macB := hmacSHA256(confirmKeyB, []byte("initiator"))

	if hex.EncodeToString(macA) != hex.EncodeToString(macB) {
		diag["error"] = "key confirmation mismatch"
		return "fail"
	}

	diag["shared_key_match"] = true
	return "pass"
}

func hmacSHA256(key, data []byte) []byte {
	mac := chmac.New(csha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
