package quic

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
	/*"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"*/)

// in the neqo implementation, defenseRunner basically hooks into process_timer, i.e., the function called when a timeout of a registered timer occurs
// this concept does not directly exist in quic-go
// in either case we need a function that provides when the next timer should fire for the defense
type defenseRunner interface {
	InitTrace(defenseConfig defenseConfig, serverName, dstConnID string)
	// set the start time for the trace
	Start(now time.Time)
	NextTimer() time.Time
	ProcessTimer(now time.Time)
	NeedsChaff() bool
	SentChaffPacket(now time.Time)
	/*CurrentSize() protocol.ByteCount
	GetPing(now time.Time) (ping ackhandler.Frame, datagramSize protocol.ByteCount)
	Reset(now time.Time, start, max protocol.ByteCount)*/
}

type defenseConfig interface {
	InitTrace() []time.Duration
	SetSeed(uint64)
}

type frontConfig struct {
	nofServerPackets uint32
	peakMin          float64
	peakMax          float64
	seed             uint64
}

func newFrontConfig() *frontConfig {
	return &frontConfig{
		nofServerPackets: 1300,
		peakMin:          0.2,
		peakMax:          3.0,
		seed:             0,
	}
}

func (fConf *frontConfig) InitTrace() []time.Duration {
	//randv2; not entirely sure why two seeds are needed?
	rng := rand.New(rand.NewPCG(fConf.seed, fConf.seed))
	//since we are the server in quic-go (no checks for that though!) the outgoing packets are using nofServerPackets
	outgoingPackets := samplePacketTimestamps(fConf.peakMin, fConf.peakMax, fConf.nofServerPackets, rng)
	// TODO: I think a lot of the code can be simplified if we reverse this list
	sort.Slice(outgoingPackets, func(i, j int) bool {
		return outgoingPackets[i] < outgoingPackets[j]
	})
	return outgoingPackets
}

func (fConf *frontConfig) SetSeed(seed uint64) {
	fConf.seed = seed
}

// taken from numpy/qcsd
func rayleighCdfInv(uniformRandomNumber float64, weightFromPeaks float64) float64 {
	//l_n(1-u)
	inner := math.Log(1.0 - uniformRandomNumber)
	//sqrt(-2*ln(1-u))
	outer := math.Sqrt(-2.0 * inner)
	//w*sqrt(-2*ln(1-u))
	return weightFromPeaks * outer
}

// the returned slice is likely not sorted
func samplePacketTimestamps(peakMin, peakMax float64, maxPackets uint32, rng *rand.Rand) []time.Duration {
	if maxPackets == 0 {
		return nil
	}
	// [1..maxPackets] -- technically [0..maxPackets)+1
	// discretized just means we sample integers instead of floats
	nofPackets := rng.IntN(int(maxPackets)) + 1
	weight := ((peakMax - peakMin) * rng.Float64()) + peakMin
	timestamps := make([]time.Duration, nofPackets)
	for i := 0; i < int(nofPackets); i++ {
		// sample from rayleigh distribution
		// rayleigh returns seconds in floating points (basically just following the original FRONT paper)
		timestamps[i] = time.Duration(float64(time.Second) * rayleighCdfInv(rng.Float64(), weight))
	}
	return timestamps
}

type chaffDefender struct {
	controlInterval time.Duration
	// the trace we have left, excluding the current control interval (relative to start, thus durations)
	defenseTrace []time.Duration
	//next control interval as absolute timestamp
	nextUpdate time.Time
	// implicit trace start time
	start time.Time
	// end time
	end time.Time
	// the actions in the current control interval (absolute timestamps to compare to now)
	chaffPacketQueue uint32
	//actionQueue []time.Time
	serverName string

	dstConnID string

	//rttStats *utils.RTTStats

	//inFlight protocol.ByteCount // the size of the probe packet currently in flight. InvalidByteCount if none is in flight

	// The generation is used to ignore ACKs / losses for probe packets sent before a reset.
	// Resets happen when the connection is migrated to a new path.
	// We're therefore not concerned about overflows of this counter.
	//generation uint8

	//tracer *logging.ConnectionTracer
}

func newChaffDefender() *chaffDefender {
	return &chaffDefender{}
}

func (def *chaffDefender) Start(now time.Time) {
	if def.start.IsZero() {
		def.start = now
		def.controlInterval = time.Millisecond * 5
		def.nextUpdate = now
	} else {
		log.Println("ChaffDefender.Start called multiple times!")
	}
}
func (def *chaffDefender) InitTrace(defenseConfig defenseConfig, serverName, dstConnID string) {
	if def.start.IsZero() {
		if def.defenseTrace != nil {
			log.Println("INIT CALLED MULTIPLE TIMES!")
			return
		}
		def.serverName = serverName
		def.dstConnID = dstConnID
		//read seed from env var, otherwise randomly generate
		seedFromEnv, exists := os.LookupEnv("FRONT_SEED")
		seed := rand.Uint64()
		if exists {
			if seedParsed, err := strconv.ParseUint(seedFromEnv, 10, 64); err == nil {
				seed = seedParsed
			}
		}
		defenseConfig.SetSeed(seed)
		def.defenseTrace = defenseConfig.InitTrace()
		csvPath, exists := os.LookupEnv("TRACE_CSV_DIR")
		if exists {
			path := filepath.Join(csvPath, fmt.Sprintf("%s-%s-front-defense-seed-%s.csv", serverName, dstConnID, strconv.FormatUint(seed, 10)))
			file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				return
			}
			dataWriter := bufio.NewWriter(file)
			// we write out as if this were a trace from the client perspective, where negative numbers indicate incoming packets
			packetSizeAndDirection := "-1280"
			_, _ = dataWriter.WriteString("time_ms,size\n")
			for _, traceTime := range def.defenseTrace {
				_, _ = dataWriter.WriteString(fmt.Sprintf("%d,%s", traceTime.Milliseconds(), packetSizeAndDirection) + "\n")
			}
			dataWriter.Flush()
			file.Close()
		}

	}

}

func (def *chaffDefender) NextTimer() time.Time {
	if def.start.IsZero() {
		return time.Time{}
	}
	if len(def.defenseTrace) == 0 || def.defenseTrace == nil {
		return time.Time{}
	}
	//this should be smarter and take into account when the next packet is actually needed, as there are a lot of control intervals without any packets toward the end
	return def.nextUpdate
}

func (def *chaffDefender) ProcessTimer(now time.Time) {
	//log.Println(def.dstConnID)
	// if both defense and next actions are empty, the defense is done
	// the check is in ProcessTimer so that the check happens quite late but is called almost directly from within the main run loop
	// TODO: defense done should probably be moved to the runLoop in connection.go
	if !def.start.IsZero() && !def.end.IsZero() && len(def.defenseTrace) == 0 && def.chaffPacketQueue == 0 {
		//TODO: signal to our python script that the defense is done using unix domain sockets
		fmt.Println("DEFENSE DONE")
	}
	if def.start.IsZero() || !def.end.IsZero() {
		return
	}
	if len(def.defenseTrace) == 0 || def.defenseTrace == nil {
		return
	}
	if now.Before(def.nextUpdate) {
		return
	}
	def.chaffPacketQueue = 0

	//convert real time to trace time (i.e., from time instant to duration since start)
	endOfCurrentControlInterval := now.Add(def.controlInterval).Sub(def.start)
	// this is rather easy compared to the version in neqo because a packet is simply a timestamp
	// theoretically, you could model this as a simple counter, but we want to see how much we drift compared to the trace
	// add all packets that should be sent in the next 5 ms
	// effectively this means we will drift by up to 5 ms compared to the original trace
	// it also does not seem to matter whether we look at the next 5 ms in the trace or the past 5 ms
	for len(def.defenseTrace) > 0 && def.defenseTrace[0] < endOfCurrentControlInterval {
		// definitely not safe from goroutines
		// convert the durations back to absolute timestamps
		def.chaffPacketQueue += 1
		def.defenseTrace = def.defenseTrace[1:]
	}
	def.nextUpdate = now.Add(def.controlInterval)
	// if the trace is empty,
	if len(def.defenseTrace) == 0 {
		def.end = now
		def.nextUpdate = time.Time{}
	}

}
func (def *chaffDefender) NeedsChaff() bool {
	return def.chaffPacketQueue > 0
}

func (def *chaffDefender) SentChaffPacket(now time.Time) {
	if def.chaffPacketQueue > 0 {
		def.chaffPacketQueue -= 1
	}
}
