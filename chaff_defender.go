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
	InitSchedule(defenseConfig defenseConfig, remotePort string, controlIntervalIsSlidingWindow bool)
	// set the start time for the trace
	Start(now time.Time)
	NextTimer(expiryTime time.Time) time.Time
	ProcessTimer(now, expiryTime time.Time)
	NeedsPadding() bool
	NeedsChaff() bool
	SentChaffPacket(now time.Time)
	NeedsKeepalive() bool
	// Stop signals that the defense is over (e.g. because the connection is closing),
	// removing the defense-state lock file if one was created.
	Stop()
	/*CurrentSize() protocol.ByteCount
	GetPing(now time.Time) (ping ackhandler.Frame, datagramSize protocol.ByteCount)
	Reset(now time.Time, start, max protocol.ByteCount)*/
}

// [TODO]: this should probably be the place where sliding window is decided and not in the defenserunner start function
type defenseConfig interface {
	InitSchedule() []time.Duration
	SetSeed(uint64)
}

type frontConfig struct {
	maxServerPackets uint32
	peakMin          float64
	peakMax          float64
	seed             uint64
}

func newFrontConfig(maxServerPackets uint32, peakMin, peakMax float64) *frontConfig {
	//fmt.Printf("PID %d: FRONT config: maxServerPackets=%d, peakMin=%f, peakMax=%f\n", os.Getpid(), maxServerPackets, peakMin, peakMax)
	return &frontConfig{
		maxServerPackets: maxServerPackets,
		peakMin:          peakMin,
		peakMax:          peakMax,
		seed:             0,
	}
}

func (fConf *frontConfig) InitSchedule() []time.Duration {
	//randv2; not entirely sure why two seeds are needed?
	rng := rand.New(rand.NewPCG(fConf.seed, fConf.seed))
	//since we are the server in quic-go (no checks for that though!) the outgoing packets are using nofServerPackets
	outgoingPackets := samplePacketTimestamps(fConf.peakMin, fConf.peakMax, fConf.maxServerPackets, rng)
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
	controlIntervalLength time.Duration
	// the trace we have left, excluding the current control interval (relative to start, thus durations)
	defenseSchedule []time.Duration
	//next control interval as absolute timestamp
	nextUpdate time.Time
	// implicit trace start time
	start time.Time
	// end time
	end time.Time
	// the actions in the current control interval (absolute timestamps to compare to now)
	// == neqo_transport::DefenseRunner.control_interval
	chaffPacketQueue uint32
	//actionQueue []time.Time
	//serverName string

	//dstConnID string

	remotePort string

	// path of the lock file signaling to the firefox automation that a server-side
	// defense is in progress; empty if DEFENSE_SERVER_STATE_DIR is unset. Removed once
	// the defense finishes (see signalDefenseDone).
	defenseStateFile string

	controlIntervalIsSlidingWindow bool

	needsKeepalive bool

	nextControlInterval time.Duration

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
		def.controlIntervalLength = time.Millisecond * 5
		def.nextUpdate = now
		//log.Println("Defense starting", now)
	} else {
		log.Println("ChaffDefender.Start called multiple times!")
	}
}

// at this point, this is equivalent to the neqo new function of the defense runner there
func (def *chaffDefender) InitSchedule(defenseConfig defenseConfig, remotePort string, controlIntervalIsSlidingWindow bool) {
	if def.start.IsZero() {
		if def.defenseSchedule != nil {
			log.Println("INIT CALLED MULTIPLE TIMES!")
			return
		}
		/*def.serverName = serverName
		def.dstConnID = dstConnID*/
		def.remotePort = remotePort
		def.controlIntervalIsSlidingWindow = controlIntervalIsSlidingWindow
		// add qcsd to csv if not sliding window mode
		is_qcsd_str := ""
		if !controlIntervalIsSlidingWindow {
			is_qcsd_str = "-qcsd"
		}
		//read seed from env var, otherwise randomly generate
		//seedFromEnv, exists := os.LookupEnv("FRONT_SEED")
		// [TODO]: make seed configurable through CLI instead
		seed := rand.Uint64()
		/*if exists {
			if seedParsed, err := strconv.ParseUint(seedFromEnv, 10, 64); err == nil {
				seed = seedParsed
			}
		}*/
		defenseConfig.SetSeed(seed)
		def.defenseSchedule = defenseConfig.InitSchedule()
		csvPath, exists := os.LookupEnv("TRACE_CSV_DIR")
		if exists {
			path := filepath.Join(csvPath, fmt.Sprintf("%s-server-side-front-defense%s-seed-%s.csv", def.remotePort, is_qcsd_str, strconv.FormatUint(seed, 10)))
			file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				return
			}
			dataWriter := bufio.NewWriter(file)
			// we write out as if this were a trace from the client perspective, where negative numbers indicate incoming packets
			packetSizeAndDirection := "-1280"
			_, _ = dataWriter.WriteString("time_ms,size\n")
			for _, traceTime := range def.defenseSchedule {
				_, _ = dataWriter.WriteString(fmt.Sprintf("%d,%s", traceTime.Milliseconds(), packetSizeAndDirection) + "\n")
			}
			dataWriter.Flush()
			file.Close()
		}

		// signal to the firefox automation that a server-side defense is in progress by
		// creating a lock file; the automation polls DEFENSE_SERVER_STATE_DIR and waits
		// until it is empty. The file is removed again once the defense finishes (see
		// signalDefenseDone). We mirror the CSV naming so the lock is traceable to its
		// schedule; the automation only cares that the directory is non-empty.
		if stateDir, exists := os.LookupEnv("DEFENSE_SERVER_STATE_DIR"); exists {
			path := filepath.Join(stateDir, fmt.Sprintf("%s-server-side-front-defense-seed-%s", def.remotePort, strconv.FormatUint(seed, 10)))
			if file, err := os.Create(path); err != nil {
				log.Println("failed creating defense state file", path, "error:", err)
			} else {
				file.Close()
				def.defenseStateFile = path
			}
		}

	} else {
		log.Println("ChaffDefender.InitSchedule called multiple times!")
		def.start = time.Time{}
		def.end = time.Time{}
		def.nextUpdate = time.Time{}
		def.defenseSchedule = nil
		def.chaffPacketQueue = 0
	}
}

func (def *chaffDefender) NextTimer(expiryTime time.Time) time.Time {
	if def.controlIntervalIsSlidingWindow {
		if def.start.IsZero() || !def.end.IsZero() || def.defenseSchedule == nil || len(def.defenseSchedule) == 0 {
			return time.Time{}
		}
		//this should be smarter and take into account when the next packet is actually needed, as there are a lot of control intervals without any packets toward the end
		return def.nextUpdate
	} else {
		var instant time.Time
		if def.chaffPacketQueue > 0 {
			instant = time.Now()
		} else if !def.end.IsZero() {
			instant = def.end
		} else if def.defenseSchedule == nil || len(def.defenseSchedule) == 0 {
			instant = def.start.Add(def.nextControlInterval)
		} else {
			nextDefenseTime := def.defenseSchedule[0]
			if nextDefenseTime < def.nextControlInterval {
				instant = def.start.Add(nextDefenseTime)
			} else {
				instant = def.start.Add(def.nextControlInterval)
			}
		}
		cancelExpiryAt := expiryTime.Add(-100 * time.Millisecond)
		if cancelExpiryAt.Before(instant) {
			instant = cancelExpiryAt
		}
		if instant.Before(time.Now()) {
			instant = time.Now()
		}
		return instant

	}
}

func (def *chaffDefender) ProcessTimer(now, expiryTime time.Time) {
	/*if def.start.IsZero() {
		return
	}
	//log.Println(def.dstConnID)
	// if both defense and next actions are empty, the defense is done
	// the check is in ProcessTimer so that the check happens quite late but is called almost directly from within the main run loop
	// TODO: defense done should probably be moved to the runLoop in connection.go
	if !def.start.IsZero() && !def.end.IsZero() && len(def.defenseSchedule) == 0 && def.chaffPacketQueue == 0 {
		//TODO: signal to our python script that the defense is done using unix domain sockets
		fmt.Println("DEFENSE DONE")
	}
	if len(def.defenseSchedule) == 0 || def.defenseSchedule == nil {
		return
		}*/

	if def.controlIntervalIsSlidingWindow {
		if def.start.IsZero() || def.nextUpdate.IsZero() || !def.end.IsZero() || def.defenseSchedule == nil || len(def.defenseSchedule) == 0 {
			return
		}
		if now.Before(def.nextUpdate) {
			return
		}

		def.chaffPacketQueue = 0

		//convert real time to trace time (i.e., from time instant to duration since start)
		endOfCurrentControlInterval := now.Add(def.controlIntervalLength).Sub(def.start)
		// we have a sliding window of 5 milliseconds around the defense trace dummy packet send events
		// if a timeout is missed, the packet will still be sent if it was within half of the window in the past
		// effectively the window is not 5 milliseconds but 5 milliseconds in the future and 2.5 milliseconds in the past
		// however, the past is only a counter to timers being missed due to other processing going on
		startOfCurrentControlInterval := now.Add(-1 * (def.controlIntervalLength / 2)).Sub(def.start)
		// this is rather easy compared to the version in neqo because a packet is simply a timestamp
		// we don't have any kind of sliding window, each control interval is clean and does not have past unsent packets -> this is not true, it will take ALL unsent packets from the trace, even if they are in the past
		// this is wrong. if we miss a timeout this all falls apart
		// also there is no handling of packets that are too old, i.e., if a timeout happens too late we still act like they are within the current control interval

		// drop packets outsie the window into the past
		for len(def.defenseSchedule) > 0 && def.defenseSchedule[0] < startOfCurrentControlInterval {
			//missedDummyPacket := def.start.Add(def.defenseSchedule[0])
			//log.Println("missed defense packet at", missedDummyPacket) //, "for server", def.serverName, "DCID", def.dstConnID)
			def.defenseSchedule = def.defenseSchedule[1:]
		}
		// add packets within the window
		for len(def.defenseSchedule) > 0 && def.defenseSchedule[0] < endOfCurrentControlInterval {
			// definitely not safe from goroutines
			// convert the durations back to absolute timestamps
			def.chaffPacketQueue += 1
			def.defenseSchedule = def.defenseSchedule[1:]
		}
		//def.nextUpdate = now.Add(def.controlInterval)
		// if the trace is empty, set end and set nextupdate to dummy time
		if len(def.defenseSchedule) == 0 {
			def.end = now
			def.nextUpdate = time.Time{}
			def.signalDefenseDone()
		} else {
			// we peak into the defense trace to see when the next dummy packet is due
			def.nextUpdate = def.start.Add(def.defenseSchedule[0])
			//timeoutDuration := def.nextUpdate.Sub(now)
			//log.Println("duration until next dummy packet: ", timeoutDuration)
		}
	} else {
		if def.start.IsZero() || !def.end.IsZero() {
			return
		}
		sinceStart := now.Sub(def.start)
		ciIndex := sinceStart.Milliseconds() / def.controlIntervalLength.Milliseconds()
		if def.nextControlInterval < sinceStart {
			def.nextControlInterval = time.Duration(ciIndex+1) * def.controlIntervalLength
		}
		//endOfCurrentControlInterval := now.Add(def.controlIntervalLength).Sub(def.start)
		for len(def.defenseSchedule) > 0 && def.defenseSchedule[0] < sinceStart {
			// definitely not safe from goroutines
			// convert the durations back to absolute timestamps
			def.chaffPacketQueue += 1
			def.defenseSchedule = def.defenseSchedule[1:]
		}
		if len(def.defenseSchedule) == 0 {
			def.end = now
			def.signalDefenseDone()
		}
		cancelExpiryAt := expiryTime.Add(-100 * time.Millisecond)
		if def.end.IsZero() && !cancelExpiryAt.After(now) && def.chaffPacketQueue == 0 {
			//log.Printf("Need keepalive; %d packets in schedule remaining\n", len(def.defenseSchedule))
			def.needsKeepalive = true
		}
	}

	//log.Printf("%d packets in queue\n", def.chaffPacketQueue)

}

func (def *chaffDefender) NeedsKeepalive() bool {
	if def.needsKeepalive {
		def.needsKeepalive = false
		return true
	}
	return false
}

func (def *chaffDefender) NeedsChaff() bool {
	if !def.controlIntervalIsSlidingWindow {
		//log.Printf("NeedsChaff; %d packets in queue\n", def.chaffPacketQueue)
		return def.chaffPacketQueue > 0
	}
	return false
}

func (def *chaffDefender) NeedsPadding() bool {
	if def.controlIntervalIsSlidingWindow {
		return def.chaffPacketQueue > 0
	}
	return false
}

func (def *chaffDefender) SentChaffPacket(now time.Time) {
	if def.chaffPacketQueue > 0 {
		def.chaffPacketQueue -= 1
		//log.Printf("Sent chaff/padding; %d packets in queue\n", def.chaffPacketQueue)
	}
}

// signalDefenseDone removes the defense-state lock file, telling the firefox automation
// that this connection's defense has finished. It is a no-op if no file was created.
func (def *chaffDefender) signalDefenseDone() {
	if def.defenseStateFile == "" {
		return
	}
	if err := os.Remove(def.defenseStateFile); err != nil {
		// retry once, mirroring the neqo implementation, then leave the file in place
		if err := os.Remove(def.defenseStateFile); err != nil {
			log.Println("could not remove defense state file", def.defenseStateFile, "error:", err)
			return
		}
	}
	def.defenseStateFile = ""
}

func (def *chaffDefender) Stop() {
	log.Println("stopping defense, trace left in queue:", len(def.defenseSchedule))
}
