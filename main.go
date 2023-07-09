package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tmthrgd/go-hex"
	"go.etcd.io/bbolt"
)

var (
	refreshRPS  = flag.Float64("refresh-rps", 0.4, "Number of requests per second to make to keep the cache up-to-date")
	fillRPS     = flag.Float64("fill-rps", 100.0, "Number of requests per seconds to make to fill the cache initially")
	upstreamURL = flag.String("upstream-url", "https://api.pwnedpasswords.com/range", "Upstream URL the cache should pull from")
)

// Data structure (per range)
// Last Modified Unix Timestamp (8 bytes)
// Number of hashes (2 bytes)
// Per hash:
// First nibble contains occurrences if <16, otherwise zero
// 17.5 bytes of SHA-1 hash
// Packed varuints of all zero nibble occurrences

type Entry struct {
	// First nibble is reserved
	Hash        [18]byte
	Occurrences uint64
}

func ParseEntries(r io.Reader) ([]Entry, error) {
	var out []Entry
	s := bufio.NewScanner(r)
	for s.Scan() {
		hashRaw, occRaw, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		hash, err := hex.DecodeString("0" + hashRaw)
		if err != nil {
			return nil, fmt.Errorf("failed decoding hash: %w", err)
		}
		occ, err := strconv.ParseUint(occRaw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed parsing occurrences: %w", err)
		}
		var e Entry
		copy(e.Hash[:], hash)
		e.Occurrences = occ
		out = append(out, e)
	}
	return out, nil
}

type Range struct {
	LastModified time.Time
	Entries      []Entry
}

func (r *Range) Marshal() []byte {
	le := binary.LittleEndian
	var out []byte
	out = le.AppendUint64(out, uint64(r.LastModified.Unix()))
	out = le.AppendUint32(out, uint32(len(r.Entries)))
	var spilledOccurrences []uint64
	for _, e := range r.Entries {
		firstHashByte := e.Hash[0]
		firstHashByte &= 0x0F
		if e.Occurrences < 16 {
			firstHashByte |= byte(e.Occurrences) << 4
		} else {
			spilledOccurrences = append(spilledOccurrences, e.Occurrences)
		}
		out = append(out, firstHashByte)
		out = append(out, e.Hash[1:]...)
	}
	for _, spO := range spilledOccurrences {
		out = binary.AppendUvarint(out, spO)
	}
	return out
}

func UnmarshalRange(data []byte) (*Range, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("less than minimum 12 bytes")
	}
	lastModified := binary.LittleEndian.Uint64(data[:8])
	count := binary.LittleEndian.Uint32(data[8:12])
	data = data[12:]
	var spilled []uint32
	if len(data) < (18 * int(count)) {
		return nil, fmt.Errorf("not enough data for entry count")
	}
	entries := make([]Entry, 0, count)
	for i := uint32(0); i < count; i++ {
		var e Entry
		copy(e.Hash[:], data[18*i:18*i+18])
		occNibble := (e.Hash[0] & 0xF0) >> 4
		if occNibble == 0 {
			spilled = append(spilled, i)
		} else {
			e.Occurrences = uint64(occNibble)
		}
		entries = append(entries, e)
	}
	varintR := bytes.NewReader(data[18*count:])
	for i := 0; i < len(spilled); i++ {
		val, err := binary.ReadUvarint(varintR)
		if err != nil {
			return nil, fmt.Errorf("error reading spilled occurrences varint: %v", err)
		}
		entries[spilled[i]].Occurrences = uint64(val)
	}
	return &Range{
		LastModified: time.Unix(int64(lastModified), 0),
		Entries:      entries,
	}, nil
}

func (r *Range) WriteTo(w http.ResponseWriter) (int64, error) {
	w.Header().Set("last-modified", r.LastModified.Format(http.TimeFormat))
	buf := make([]byte, len(r.Entries)*50)
	bufPos := 0
	occBuf := make([]byte, 0, 10)
	for _, e := range r.Entries {
		hex.EncodeUpper(buf[bufPos:], e.Hash[:])
		buf[bufPos+35] = ':'
		bufPos += 36
		occBuf = strconv.AppendUint(occBuf, e.Occurrences, 10)
		bufPos += copy(buf[bufPos:], occBuf)
		occBuf = occBuf[:0]
		buf[bufPos] = '\n'
		bufPos++
	}
	w.Header().Set("content-length", strconv.Itoa(bufPos-1))
	w.WriteHeader(http.StatusOK)
	w.Write(buf[:bufPos-1])
	return int64(bufPos) - 1, nil
}

type response struct {
	prefix         [3]byte
	r              *Range
	retryAfterHint time.Time
	err            error
	duration       time.Duration
}

type Server struct {
	upstreamURL *url.URL
	db          *bbolt.DB
	hc          *http.Client

	updatePointer   uint32
	initialFillDone bool

	res chan response
}

func (s *Server) getRange(prefix [3]byte, lastModified time.Time) (*Range, time.Time, error) {
	prefix[2] &= 0xf0
	prefixStr := hex.EncodeToString(prefix[:])
	prefixStr = prefixStr[:len(prefixStr)-1] // trim final nibble
	req := http.Request{
		Method: "GET",
		URL:    s.upstreamURL.JoinPath(prefixStr),
		Host:   s.upstreamURL.Host,
		Header: http.Header{
			"user-agent": []string{"hibp-cached/0.1"},
		},
	}
	if !lastModified.IsZero() {
		req.Header.Set("if-modified-since", lastModified.UTC().Format(http.TimeFormat))
	}
	res, err := s.hc.Do(&req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("error requesting range: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		return nil, time.Time{}, nil
	}
	if res.StatusCode != http.StatusOK {
		var retryAfter time.Time
		retryAfterHdr := res.Header.Get("retry-after")
		if retryAfterHdr != "" {
			if sleepSeconds, err := strconv.ParseInt(retryAfterHdr, 10, 64); err == nil {
				sleep := time.Second * time.Duration(sleepSeconds)
				if sleep > 0 {
					retryAfter = time.Now().Add(time.Second * time.Duration(sleep))
				}
			} else if date, err := http.ParseTime(retryAfterHdr); err == nil {
				until := time.Until(date)
				if until > 0 {
					retryAfter = date
				}
			}
		}
		errMsg, _ := io.ReadAll(res.Body)
		return nil, retryAfter, fmt.Errorf("got HTTP %d: %q", res.StatusCode, errMsg)
	}

	var r Range
	r.LastModified, err = time.Parse(time.RFC1123, res.Header.Get("last-modified"))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("while parsing last-modified: %w", err)
	}

	r.Entries, err = ParseEntries(res.Body)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("while parsing entries: %w", err)
	}
	return &r, time.Time{}, nil
}

func (s *Server) makeRequest(pos uint32) {
	start := time.Now()
	prefix := [3]byte{byte(pos >> 12), byte(pos >> 4), byte(pos << 4)}
	var lastModified time.Time
	s.db.View(func(tx *bbolt.Tx) error {
		oldRange := tx.Bucket(rangesBucket).Get(prefix[:])
		if len(oldRange) >= 8 {
			lastModifiedRaw := binary.LittleEndian.Uint64(oldRange[:8])
			lastModified = time.Unix(int64(lastModifiedRaw), 0)
		}
		return nil
	})
	r, retryAfter, err := s.getRange(prefix, lastModified)
	s.res <- response{
		prefix:         prefix,
		r:              r,
		retryAfterHint: retryAfter,
		err:            err,
		duration:       time.Since(start),
	}
}

func prefixToPos(prefix [3]byte) uint32 {
	return uint32(prefix[0])<<12 | uint32(prefix[1])<<4 | uint32(prefix[2])>>4
}

var (
	fetchRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upstream_requests_total",
		Help: "Number of requests made to the HIBP upstream service by result",
	}, []string{"result"})
	fetchRequestsOk          = fetchRequests.WithLabelValues("ok")
	fetchRequestsError       = fetchRequests.WithLabelValues("error")
	fetchRequestsNotModified = fetchRequests.WithLabelValues("notmodified")
	position                 = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "fetch_position",
		Help: "Current position relative to the largest range",
	})
	checkpoints = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "checkpoints_total",
		Help: "Number of checkpoints/database commits by result",
	}, []string{"result"})
	checkpointsOk    = checkpoints.WithLabelValues("ok")
	checkpointsError = checkpoints.WithLabelValues("error")
	requestsM        = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
	}, []string{"code"})
	requestsSuccess    = requestsM.WithLabelValues("200")
	requestsNotFound   = requestsM.WithLabelValues("404")
	requestsBadRequest = requestsM.WithLabelValues("400")
	initialFillDoneM   = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "initial_fill_done",
		Help: "Indicates if the initial fill is done",
	})
	inFlightRequestBrake = promauto.NewCounter(prometheus.CounterOpts{
		Name: "in_flight_request_brake",
		Help: "Number of times the in-flight request brake was applied (may need lower RPS)",
	})
)

func (s *Server) fetchController() {
	issuePos := s.updatePointer
	completedSet := make(map[uint32]bool)
	updateIssueDuration := time.Duration(float64(time.Second) / *refreshRPS)
	fillIssueDuration := time.Duration(float64(time.Second) / *fillRPS)
	newRanges := make(map[[3]byte]Range)
	checkpointT := time.NewTicker(30 * time.Second)
	var requeue []uint32
	var inFlightRequests int
	var tickerDuration time.Duration = updateIssueDuration
	if !s.initialFillDone {
		tickerDuration = fillIssueDuration
	}
	var activeBackoff bool
	var disableFetching bool
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxElapsedTime = 0
	qpsT := time.NewTicker(tickerDuration)
	for {
		select {
		case <-qpsT.C:
			if disableFetching {
				continue
			}
			if activeBackoff {
				activeBackoff = false
				qpsT.Reset(tickerDuration)
			}
			// If the in-flight requests exceed the configured RPS,
			// the average request takes more than 1s which is indicative
			// of congestion. Add 1 to RPS to not break things at low
			// RPS.
			if inFlightRequests > int(*fillRPS)+1 {
				inFlightRequestBrake.Add(1)
				continue
			}
			inFlightRequests++
			if len(requeue) > 0 {
				go s.makeRequest(requeue[0])
				requeue = requeue[1:]
				continue
			}
			go s.makeRequest(issuePos)

			issuePos = (issuePos + 1) & ((1 << rangePrefixBits) - 1)
			if issuePos == 0 && !s.initialFillDone {
				s.initialFillDone = true
				initialFillDoneM.Set(1)
				tickerDuration = updateIssueDuration
				qpsT.Reset(tickerDuration)
			}
		case res := <-s.res:
			inFlightRequests--
			if res.err != nil {
				activeBackoff = true
				var waitTime time.Duration
				if res.retryAfterHint.IsZero() {
					// If no retry-after hint was given, use our own exponential backoff
					waitTime = expBackoff.NextBackOff()
				} else {
					waitTime = time.Until(res.retryAfterHint)
					// Clamp indicated retry-after to 1 hour
					if waitTime > 1*time.Hour {
						waitTime = 1 * time.Hour
					}
				}
				fetchRequestsError.Add(1)
				log.Printf("Backing off for %v due to: %v", waitTime, res.err)
				qpsT.Reset(waitTime)
				requeue = append(requeue, prefixToPos(res.prefix))
				continue
			}
			expBackoff.Reset()
			completedSet[prefixToPos(res.prefix)] = true
			for i := s.updatePointer; ; i++ {
				if completedSet[i] {
					s.updatePointer = i + 1
					delete(completedSet, i)
				} else {
					break
				}
			}
			position.Set(float64(s.updatePointer) / float64(uint32(1)<<rangePrefixBits))
			if res.r != nil {
				newRanges[res.prefix] = *res.r
				fetchRequestsOk.Add(1)
			} else {
				fetchRequestsNotModified.Add(1)
			}
		case <-checkpointT.C:
			err := s.db.Update(func(tx *bbolt.Tx) error {
				rawVal := make([]byte, 4)
				binary.LittleEndian.PutUint32(rawVal, s.updatePointer)
				if err := tx.Bucket(metaBucket).Put(updatePointerKey, rawVal); err != nil {
					return err
				}
				if s.initialFillDone {
					if err := tx.Bucket(metaBucket).Put(initialFillDoneKey, []byte{1}); err != nil {
						return err
					}
				}
				for k, v := range newRanges {
					// TODO: maybe not persist ranges before s.updatePointer?
					// Could save a tiny amount of work on restarts.
					if err := tx.Bucket(rangesBucket).Put(k[:], v.Marshal()); err != nil {
						return err
					}
					delete(newRanges, k)
				}
				return nil
			})
			if err != nil {
				// Disable fetching if we have database issues
				disableFetching = true
				log.Printf("Database checkpoint failed, disabling fetching until next successful checkpoint: %v", err)
				checkpointsError.Add(1)
			} else {
				disableFetching = false
				checkpointsOk.Add(1)
			}
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hashRaw := strings.TrimPrefix(req.URL.Path, "/range/")
	if hashRaw == req.URL.Path {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("unknown path"))
		requestsNotFound.Add(1)
		return
	}
	if len(hashRaw)&1 != 0 {
		hashRaw += "0"
	}
	hash, err := hex.DecodeString(hashRaw)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("prefix not valid hex"))
		requestsBadRequest.Add(1)
		return
	}
	if len(hash) < 3 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("hash prefix too short (needs at minimum 5 hex characters)"))
		return
	}
	prefix := hash[:3]
	prefix[2] &= 0xF0
	var r *Range
	s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket(rangesBucket).Get(prefix)
		if len(data) > 0 {
			r, err = UnmarshalRange(data)
		}
		return nil
	})
	if r == nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("prefix not available"))
		requestsNotFound.Add(1)
		return
	}
	r.WriteTo(w)
	requestsSuccess.Add(1)
}

func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	var ready bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		fillDone := tx.Bucket(metaBucket).Get(initialFillDoneKey)
		ready = fillDone != nil
		return nil
	})
	if ready && err == nil {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

var rangesBucket = []byte("ranges")
var metaBucket = []byte("meta")

var updatePointerKey = []byte("updateptr")
var initialFillDoneKey = []byte("initialFetchDone")

var rangePrefixBits = 20

func main() {
	flag.Parse()
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}
	db, err := bbolt.Open("data/cache.db", 0644, nil)
	if err != nil {
		log.Fatalf("error opening cache DB: %v", err)
	}

	upstreamURL, err := url.Parse(*upstreamURL)
	if err != nil {
		log.Fatalf("invalid upstream URL: %v", err)
	}

	var updatePtr uint32
	tx, err := db.Begin(true)
	if err != nil {
		log.Fatalf("error opening tx: %v", err)
	}
	metaB, err := tx.CreateBucketIfNotExists(metaBucket)
	if err != nil {
		log.Fatalf("error creating meta bucket: %v", err)
	}
	updatePtrRaw := metaB.Get(updatePointerKey)
	if len(updatePtrRaw) == 4 {
		updatePtr = binary.LittleEndian.Uint32(updatePtrRaw)
	}
	initialFillDone := metaB.Get(initialFillDoneKey)
	if initialFillDone == nil {
		initialFillDoneM.Set(0)
	} else {
		initialFillDoneM.Set(1)
	}

	_, err = tx.CreateBucketIfNotExists(rangesBucket)
	if err != nil {
		log.Fatalf("error creating ranges bucket: %v", err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatalf("error commiting setup transaction: %v", err)
	}
	s := Server{
		db: db,
		hc: &http.Client{
			Timeout: 5 * time.Second,
		},
		upstreamURL:     upstreamURL,
		updatePointer:   updatePtr,
		initialFillDone: initialFillDone != nil,
		res:             make(chan response, 128),
	}

	go http.ListenAndServe(":8080", &s)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/ready", s.readyHandler)
	go http.ListenAndServe(":8081", nil)

	if s.initialFillDone {
		log.Printf("Started hibp-cached on 8080, initial fill complete, ready to serve")
	} else {
		log.Printf("Started hibp-cached on 8080, filling cache")
	}

	s.fetchController()
}
