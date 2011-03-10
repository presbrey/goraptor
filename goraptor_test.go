package goraptor

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"testing"
	"time"
)

func codec(s *Statement) (err os.Error) {
	subj := s.Subject
	pred := s.Predicate
	obj := s.Object

	sbuf, err := subj.GobEncode()
	if err != nil {
		errs := fmt.Sprintf("GobEncode(%s): %s", subj, err)
		err = os.NewError(errs)
		return
	}
	pbuf, err := pred.GobEncode()
	if err != nil {
		errs := fmt.Sprintf("GobEncode(%s): %s", pred, err)
		err = os.NewError(errs)
		return
	}
	obuf, err := obj.GobEncode()
	if err != nil {
		errs := fmt.Sprintf("GobEncode(%s): %s", obj, err)
		err = os.NewError(errs)
		return
	}

	subj2, err := TermDecode(sbuf)
	if err != nil {
		errs := fmt.Sprintf("TermDecode(%s): %s", subj, err)
		err = os.NewError(errs)
		return
	}
	pred2, err := TermDecode(pbuf)
	if err != nil {
		errs := fmt.Sprintf("TermDecode(%s): %s", pred, err)
		err = os.NewError(errs)
		return
	}
	obj2, err := TermDecode(obuf)
	if err != nil {
		errs := fmt.Sprintf("TermDecode(%s): %s", obj, err)
		err = os.NewError(errs)
		return
	}

	if !subj.Equals(subj2) {
		errs := fmt.Sprintf("%s != %s", subj, subj2)
		err = os.NewError(errs)
		return
	}
	if !pred.Equals(pred2) {
		errs := fmt.Sprintf("%s != %s", pred, pred2)
		err = os.NewError(errs)
		return
	}
	if !obj.Equals(obj2) {
		errs := fmt.Sprintf("%s != %s", obj, obj2)
		err = os.NewError(errs)
		return
	}

	s2 := &Statement{subj2, pred2, obj2, nil}
	if !s.Equals(s2) {
		errs := fmt.Sprintf("%s != %s", s, s2)
		err = os.NewError(errs)
		return
	}

	ssbuf, err := s.GobEncode()
	if err != nil {
		errs := fmt.Sprintf("Statement.GobEncode(%s): %s", s, err)
		err = os.NewError(errs)
		return
	}

	s3 := &Statement{}
	err = s3.GobDecode(ssbuf)
	if err != nil {
		errs := fmt.Sprintf("Statement.GobDecode(%s): %s", s, err)
		err = os.NewError(errs)
		return
	}
	if !s.Equals(s3) {
		errs := fmt.Sprintf("%s != %s", s, s3)
		err = os.NewError(errs)
		return
	}
	return
}

func TestRaptorParseFile(t *testing.T) {
	parser := NewParser("rdfxml")
	defer parser.Free()

	count := 0
	exp := 153
	out := parser.ParseFile("foaf.rdf", "")
	for {
		s := <-out
		if closed(out) {
			break
		}
		count++
		err := codec(s)
		if err != nil {
			t.Fatal(err)
		}
	}
	if count != exp {
		t.Errorf("Expected %d statements got %d\n", count, exp)
	}
}

func TestRaptorParseUri(t *testing.T) {
	parser := NewParser("guess")
	defer parser.Free()

	count := 0
	out := parser.ParseUri("http://www.w3.org/People/Berners-Lee/card", "")
	for {
		s := <-out
		if closed(out) {
			break
		}
		count++
		err := codec(s)
		if err != nil {
			t.Fatal(err)
		}
	}
	if count == 0 {
		t.Errorf("Expected to find some statements... maybe there is no network?")
	}
}

func TestTiger(t *testing.T) {
	parser := NewParser("ntriples")
	ch := parser.ParseFile("TGR06001.nt", "")
	count := 0
	start := time.Nanoseconds()
	for {
		s := <-ch
		if closed(ch) {
			break
		}
		_ = fmt.Sprintf("%s", s)
		count++
		if count%10000 == 0 {
			end := time.Nanoseconds()
			dt := uint64(count) * 1e9 / uint64(end-start)
			log.Printf("%d statements loaded at %d tps", count, dt)
		}
	}
	end := time.Nanoseconds()
	dt := uint64(count) * 1e9 / uint64(end-start)
	log.Printf("%d statements loaded at %d tps", count, dt)
}

func benchParse() {
	parser := NewParser("rdfxml")
	out := parser.ParseFile("foaf.rdf", "")
	for {
		s := <-out
		if closed(out) {
			break
		}
		codec(s)
		_ = s
	}
	parser.Free()
}

func BenchmarkCodecMemory(b *testing.B) {

	for i := 0; i < 10000; i++ {
		log.Printf("start alloc: %d total: %d heap: %d",
			runtime.MemStats.Alloc,
			runtime.MemStats.TotalAlloc,
			runtime.MemStats.HeapAlloc)
		benchParse()
		Reset()
		runtime.GC()
		log.Printf("end alloc: %d total: %d heap: %d",
			runtime.MemStats.Alloc,
			runtime.MemStats.TotalAlloc,
			runtime.MemStats.HeapAlloc)

	}
}
