/*
Go bindings for the raptor RDF parser / seraliser.

Written in 2011 by William Waites <ww@styx.org>.
Distributed under the terms of the LGPL version 2.1 or
any later version.

To build you must have raptor version 2 or greater
installed. You can get raptor from http://librdf.org/raptor/

Example usage:

    parser := goraptor.NewParser("guess")
    defer parser.Free()

    ch := parser.ParseUri("http://www.w3.org/People/Berners-Lee/card", "")
    for {
        statement, ok := <-ch
        if ! ok {
            break
        }

        // do something with statement
     }

Serialisers are analogous. For example to read in one serialisation
and write in another, preserving namespaces:

    parser := goraptor.NewParser("guess")
    defer parser.Free()

    serializer := goraptor.NewSerializer("turtle")
    defer serializer.Free()

    parser.SetNamespaceHandler(func(pfx, uri string) { serializer.SetNamespace(pfx, uri) })

    statements := parser.ParseUri("http://www.w3.org/People/Berners-Lee/card", "")
    str, err := serializer.Serialize(statements, "")

    fmt.Print(str)

The step of setting the namespace handler is strictly unnecessary
and is basically used so that the output is more aesthetically
pleasing. If instead of serializing to a string you want to serialize
to a file, you can do instead:

    fp := os.Open("output.ttl", os.O_WRONLY, 0644)
    serializer.SetFile(fp, "")
    serializer.AddN(statements)

Note that it is strictly necessary to free the serializer for only then
can it be guaranteed that any buffered output is written to the
destination file.

The basic datatype is the Term which represents an RDF URI,
blank node or literal value. Terms are grouped into compound
Statement datatypes which contain four Terms, Subject, Predicate,
Object and Graph. Both of these datatypes are memory managed
by Go but can be converted back and forth to/from raptor's
internal representation. The datatypes support a compact
binary encoding for use with the gob package.

*/
package goraptor

// #cgo CFLAGS: -I/usr/local/include/raptor2 -I/usr/include/raptor2
// #cgo LDFLAGS: -L/usr/local/lib -lraptor2
// #include <stdlib.h>
// #include <string.h>
// #include <strings.h>
// #include <raptor.h>
// #include "craptor.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

const (
	RAPTOR_TERM_TYPE_URI     = C.RAPTOR_TERM_TYPE_URI
	RAPTOR_TERM_TYPE_BLANK   = C.RAPTOR_TERM_TYPE_BLANK
	RAPTOR_TERM_TYPE_LITERAL = C.RAPTOR_TERM_TYPE_LITERAL
)

const (
	RAPTOR_LOG_LEVEL_NONE  = C.RAPTOR_LOG_LEVEL_NONE
	RAPTOR_LOG_LEVEL_TRACE = C.RAPTOR_LOG_LEVEL_TRACE
	RAPTOR_LOG_LEVEL_DEBUG = C.RAPTOR_LOG_LEVEL_DEBUG
	RAPTOR_LOG_LEVEL_INFO  = C.RAPTOR_LOG_LEVEL_INFO
	RAPTOR_LOG_LEVEL_WARN  = C.RAPTOR_LOG_LEVEL_WARN
	RAPTOR_LOG_LEVEL_ERROR = C.RAPTOR_LOG_LEVEL_ERROR
	RAPTOR_LOG_LEVEL_FATAL = C.RAPTOR_LOG_LEVEL_FATAL
)

var world_lock sync.Mutex
var global_world *C.raptor_world

// struct holding some details of available parsers or serializers
type Syntax struct {
	Label    string
	Name     string
	MimeType string
}

func (s *Syntax) String() string {
	str := fmt.Sprintf("%s - %s", s.Name, s.Label)
	if len(s.MimeType) > 0 {
		str += fmt.Sprintf(" (%s)", s.MimeType)
	}
	return str
}

// global map of parser name to parser description
var ParserSyntax map[string]*Syntax

// global map of serializer name to serializer description
var SerializerSyntax map[string]*Syntax

func init() {
	LogLevels = make(map[int]string)
	LogLevels[RAPTOR_LOG_LEVEL_NONE] = "NONE"
	LogLevels[RAPTOR_LOG_LEVEL_TRACE] = "TRACE"
	LogLevels[RAPTOR_LOG_LEVEL_DEBUG] = "DEBUG"
	LogLevels[RAPTOR_LOG_LEVEL_INFO] = "INFO"
	LogLevels[RAPTOR_LOG_LEVEL_WARN] = "WARN"
	LogLevels[RAPTOR_LOG_LEVEL_ERROR] = "ERROR"
	LogLevels[RAPTOR_LOG_LEVEL_FATAL] = "FATAL"
	Reset()

	ParserSyntax = make(map[string]*Syntax)
	for i := 0; ; i++ {
		syndesc := C.raptor_world_get_parser_description(global_world, C.uint(i))
		if syndesc == nil {
			break
		}
		syntax := &Syntax{}
		syntax.Label = C.GoString(syndesc.label)
		syntax.Name = C.GoString(*syndesc.names)
		if syndesc.mime_types != nil {
			syntax.MimeType = C.GoString((*syndesc.mime_types).mime_type)
		}
		ParserSyntax[syntax.Name] = syntax
	}

	SerializerSyntax = make(map[string]*Syntax)
	for i := 0; ; i++ {
		syndesc := C.raptor_world_get_serializer_description(global_world, C.uint(i))
		if syndesc == nil {
			break
		}
		syntax := &Syntax{}
		syntax.Label = C.GoString(syndesc.label)
		syntax.Name = C.GoString(*syndesc.names)
		if syndesc.mime_types != nil {
			syntax.MimeType = C.GoString((*syndesc.mime_types).mime_type)
		}
		SerializerSyntax[syntax.Name] = syntax
	}
}

func Reset() {
	world_lock.Lock()
	if global_world != nil {
		C.raptor_free_world(global_world)
	}
	global_world = C.raptor_new_world_internal(C.RAPTOR_VERSION)
	world_lock.Unlock()
}

type Term interface {
	Type() uint8
	N3() string
	String() string
	Equals(Term) bool
	GobEncode() ([]byte, error)
	GobDecode([]byte) error
	raptor_term() *C.raptor_term
}

func term_to_string(term *C.raptor_term) (s string) {
	n3string := C.raptor_term_to_string(term)
	s = C.GoString((*C.char)(unsafe.Pointer(n3string)))
	C.free(unsafe.Pointer(n3string))
	return
}

func term_to_go(term *C.raptor_term) (t Term) {
	switch {
	case term == nil:
		return
	case term._type == C.RAPTOR_TERM_TYPE_URI:
		t = uri_from_term(term)
	case term._type == C.RAPTOR_TERM_TYPE_BLANK:
		t = blank_from_term(term)
	case term._type == C.RAPTOR_TERM_TYPE_LITERAL:
		t = literal_from_term(term)
	}
	return
}

func TermDecode(buf []byte) (t Term, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	switch {
	case buf[0] == RAPTOR_TERM_TYPE_URI:
		u := new(Uri)
		err = u.GobDecode(buf)
		if err == nil {
			t = u
		}
	case buf[0] == RAPTOR_TERM_TYPE_BLANK:
		b := new(Blank)
		err = b.GobDecode(buf)
		if err == nil {
			t = b
		}
	case buf[0] == RAPTOR_TERM_TYPE_LITERAL:
		l := Literal{}
		err = l.GobDecode(buf)
		if err == nil {
			t = &l
		}
	}
	return
}

type Uri string

func uri_from_term(term *C.raptor_term) Term {
	ruri := *(**C.raptor_uri)(unsafe.Pointer(&term.value))
	uristr := C.GoString((*C.char)(unsafe.Pointer(C.raptor_uri_as_string(ruri))))
	uri := Uri(uristr)
	return &uri

}
func (u *Uri) raptor_term() (term *C.raptor_term) {
	uri := string(*u)
	ustr := (*C.uchar)(unsafe.Pointer(C.CString(uri)))
	term = C.raptor_new_term_from_counted_uri_string(global_world, ustr, C.size_t(len(uri)))
	C.free(unsafe.Pointer(ustr))
	return
}
func (u *Uri) Type() uint8 {
	return RAPTOR_TERM_TYPE_URI
}
func (u *Uri) N3() (s string) {
	world_lock.Lock()
	term := u.raptor_term()
	s = term_to_string(term)
	C.raptor_free_term(term)
	world_lock.Unlock()
	return
}
func (u *Uri) String() string {
	return string(*u)
}
func (u *Uri) Equals(other Term) (eq bool) {
	world_lock.Lock()
	uterm := u.raptor_term()
	oterm := other.raptor_term()
	if C.raptor_term_equals(uterm, oterm) != 0 {
		eq = true
	}
	C.raptor_free_term(oterm)
	C.raptor_free_term(uterm)
	world_lock.Unlock()
	return
}
func (u *Uri) GobEncode() (buf []byte, err error) {
	ustr := string(*u)
	w := bytes.NewBuffer(make([]byte, 0, len(ustr)+1))
	w.WriteByte(RAPTOR_TERM_TYPE_URI)
	w.WriteString(ustr)
	buf = w.Bytes()
	return
}
func (u *Uri) GobDecode(buf []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	if buf[0] != RAPTOR_TERM_TYPE_URI {
		errs := fmt.Sprintf("Uri.GobDecode: expected type %d in buffer got %d",
			RAPTOR_TERM_TYPE_URI, buf[0])
		err = errors.New(errs)
		return
	}
	*u = Uri(buf[1:])
	return
}

type Blank string

func blank_from_term(term *C.raptor_term) Term {
	rblank := (*C.raptor_term_blank_value)(unsafe.Pointer(&term.value))
	blankstr := C.GoString((*C.char)(unsafe.Pointer(rblank.string)))
	blank := Blank(blankstr)
	return &blank

}
func (b *Blank) raptor_term() (term *C.raptor_term) {
	bstr := string(*b)
	nodeid := (*C.uchar)(unsafe.Pointer(C.CString(bstr)))
	term = C.raptor_new_term_from_counted_blank(global_world, nodeid, C.size_t(len(bstr)))
	C.free(unsafe.Pointer(nodeid))
	return
}
func (b *Blank) Type() uint8 {
	return RAPTOR_TERM_TYPE_BLANK
}
func (b *Blank) N3() (s string) {
	world_lock.Lock()
	term := b.raptor_term()
	s = term_to_string(term)
	C.raptor_free_term(term)
	world_lock.Unlock()
	return
}
func (b *Blank) String() string {
	return string(*b)
}
func (b *Blank) Equals(other Term) (eq bool) {
	world_lock.Lock()
	bterm := b.raptor_term()
	oterm := other.raptor_term()
	if C.raptor_term_equals(bterm, oterm) != 0 {
		eq = true
	}
	C.raptor_free_term(oterm)
	C.raptor_free_term(bterm)
	world_lock.Unlock()
	return
}
func (b *Blank) GobEncode() (buf []byte, err error) {
	bstr := string(*b)
	w := bytes.NewBuffer(make([]byte, 0, len(bstr)+1))
	w.WriteByte(RAPTOR_TERM_TYPE_BLANK)
	w.WriteString(bstr)
	buf = w.Bytes()
	return
}
func (b *Blank) GobDecode(buf []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	if buf[0] != RAPTOR_TERM_TYPE_BLANK {
		errs := fmt.Sprintf("Blank.GobDecode: expected type %d in buffer got %d",
			RAPTOR_TERM_TYPE_BLANK, buf[0])
		err = errors.New(errs)
		return
	}
	*b = Blank(buf[1:])
	return
}

type Literal struct {
	Value    string
	Lang     string
	Datatype string
}

func literal_from_term(term *C.raptor_term) Term {
	literal := Literal{}
	lval := (*C.raptor_term_literal_value)(unsafe.Pointer(&term.value))
	literal.Value = C.GoString((*C.char)(unsafe.Pointer(lval.string)))
	if int(lval.language_len) != 0 {
		literal.Lang = C.GoString((*C.char)(unsafe.Pointer(lval.language)))
	}
	if lval.datatype != nil {
		dtstr := C.raptor_uri_as_string(lval.datatype)
		literal.Datatype = C.GoString((*C.char)(unsafe.Pointer(dtstr)))
	}
	return &literal
}

func (l *Literal) raptor_term() (term *C.raptor_term) {
	value := (*C.uchar)(unsafe.Pointer(C.CString(l.Value)))
	llen := len(l.Value)
	var lang *C.uchar
	langlen := len(l.Lang)
	if langlen != 0 {
		lang = (*C.uchar)(unsafe.Pointer(C.CString(l.Lang)))
	}
	var datatype *C.raptor_uri
	if len(l.Datatype) != 0 {
		dtstr := (*C.uchar)(unsafe.Pointer(C.CString(l.Datatype)))
		datatype = C.raptor_new_uri(global_world, dtstr)
		C.free(unsafe.Pointer(dtstr))
	}
	term = C.raptor_new_term_from_counted_literal(global_world,
		value, C.size_t(llen), datatype, lang, C.uchar(langlen))
	if datatype != nil {
		C.raptor_free_uri(datatype)
	}
	if lang != nil {
		C.free(unsafe.Pointer(lang))
	}
	C.free(unsafe.Pointer(value))
	return
}
func (l *Literal) Type() uint8 {
	return RAPTOR_TERM_TYPE_LITERAL
}
func (l *Literal) N3() (s string) {
	world_lock.Lock()
	term := l.raptor_term()
	s = term_to_string(l.raptor_term())
	C.raptor_free_term(term)
	world_lock.Unlock()
	return
}
func (l *Literal) String() string {
	return l.Value
}
func (l *Literal) Equals(other Term) (eq bool) {
	world_lock.Lock()
	lterm := l.raptor_term()
	oterm := other.raptor_term()
	if C.raptor_term_equals(lterm, oterm) != 0 {
		eq = true
	}
	C.raptor_free_term(oterm)
	C.raptor_free_term(lterm)
	world_lock.Unlock()
	return
}

const (
	has_language = 1 << iota
	has_datatype
)

func (l *Literal) GobEncode() (buf []byte, err error) {
	var flags byte
	size := 2
	vlen := len(l.Value)
	size += 2 + vlen
	langlen := len(l.Lang)
	if langlen != 0 {
		flags |= has_language
		size += 1 + langlen
	}
	dtlen := len(l.Datatype)
	if dtlen != 0 {
		flags |= has_datatype
		size += 2 + dtlen
	}
	w := bytes.NewBuffer(make([]byte, 0, size))
	w.WriteByte(RAPTOR_TERM_TYPE_LITERAL)
	w.WriteByte(flags)
	sbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(sbuf, uint16(vlen))
	w.Write(sbuf)
	w.WriteString(l.Value)
	if langlen != 0 {
		w.WriteByte(byte(langlen))
		w.WriteString(l.Lang)
	}
	if dtlen != 0 {
		binary.BigEndian.PutUint16(sbuf, uint16(dtlen))
		w.Write(sbuf)
		w.WriteString(l.Datatype)
	}
	buf = w.Bytes()
	return
}
func (l *Literal) GobDecode(buf []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	if buf[0] != RAPTOR_TERM_TYPE_LITERAL {
		errs := fmt.Sprintf("Literal.GobDecode: expected type %d in buffer got %d",
			RAPTOR_TERM_TYPE_LITERAL, buf[0])
		err = errors.New(errs)
		return
	}
	*l = Literal{}
	flags := buf[1]
	offset := 2
	llen := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	l.Value = string(buf[offset : offset+llen])
	offset += int(llen)

	if flags&has_language != 0 {
		langlen := int(buf[offset])
		offset++
		l.Lang = string(buf[offset : offset+langlen])
		offset += int(langlen)
	}

	if flags&has_datatype != 0 {
		dtlen := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
		l.Datatype = string(buf[offset : offset+dtlen])
	}
	return
}

type Statement struct {
	Subject, Predicate, Object, Graph Term
}

func (s *Statement) raptor_statement() (statement *C.raptor_statement) {
	var rs, rp, ro, rg *C.raptor_term
	if s.Subject != nil {
		rs = s.Subject.raptor_term()
	}
	if s.Predicate != nil {
		rp = s.Predicate.raptor_term()
	}
	if s.Object != nil {
		ro = s.Object.raptor_term()
	}
	if s.Graph != nil {
		rg = s.Graph.raptor_term()
	}
	statement = C.raptor_new_statement_from_nodes(global_world, rs, rp, ro, rg)
	if statement == nil {
		if rs != nil {
			C.raptor_free_term(rs)
		}
		if rp != nil {
			C.raptor_free_term(rp)
		}
		if ro != nil {
			C.raptor_free_term(ro)
		}
		if rg != nil {
			C.raptor_free_term(rg)
		}
	}
	return
}
func (s *Statement) N3() string {
	var sn3, pn3, on3, gn3 string
	if s.Subject != nil {
		sn3 = s.Subject.N3()
	}
	if s.Predicate != nil {
		pn3 = s.Predicate.N3()
	}
	if s.Object != nil {
		on3 = s.Object.N3()
	}
	if s.Graph != nil {
		gn3 = s.Graph.N3()
	}
	return fmt.Sprintf("%s %s %s %s.", sn3, pn3, on3, gn3)
}
func (s *Statement) String() string {
	return s.N3()
}
func (s *Statement) Equals(other *Statement) (eq bool) {
	world_lock.Lock()
	rs := s.raptor_statement()
	ro := other.raptor_statement()
	if C.raptor_statement_equals(rs, ro) != 0 {
		eq = true
	}
	C.raptor_free_statement(rs)
	C.raptor_free_statement(ro)
	world_lock.Unlock()
	return
}
func (s *Statement) GobEncode() (buf []byte, err error) {
	var sbuf, pbuf, obuf, gbuf []byte
	var slen, plen, olen, glen int
	if s.Subject != nil {
		sbuf, err = s.Subject.GobEncode()
		if err != nil {
			return
		}
		slen = len(sbuf)
	}
	if s.Predicate != nil {
		pbuf, err = s.Predicate.GobEncode()
		if err != nil {
			return
		}
		plen = len(pbuf)
	}
	if s.Object != nil {
		obuf, err = s.Object.GobEncode()
		if err != nil {
			return
		}
		olen = len(obuf)
	}
	if s.Graph != nil {
		gbuf, err = s.Graph.GobEncode()
		if err != nil {
			return
		}
		glen = len(gbuf)
	}

	buf = make([]byte, 8, 8+len(sbuf)+len(pbuf)+len(obuf)+len(gbuf))

	binary.BigEndian.PutUint16(buf[0:2], uint16(slen))
	binary.BigEndian.PutUint16(buf[2:4], uint16(plen))
	binary.BigEndian.PutUint16(buf[4:6], uint16(olen))
	binary.BigEndian.PutUint16(buf[6:8], uint16(glen))

	buf = append(buf, sbuf...)
	buf = append(buf, pbuf...)
	buf = append(buf, obuf...)
	buf = append(buf, gbuf...)

	return
}

func (s *Statement) GobDecode(buf []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	*s = Statement{}

	slen := int(binary.BigEndian.Uint16(buf[0:2]))
	plen := int(binary.BigEndian.Uint16(buf[2:4]))
	olen := int(binary.BigEndian.Uint16(buf[4:6]))
	glen := int(binary.BigEndian.Uint16(buf[6:8]))
	offset := 8

	if slen != 0 {
		s.Subject, err = TermDecode(buf[offset : offset+slen])
		if err != nil {
			return
		}
		offset += slen
	}

	if plen != 0 {
		s.Predicate, err = TermDecode(buf[offset : offset+plen])
		if err != nil {
			return
		}
		offset += plen
	}

	if olen != 0 {
		s.Object, err = TermDecode(buf[offset : offset+olen])
		if err != nil {
			return
		}
		offset += olen
	}

	if glen != 0 {
		s.Graph, err = TermDecode(buf[offset : offset+glen])
		if err != nil {
			return
		}
	}
	return
}

/*
LogHandler functions are called from parsers and serialisers. They
are colled with a log level integer and a log message string. The
default implementation pretty prints the level and the string using
the generic log package
*/
type LogHandler func(int, string)

/*
For convenience a mapping of log levels to human readable strings.
*/
var LogLevels map[int]string

// For internal use only, callback for log messages from C. Arranges
// that the configured log handler will be called.
//export GoRaptor_handle_log
func GoRaptor_handle_log(user_data, msgp unsafe.Pointer) {
	message := (*C.raptor_log_message)(msgp)
	text := C.GoString(message.text)
	handler := (*LogHandler)(user_data)
	(*handler)(int(message.level), text)
}

type Parser struct {
	mutex             sync.Mutex
	world             *C.raptor_world
	parser            *C.raptor_parser
	namespace_handler NamespaceHandler
	out               chan *Statement
}

func NewParser(name string) *Parser {
	cname := C.CString(name)
	world := C.raptor_new_world_internal(C.RAPTOR_VERSION)
	rparser := C.raptor_new_parser(world, cname)
	C.raptor_parser_set_option(rparser, C.RAPTOR_OPTION_LOAD_EXTERNAL_ENTITIES, nil, 0)
	parser := &Parser{world: world, parser: rparser}
	C.free(unsafe.Pointer(cname))
	C.go_raptor_parser_set_statement_handler(rparser, unsafe.Pointer(parser))
	C.go_raptor_parser_set_namespace_handler(rparser, unsafe.Pointer(parser))
	parser.SetLogHandler(func(level int, text string) { log.Printf("[%s] %s", LogLevels[level], text) })
	parser.SetNamespaceHandler(func(prefix, uri string) {})
	runtime.SetFinalizer(parser, func(p *Parser) {
		if p != nil {
			p.Free()
		}
	})
	return parser
}

func (p *Parser) Free() {
	p.mutex.Lock()
	C.raptor_free_parser(p.parser)
	p.parser = nil
	C.raptor_free_world(p.world)
	p.world = nil
	p.mutex.Unlock()
}

// set the log handler which by default will use the generic log package
func (p *Parser) SetLogHandler(handler LogHandler) {
	C.go_raptor_set_log_handler(p.world, unsafe.Pointer(&handler))
}

/*
A handler function to be called when the parser encounters
a namespace.
*/
type NamespaceHandler func(prefix string, uri string)

// set the namespace handler which is by default a noop
func (p *Parser) SetNamespaceHandler(handler NamespaceHandler) {
	p.namespace_handler = handler
}

// parse a local file
func (p *Parser) ParseFile(filename string, base_uri string) chan *Statement {
	p.out = make(chan *Statement)
	go func() {
		p.mutex.Lock()

		cfilename := C.CString(filename)
		uri_string := C.raptor_uri_filename_to_uri_string(cfilename)
		C.free(unsafe.Pointer(cfilename))

		uri := C.raptor_new_uri(p.world, uri_string)
		C.raptor_free_memory(unsafe.Pointer(uri_string))

		var buri *C.raptor_uri
		if len(base_uri) == 0 {
			buri = C.raptor_uri_copy(uri)
		} else {
			cbase_uri := C.CString(base_uri)
			buri = C.raptor_new_uri(p.world, (*C.uchar)(unsafe.Pointer(cbase_uri)))
			C.free(unsafe.Pointer(cbase_uri))
		}

		C.raptor_parser_parse_file(p.parser, uri, buri)

		C.raptor_free_uri(uri)
		C.raptor_free_uri(buri)

		p.mutex.Unlock()

		close(p.out)
	}()
	return p.out
}

// parse a network resource
func (p *Parser) ParseUri(uri string, base_uri string) chan *Statement {
	p.out = make(chan *Statement)
	go func() {
		p.mutex.Lock()

		curi := C.CString(uri)
		ruri := C.raptor_new_uri(p.world, (*C.uchar)(unsafe.Pointer(curi)))
		C.free(unsafe.Pointer(curi))

		var buri *C.raptor_uri
		if len(base_uri) == 0 {
			buri = C.raptor_uri_copy(ruri)
		} else {
			cbase_uri := C.CString(base_uri)
			buri = C.raptor_new_uri(p.world, (*C.uchar)(unsafe.Pointer(cbase_uri)))
			C.free(unsafe.Pointer(cbase_uri))
		}

		C.raptor_parser_parse_uri(p.parser, ruri, buri)

		C.raptor_free_uri(ruri)
		C.raptor_free_uri(buri)

		p.mutex.Unlock()

		close(p.out)
	}()
	return p.out
}

// Parse RDF data from an io.Reader
func (p *Parser) Parse(reader io.Reader, base_uri string) chan *Statement {
	p.out = make(chan *Statement)
	go func() {
		p.mutex.Lock()

		cbase_uri := C.CString(base_uri)
		buri := C.raptor_new_uri(p.world, (*C.uchar)(unsafe.Pointer(cbase_uri)))
		C.free(unsafe.Pointer(cbase_uri))

		if C.raptor_parser_parse_start(p.parser, buri) == 0 {
			buf := make([]byte, 8192)
			for {
				n, err := reader.Read(buf)
				if err != nil {
					break
				}
				C.raptor_parser_parse_chunk(p.parser, (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(n), 0)
			}
			C.raptor_parser_parse_chunk(p.parser, nil, 0, 1)
		}

		p.mutex.Unlock()
		close(p.out)
	}()
	return p.out
}

//for internal use only. callback from the C statement handler for the parser
//export GoRaptor_handle_statement
func GoRaptor_handle_statement(user_data, rsp unsafe.Pointer) {
	// must be called with parser.lock held
	parser := (*Parser)(user_data)
	rs := (*C.raptor_statement)(rsp)
	s := Statement{}
	s.Subject = term_to_go(rs.subject)
	s.Predicate = term_to_go(rs.predicate)
	s.Object = term_to_go(rs.object)
	s.Graph = term_to_go(rs.graph)
	parser.out <- &s
}

//for internal use only. callback from the C namespace handler for the parser
//export GoRaptor_handle_namespace
func GoRaptor_handle_namespace(user_data, nsp unsafe.Pointer) {
	parser := (*Parser)(user_data)
	ns := (*C.raptor_namespace)(nsp)
	cprefix := C.raptor_namespace_get_prefix(ns)
	curi := C.raptor_namespace_get_uri(ns)
	prefix := C.GoString((*C.char)(unsafe.Pointer(cprefix)))
	uri := C.GoString((*C.char)(unsafe.Pointer(C.raptor_uri_as_string(curi))))
	parser.namespace_handler(prefix, uri)
}

type Serializer struct {
	mutex      sync.Mutex
	world      *C.raptor_world
	serializer *C.raptor_serializer
	running    bool
	fh         *C.FILE
}

func NewSerializer(name string) *Serializer {
	cname := C.CString(name)
	world := C.raptor_new_world_internal(C.RAPTOR_VERSION)
	rserializer := C.raptor_new_serializer(world, cname)
	C.raptor_serializer_set_option(rserializer, C.RAPTOR_OPTION_WRITE_BASE_URI, nil, 0)
	serializer := &Serializer{world: world, serializer: rserializer}
	C.free(unsafe.Pointer(cname))
	serializer.SetLogHandler(func(level int, text string) { log.Printf("[%s] %s", LogLevels[level], text) })
	runtime.SetFinalizer(serializer, func(s *Serializer) {
		if s != nil {
			s.Free()
		}
	})
	return serializer
}

func (s *Serializer) Free() {
	s.mutex.Lock()
	if s.running {
		s.end()
	}
	C.raptor_free_serializer(s.serializer)
	s.serializer = nil
	C.raptor_free_world(s.world)
	s.world = nil
	s.mutex.Unlock()
}

func (s *Serializer) end() {
	C.raptor_serializer_serialize_end(s.serializer)
	if s.fh != nil {
		C.fflush(s.fh)
	}
	s.running = false
}

// set the log handler which by default will use the generic log package
func (s *Serializer) SetLogHandler(handler LogHandler) {
	s.mutex.Lock()
	C.go_raptor_set_log_handler(s.world, unsafe.Pointer(&handler))
	s.mutex.Unlock()
}

func (s *Serializer) SetNamespace(prefix, uri string) {
	cprefix := C.CString(prefix)
	curistr := C.CString(uri)
	curi := C.raptor_new_uri(s.world, (*C.uchar)(unsafe.Pointer(curistr)))
	C.raptor_serializer_set_namespace(s.serializer, curi, (*C.uchar)(unsafe.Pointer(cprefix)))
	C.free(unsafe.Pointer(cprefix))
	C.free(unsafe.Pointer(curistr))
}

func (s *Serializer) SetFile(fp *os.File, base_uri string) (err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	mode := C.CString("w")
	fh, err := C.fdopen(C.int(fp.Fd()), mode) // do something better with mode?
	C.free(unsafe.Pointer(mode))
	if err != nil {
		return
	}
	s.fh = fh

	var buri *C.raptor_uri
	if len(base_uri) > 0 {
		cbase_uri := C.CString(base_uri)
		buri = C.raptor_new_uri(s.world, (*C.uchar)(unsafe.Pointer(cbase_uri)))
		C.free(unsafe.Pointer(cbase_uri))
		defer C.raptor_free_uri(buri)
	}
	if C.raptor_serializer_start_to_file_handle(s.serializer, buri, s.fh) != 0 {
		err = errors.New("C.raptor_serializer_start_to_file_handle failed")
		return
	}

	s.running = true

	return
}

func (s *Serializer) add(statement *Statement) (err error) {
	rs := statement.raptor_statement()
	if C.raptor_serializer_serialize_statement(s.serializer, rs) != 0 {
		err = errors.New("raptor_serializer_serialize_statement failed")
	}
	C.raptor_free_statement(rs)
	return
}

func (s *Serializer) Add(statement *Statement) (err error) {
	s.mutex.Lock()
	err = s.add(statement)
	s.mutex.Unlock()
	return
}

func (s *Serializer) AddN(ch chan *Statement) {
	s.mutex.Lock()
	for {
		statement, ok := <-ch
		if !ok {
			break
		}
		s.add(statement)
	}
	s.mutex.Unlock()
}

func (s *Serializer) StartStream(file *os.File, base_uri string) (err error) {
	var buri *C.raptor_uri

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		err = errors.New("serializer already running")
		return
	}
	s.running = true

	if len(base_uri) > 0 {
		cbase_uri := C.CString(base_uri)
		buri = C.raptor_new_uri(s.world, (*C.uchar)(unsafe.Pointer(cbase_uri)))
		C.free(unsafe.Pointer(cbase_uri))
		// XXX LEAK defer C.raptor_free_uri(buri)
	}

	cwb := C.CString("wb")
	fh, err := C.fdopen(C.int(file.Fd()), cwb)
	C.free(unsafe.Pointer(cwb))
	if fh == nil {
		err = errors.New("fdopen: ...")
		return
	}
	s.fh = fh

	if C.raptor_serializer_start_to_file_handle(s.serializer, buri, s.fh) != 0 {
		err = errors.New("raptor_serializer_start_to_file_handle failed")
		return
	}

	return
}

func (s *Serializer) EndStream() (err error) {
	s.end()
	return
}

func (s *Serializer) Serialize(ch chan *Statement, base_uri string) (str string, err error) {
	var cstrp unsafe.Pointer
	var cstrlen C.size_t
	var buri *C.raptor_uri

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		err = errors.New("serializer already running")
		return
	}
	s.running = true

	if len(base_uri) > 0 {
		cbase_uri := C.CString(base_uri)
		buri = C.raptor_new_uri(s.world, (*C.uchar)(unsafe.Pointer(cbase_uri)))
		C.free(unsafe.Pointer(cbase_uri))
		defer C.raptor_free_uri(buri)
	}

	if C.raptor_serializer_start_to_string(s.serializer, buri, &cstrp, &cstrlen) != 0 {
		err = errors.New("raptor_serializer_start_to_string failed")
		return
	}

	for {
		statement, ok := <-ch
		if !ok {
			break
		}
		err = s.add(statement)
		if err != nil {
			log.Print(err)
			break
		}
	}

	s.end()

	if cstrp == nil {
		err = errors.New("serialising failed")
		return
	}
	str = C.GoString((*C.char)(cstrp))
	C.free(cstrp)

	return
}
