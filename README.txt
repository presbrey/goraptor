PACKAGE

package goraptor
import "bitbucket.org/ww/goraptor"

Go bindings for the raptor RDF parser / seraliser.

Written in 2011 by William Waites <ww@styx.org>.
Distributed under the terms of the LGPL version 2.1 or
any later version.

To build you must have raptor version 2 or greater
installed. You can get raptor from http://librdf.org/raptor/

Example usage:

	parser := goraptor.NewParser("guess")
	defer parser.Free()

	ch := parser.ParseUri("www.w3.org/People/Berners-Lee/card", "")
        for {
                statement, ok := <-ch
                if ! ok {
                        break
                }
		// do something with statement
        }

The basic datatype is the Term which represents an RDF URI,
blank node or literal value. Terms are grouped into compound
Statement datatypes which contain four Terms, Subject, Predicate,
Object and Graph. Both of these datatypes are memory managed
by Go but can be converted back and forth to/from raptor's
internal representation. The datatypes support a compact
binary encoding for use with the gob package.

There is no support for the serialiser yet.


CONSTANTS

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


VARIABLES

var LogLevels map[int]string
For convenience a mapping of log levels to human readable strings.

var ParserSyntax map[string]*Syntax
global map of parser name to parser description

var SerializerSyntax map[string]*Syntax
global map of serializer name to serializer description


FUNCTIONS

func GoRaptor_handle_log(user_data, msgp unsafe.Pointer)
For internal use only, callback for log messages from C. Arranges
that the configured log handler will be called.
export GoRaptor_handle_log

func GoRaptor_handle_namespace(user_data, nsp unsafe.Pointer)
for internal use only. callback from the C namespace handler for the parser
export GoRaptor_handle_namespace

func GoRaptor_handle_statement(user_data, rsp unsafe.Pointer)
for internal use only. callback from the C statement handler for the parser
export GoRaptor_handle_statement

func Reset()


TYPES

type Blank string

func (b *Blank) Equals(other Term) (eq bool)

func (b *Blank) GobDecode(buf []byte) (err os.Error)

func (b *Blank) GobEncode() (buf []byte, err os.Error)

func (b *Blank) N3() (s string)

func (b *Blank) String() string

func (b *Blank) Type() uint8

type Literal struct {
    // contains unexported fields
}

func (l *Literal) Equals(other Term) (eq bool)

func (l *Literal) GobDecode(buf []byte) (err os.Error)

func (l *Literal) GobEncode() (buf []byte, err os.Error)

func (l *Literal) N3() (s string)

func (l *Literal) String() string

func (l *Literal) Type() uint8

type LogHandler func(int, string)
LogHandler functions are called from parsers and serialisers. They
are colled with a log level integer and a log message string. The
default implementation pretty prints the level and the string using
the generic log package

type NamespaceHandler func(prefix string, uri string)
A handler function to be called when the parser encounters
a namespace.

type Parser struct {
    // contains unexported fields
}

func NewParser(name string) *Parser

func (p *Parser) Free()

func (p *Parser) ParseFile(filename string, base_uri string) chan *Statement
parse a local file

func (p *Parser) ParseUri(uri string, base_uri string) chan *Statement
parse a network resource

func (p *Parser) SetLogHandler(handler LogHandler)
set the log handler which by default will use the generic log package

func (p *Parser) SetNamespaceHandler(handler NamespaceHandler)
set the namespace handler which is by default a noop

type Serializer struct {
    // contains unexported fields
}

func NewSerializer(name string) *Serializer

func (s *Serializer) Add(statement *Statement) (err os.Error)

func (s *Serializer) AddN(ch chan *Statement)

func (s *Serializer) Free()

func (s *Serializer) Serialize(ch chan *Statement, base_uri string) (str string, err os.Error)

func (s *Serializer) SetFile(fp *os.File, base_uri string) (err os.Error)

func (s *Serializer) SetLogHandler(handler LogHandler)
set the log handler which by default will use the generic log package

func (s *Serializer) SetNamespace(prefix, uri string)

type Statement struct {
    Subject, Predicate, Object, Graph Term
}

func (s *Statement) Equals(other *Statement) (eq bool)

func (s *Statement) GobDecode(buf []byte) (err os.Error)

func (s *Statement) GobEncode() (buf []byte, err os.Error)

func (s *Statement) N3() string

func (s *Statement) String() string

type Syntax struct {
    Label    string
    Name     string
    MimeType string
}
struct holding some details of available parsers or serializers

func (s *Syntax) String() string

type Term interface {
    Type() uint8
    N3() string
    String() string
    Equals(Term) bool
    GobEncode() ([]byte, os.Error)
    GobDecode([]byte) os.Error
    // contains unexported methods
}

func TermDecode(buf []byte) (t Term, err os.Error)

type Uri string

func (u *Uri) Equals(other Term) (eq bool)

func (u *Uri) GobDecode(buf []byte) (err os.Error)

func (u *Uri) GobEncode() (buf []byte, err os.Error)

func (u *Uri) N3() (s string)

func (u *Uri) String() string

func (u *Uri) Type() uint8


SUBDIRECTORIES

	.hg
