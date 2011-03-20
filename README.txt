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


FUNCTIONS

func GoRaptor_handle_statement(user_data unsafe.Pointer, rsp unsafe.Pointer)
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

type Parser struct {
    // contains unexported fields
}

func NewParser(name string) *Parser

func (p *Parser) Free()

func (p *Parser) ParseFile(filename string, base_uri string) chan *Statement

func (p *Parser) ParseUri(uri string, base_uri string) chan *Statement

type Statement struct {
    Subject, Predicate, Object, Graph Term
}

func (s *Statement) Equals(other *Statement) (eq bool)

func (s *Statement) GobDecode(buf []byte) (err os.Error)

func (s *Statement) GobEncode() (buf []byte, err os.Error)

func (s *Statement) N3() string

func (s *Statement) String() string

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
