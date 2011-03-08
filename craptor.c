#include <stdlib.h>
#include <raptor2/raptor.h>
#include "craptor.h"
#include "_cgo_export.h"

void go_raptor_parser_set_statement_handler(raptor_parser *parser, void *user_data) {
    raptor_parser_set_statement_handler(parser, user_data,
					(void (*)(void *, raptor_statement *))GoRaptor_handle_statement);
    
}
