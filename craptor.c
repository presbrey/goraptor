#include <stdlib.h>
#include <raptor2/raptor.h>
#include "craptor.h"
#include "_cgo_export.h"

void go_raptor_set_log_handler(raptor_world *world, void *user_data) {
    raptor_world_set_log_handler(world, user_data, (raptor_log_handler)GoRaptor_handle_log);
}

void go_raptor_parser_set_statement_handler(raptor_parser *parser, void *user_data) {
    raptor_parser_set_statement_handler(parser, user_data,
					(void (*)(void *, raptor_statement *))GoRaptor_handle_statement);
    
}

void go_raptor_parser_set_namespace_handler(raptor_parser *parser, void *user_data) {
    raptor_parser_set_namespace_handler(parser, user_data,
					(raptor_namespace_handler)GoRaptor_handle_namespace);
}
