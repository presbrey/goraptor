#ifndef GO_RAPTOR_H
#define GO_RAPTOR_H

extern void go_raptor_set_log_handler(raptor_world *, void *);
extern void go_raptor_parser_set_statement_handler(raptor_parser *, void *);
extern void go_raptor_parser_set_namespace_handler(raptor_parser *parser, void *user_data);

#endif
