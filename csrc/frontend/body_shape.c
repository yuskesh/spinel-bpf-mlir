/* body_shape — G2's pure text functions: the shapes that the diagnostics quote. They take no progCtx, so the C tool that compares them with Go
 * (csrc/e189/h3_tool.c) links this file alone. */
#include "body_g2.h"

/* uprobe.go outputStrShape */
sr_str fe_output_str_shape(const fe_ring_decl *r)
{
	sr_buf b = {0};
	sr_puts(&b, "`r = ");
	sr_putstr(&b, r->const_name);
	sr_puts(&b, ".output_str(");
	sr_putstr(&b, r->record->const_name);
	sr_puts(&b, ".new(…), :<u8 array member>, ctx.str_arg(n), :<i64 status member>)` then `if r` (read `r.status` inside), or `_ = ");
	sr_putstr(&b, r->const_name);
	sr_puts(&b, ".output_str(…)`");
	return sr_bufstr(&b);
}

/* argv.go outputArgvShape */
sr_str fe_g2_output_argv_shape(const fe_ring_decl *r, sr_str src)
{
	sr_buf b = {0};
	sr_puts(&b, "`_ = ");
	sr_putstr(&b, r->const_name);
	sr_puts(&b, ".output_argv(");
	sr_putstr(&b, r->record->const_name);
	sr_puts(&b, ".new(…), :<u8 array member>, ");
	sr_putstr(&b, src);
	sr_puts(&b, ", :<i64 status member>, :<u32 index member>)`");
	return sr_bufstr(&b);
}
