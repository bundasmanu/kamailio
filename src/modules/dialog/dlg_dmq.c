/**
*
* Copyright (C) 2014 Alex Hermann (SpeakUp BV)
* Based on ht_dmq.c Copyright (C) 2013 Charles Chance (Sipcentric Ltd)
*
* This file is part of Kamailio, a free SIP server.
*
* Kamailio is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version
*
* Kamailio is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
*/

#include <string.h>
#include <time.h>

#include "../../core/mem/shm_mem.h"
#include "../dmq/dmq_funcs.h"
#include "../dmq/dmqnode.h"
#include "dlg_dmq.h"
#include "dlg_hash.h"
#include "dlg_profile.h"
#include "dlg_timer.h"
#include "dlg_var.h"

static str dlg_dmq_content_type = str_init("application/json");
static str dmq_200_rpl = str_init("OK");
static str dmq_400_rpl = str_init("Bad Request");
static str dmq_500_rpl = str_init("Server Internal Error");

dmq_api_t dlg_dmqb;
dmq_peer_t *dlg_dmq_peer = NULL;

int dmq_send_all_dlgs(dmq_node_t *dmq_node);
int dlg_dmq_request_sync();

extern int dlg_enable_stats;
extern int dlg_dmq_peer_liveness_enable;
extern int dlg_dmq_peer_liveness_interval;
extern int dlg_dmq_peer_liveness_failures;

typedef struct dlg_dmq_ping_cb_param
{
	str uri;
} dlg_dmq_ping_cb_param_t;

/*!
 * One row in the peer-liveness hash: which DMQ node URI created this replica
 * (dlg_iuid). The trailing _t marks a typedef name (same convention as
 * dlg_cell_t, size_t, etc.).
 */
typedef struct dlg_dmq_replica_owner
{
	dlg_iuid_t iuid;
	unsigned int owner_uri_len;
	struct dlg_dmq_replica_owner *next;
	char owner_uri[1];
} dlg_dmq_replica_owner_t;

typedef struct dlg_dmq_purge_q
{
	dlg_iuid_t iuid;
	struct dlg_dmq_purge_q *next;
} dlg_dmq_purge_q_t;

typedef struct dlg_uri_fail
{
	int failures;
	struct dlg_uri_fail *next;
	unsigned int ulen;
	char ustr[1];
} dlg_uri_fail_t;

#define DLG_DMQ_REPLICA_OWNER_BUCKETS 512
#define DLG_DMQ_URI_FAIL_BUCKETS 64

static gen_lock_t *dlg_dmq_live_lock = NULL;
static dlg_dmq_replica_owner_t
		*dlg_dmq_replica_owner_ht[DLG_DMQ_REPLICA_OWNER_BUCKETS];
static dlg_uri_fail_t *dlg_uri_fail_buckets[DLG_DMQ_URI_FAIL_BUCKETS];

static int dlg_dmq_ping_resp_f(
		struct sip_msg *msg, int code, dmq_node_t *node, void *param);
static unsigned int dlg_dmq_uri_hash(str *u);
static dlg_uri_fail_t *dlg_uri_fail_find_nolock(str *u);
static dlg_uri_fail_t *dlg_uri_fail_get_or_create_nolock(str *u);
static void dlg_uri_fail_unlink_nolock(str *u);
static int dlg_dmq_replica_owner_uri_match(dlg_dmq_replica_owner_t *r, str *o);
static void dlg_dmq_replica_register(dlg_cell_t *dlg, dmq_node_t *node);
static int dlg_dmq_replica_rm_unrefs(dlg_cell_t *dlg);
static void dlg_dmq_collect_purge_by_owner_nolock(
		str *owner, dlg_dmq_purge_q_t **pkg_head);
static void dlg_dmq_exec_purge_queue(dlg_dmq_purge_q_t *pkg_head);
static void dlg_dmq_peer_fail(str *u);
static void dlg_dmq_peer_ok(str *u);
static int dlg_dmq_send_ping(str *uri);

/**
* @brief add notification peer
*/
int dlg_dmq_initialize()
{
	dmq_peer_t not_peer;

	/* load the DMQ API */
	if(dmq_load_api(&dlg_dmqb) != 0) {
		LM_ERR("cannot load dmq api\n");
		return -1;
	} else {
		LM_DBG("loaded dmq api\n");
	}

	not_peer.callback = dlg_dmq_handle_msg;
	not_peer.init_callback = dlg_dmq_request_sync;
	not_peer.description.s = "dialog";
	not_peer.description.len = 6;
	not_peer.peer_id.s = "dialog";
	not_peer.peer_id.len = 6;
	dlg_dmq_peer = dlg_dmqb.register_dmq_peer(&not_peer);
	if(!dlg_dmq_peer) {
		LM_ERR("error in register_dmq_peer\n");
		goto error;
	} else {
		LM_DBG("dmq peer registered\n");
	}
	dlg_dmq_peer_liveness_init();
	return 0;
error:
	return -1;
}


int dlg_dmq_send(str *body, dmq_node_t *node)
{
	if(!dlg_dmq_peer) {
		LM_ERR("dlg_dmq_peer is null!\n");
		return -1;
	}
	if(node) {
		LM_DBG("sending dmq message ...\n");
		dlg_dmqb.send_message(
				dlg_dmq_peer, body, node, NULL, 1, &dlg_dmq_content_type);
	} else {
		LM_DBG("sending dmq broadcast...\n");
		dlg_dmqb.bcast_message(
				dlg_dmq_peer, body, 0, NULL, 1, &dlg_dmq_content_type);
	}
	return 0;
}


static unsigned int dlg_dmq_uri_hash(str *u)
{
	unsigned int i, h = 5381;

	for(i = 0; i < (unsigned int)u->len; i++)
		h = ((h << 5) + h) + (unsigned char)u->s[i];
	return h;
}

#define URI_FAIL_BUCKET(u) (dlg_dmq_uri_hash(u) % DLG_DMQ_URI_FAIL_BUCKETS)

static dlg_uri_fail_t *dlg_uri_fail_find_nolock(str *u)
{
	dlg_uri_fail_t *f;
	unsigned int b;

	b = URI_FAIL_BUCKET(u);
	for(f = dlg_uri_fail_buckets[b]; f; f = f->next) {
		if(f->ulen == (unsigned int)u->len
				&& memcmp(f->ustr, u->s, u->len) == 0)
			return f;
	}
	return NULL;
}

static dlg_uri_fail_t *dlg_uri_fail_get_or_create_nolock(str *u)
{
	dlg_uri_fail_t *f;
	int sz;
	unsigned int b;

	f = dlg_uri_fail_find_nolock(u);
	if(f)
		return f;
	sz = (int)(sizeof(dlg_uri_fail_t) - 1 + u->len);
	f = (dlg_uri_fail_t *)shm_malloc(sz);
	if(f == NULL)
		return NULL;
	memset(f, 0, sz);
	f->ulen = (unsigned int)u->len;
	memcpy(f->ustr, u->s, u->len);
	b = URI_FAIL_BUCKET(u);
	f->next = dlg_uri_fail_buckets[b];
	dlg_uri_fail_buckets[b] = f;
	return f;
}

static void dlg_uri_fail_unlink_nolock(str *u)
{
	dlg_uri_fail_t *f, **pf;
	unsigned int b;

	b = URI_FAIL_BUCKET(u);
	pf = &dlg_uri_fail_buckets[b];
	while((f = *pf) != NULL) {
		if(f->ulen == (unsigned int)u->len
				&& memcmp(f->ustr, u->s, u->len) == 0) {
			*pf = f->next;
			shm_free(f);
			return;
		}
		pf = &f->next;
	}
}

static int dlg_dmq_replica_owner_uri_match(dlg_dmq_replica_owner_t *r, str *o)
{
	return r->owner_uri_len == (unsigned int)o->len
		   && memcmp(r->owner_uri, o->s, o->len) == 0;
}

static unsigned int dlg_dmq_replica_owner_bidx(dlg_iuid_t *iuid)
{
	unsigned int x;

	x = iuid->h_entry ^ (iuid->h_id * 2654435761U);
	return x & (DLG_DMQ_REPLICA_OWNER_BUCKETS - 1);
}

static dlg_dmq_replica_owner_t *dlg_dmq_replica_owner_find_nolock(
		dlg_iuid_t *iuid)
{
	dlg_dmq_replica_owner_t *r;
	unsigned int b;

	b = dlg_dmq_replica_owner_bidx(iuid);
	for(r = dlg_dmq_replica_owner_ht[b]; r; r = r->next) {
		if(r->iuid.h_id == iuid->h_id && r->iuid.h_entry == iuid->h_entry)
			return r;
	}
	return NULL;
}

static void dlg_dmq_replica_register(dlg_cell_t *dlg, dmq_node_t *node)
{
	dlg_dmq_replica_owner_t *roe;
	dlg_iuid_t iuid;
	unsigned int b;
	int rsz;

	if(dlg_dmq_peer_liveness_enable == 0 || dlg_dmq_live_lock == NULL)
		return;
	if(node == NULL || node->orig_uri.s == NULL || node->orig_uri.len <= 0)
		return;
	if((dlg->iflags & DLG_IFLAG_DMQ_REPLICA) == 0)
		return;

	iuid.h_id = dlg->h_id;
	iuid.h_entry = dlg->h_entry;

	lock_get(dlg_dmq_live_lock);
	if(dlg_dmq_replica_owner_find_nolock(&iuid) != NULL) {
		lock_release(dlg_dmq_live_lock);
		return;
	}
	rsz = (int)(sizeof(dlg_dmq_replica_owner_t) - 1 + node->orig_uri.len);
	roe = (dlg_dmq_replica_owner_t *)shm_malloc(rsz);
	if(roe == NULL) {
		lock_release(dlg_dmq_live_lock);
		return;
	}
	memset(roe, 0, rsz);
	roe->iuid = iuid;
	roe->owner_uri_len = (unsigned int)node->orig_uri.len;
	memcpy(roe->owner_uri, node->orig_uri.s, node->orig_uri.len);
	b = dlg_dmq_replica_owner_bidx(&iuid);
	roe->next = dlg_dmq_replica_owner_ht[b];
	dlg_dmq_replica_owner_ht[b] = roe;
	lock_release(dlg_dmq_live_lock);
}

void dlg_dmq_replica_unmap(dlg_cell_t *dlg)
{
	dlg_iuid_t iuid;
	dlg_dmq_replica_owner_t *r, **pr;
	unsigned int b;

	if(dlg_dmq_peer_liveness_enable == 0 || dlg_dmq_live_lock == NULL)
		return;

	iuid.h_id = dlg->h_id;
	iuid.h_entry = dlg->h_entry;

	lock_get(dlg_dmq_live_lock);
	b = dlg_dmq_replica_owner_bidx(&iuid);
	pr = &dlg_dmq_replica_owner_ht[b];
	while((r = *pr) != NULL) {
		if(r->iuid.h_id == iuid.h_id && r->iuid.h_entry == iuid.h_entry) {
			*pr = r->next;
			shm_free(r);
			break;
		}
		pr = &r->next;
	}
	lock_release(dlg_dmq_live_lock);
}

static int dlg_dmq_replica_rm_unrefs(dlg_cell_t *dlg)
{
	int ret;
	int unref = 0;

	if(dlg->state == DLG_STATE_CONFIRMED || dlg->state == DLG_STATE_EARLY) {
		ret = remove_dialog_timer(&dlg->tl);
		if(ret == 0)
			unref++;
		else if(ret < 0)
			LM_CRIT("replica rm: unable to unlink timer dlg %p\n", dlg);
	}
	if(dlg->state == DLG_STATE_CONFIRMED_NA
			|| dlg->state == DLG_STATE_CONFIRMED) {
		if_update_stat(dlg_enable_stats, active_dlgs, -1);
	} else if(dlg->state == DLG_STATE_EARLY) {
		if_update_stat(dlg_enable_stats, early_dlgs, -1);
	}
	dlg->dflags |= DLG_FLAG_NEW;
	dlg->iflags &= ~(DLG_IFLAG_DMQ_SYNC | DLG_IFLAG_DMQ_REPLICA);
	unref++;
	return unref;
}

static void dlg_dmq_collect_purge_by_owner_nolock(
		str *owner, dlg_dmq_purge_q_t **pkg_head)
{
	dlg_dmq_replica_owner_t *r, **pr;
	dlg_dmq_purge_q_t *q;
	unsigned int i;

	for(i = 0; i < DLG_DMQ_REPLICA_OWNER_BUCKETS; i++) {
		pr = &dlg_dmq_replica_owner_ht[i];
		while((r = *pr) != NULL) {
			if(dlg_dmq_replica_owner_uri_match(r, owner)) {
				*pr = r->next;
				q = (dlg_dmq_purge_q_t *)pkg_malloc(sizeof(*q));
				if(q) {
					q->iuid = r->iuid;
					q->next = *pkg_head;
					*pkg_head = q;
				}
				shm_free(r);
				continue;
			}
			pr = &r->next;
		}
	}
}

static void dlg_dmq_exec_purge_queue(dlg_dmq_purge_q_t *pkg_head)
{
	dlg_dmq_purge_q_t *q, *qn;
	int unref;
	dlg_cell_t *dlg;
	dlg_entry_t *d_entry;

	for(q = pkg_head; q; q = qn) {
		qn = q->next;
		dlg = dlg_get_by_iuid(&q->iuid);
		if(dlg == NULL) {
			pkg_free(q);
			continue;
		}
		d_entry = &d_table->entries[dlg->h_entry];
		dlg_lock(d_table, d_entry);
		if((dlg->iflags & DLG_IFLAG_DMQ_REPLICA) == 0) {
			dlg_unlock(d_table, d_entry);
			dlg_unref(dlg, 1);
			pkg_free(q);
			continue;
		}
		LM_WARN("purging replica dlg [%u:%u] after peer liveness failures "
				"for owning DMQ node\n",
				dlg->h_entry, dlg->h_id);
		unref = dlg_dmq_replica_rm_unrefs(dlg);
		dlg_unlock(d_table, d_entry);
		dlg_unref(dlg, unref);
		pkg_free(q);
	}
}

static void dlg_dmq_peer_fail(str *u)
{
	dlg_uri_fail_t *f;
	dlg_dmq_purge_q_t *pkg_head = NULL;

	if(dlg_dmq_live_lock == NULL || u == NULL || u->len <= 0)
		return;
	lock_get(dlg_dmq_live_lock);
	f = dlg_uri_fail_get_or_create_nolock(u);
	if(f == NULL) {
		lock_release(dlg_dmq_live_lock);
		return;
	}
	f->failures++;
	LM_NOTICE("dialog DMQ peer [%.*s] ping fail count %d\n", STR_FMT(u),
			f->failures);
	if(f->failures >= dlg_dmq_peer_liveness_failures) {
		dlg_uri_fail_unlink_nolock(u);
		dlg_dmq_collect_purge_by_owner_nolock(u, &pkg_head);
		lock_release(dlg_dmq_live_lock);
		dlg_dmq_exec_purge_queue(pkg_head);
		return;
	}
	lock_release(dlg_dmq_live_lock);
}

static void dlg_dmq_peer_ok(str *u)
{
	dlg_uri_fail_t *f;

	if(dlg_dmq_live_lock == NULL || u == NULL || u->len <= 0)
		return;
	lock_get(dlg_dmq_live_lock);
	f = dlg_uri_fail_find_nolock(u);
	if(f)
		f->failures = 0;
	lock_release(dlg_dmq_live_lock);
}

static int dlg_dmq_ping_resp_f(
		struct sip_msg *msg, int code, dmq_node_t *node, void *param)
{
	dlg_dmq_ping_cb_param_t *pp = (dlg_dmq_ping_cb_param_t *)param;

	(void)msg;
	(void)node;
	if(pp == NULL)
		return 0;
	if(code == 200)
		dlg_dmq_peer_ok(&pp->uri);
	else
		dlg_dmq_peer_fail(&pp->uri);
	shm_free(pp);
	return 0;
}

static int dlg_dmq_send_ping(str *uri)
{
	srjson_doc_t jdoc;
	dmq_resp_cback_t cback;
	dmq_node_t *node;
	dlg_dmq_ping_cb_param_t *pp;
	int rsz;

	if(dlg_dmq_peer == NULL || dlg_dmqb.send_message == NULL)
		return -1;

	memset(&jdoc, 0, sizeof(jdoc));
	srjson_InitDoc(&jdoc, NULL);
	jdoc.root = srjson_CreateObject(&jdoc);
	if(jdoc.root == NULL) {
		LM_ERR("cannot create json for DMQ ping\n");
		return -1;
	}
	srjson_AddNumberToObject(&jdoc, jdoc.root, "action", DLG_DMQ_PING);
	jdoc.buf.s = srjson_PrintUnformatted(&jdoc, jdoc.root);
	if(jdoc.buf.s == NULL) {
		LM_ERR("cannot serialize DMQ ping\n");
		srjson_DestroyDoc(&jdoc);
		return -1;
	}
	jdoc.buf.len = strlen(jdoc.buf.s);

	node = dlg_dmqb.find_dmq_node_uri(uri);
	if(node == NULL) {
		LM_NOTICE(
				"dialog DMQ peer liveness: no node for [%.*s]\n", STR_FMT(uri));
		jdoc.free_fn(jdoc.buf.s);
		srjson_DestroyDoc(&jdoc);
		dlg_dmq_peer_fail(uri);
		return -1;
	}

	rsz = (int)(sizeof(dlg_dmq_ping_cb_param_t) + uri->len);
	pp = (dlg_dmq_ping_cb_param_t *)shm_malloc(rsz);
	if(pp == NULL) {
		jdoc.free_fn(jdoc.buf.s);
		srjson_DestroyDoc(&jdoc);
		return -1;
	}
	memset(pp, 0, rsz);
	pp->uri.len = uri->len;
	pp->uri.s = (char *)pp + sizeof(dlg_dmq_ping_cb_param_t);
	memcpy(pp->uri.s, uri->s, uri->len);

	cback.f = dlg_dmq_ping_resp_f;
	cback.param = pp;
	if(dlg_dmqb.send_message(
			   dlg_dmq_peer, &jdoc.buf, node, &cback, 1, &dlg_dmq_content_type)
			< 0) {
		shm_free(pp);
		jdoc.free_fn(jdoc.buf.s);
		srjson_DestroyDoc(&jdoc);
		return -1;
	}
	jdoc.free_fn(jdoc.buf.s);
	srjson_DestroyDoc(&jdoc);
	return 0;
}

void dlg_dmq_peer_liveness_init(void)
{
	if(dlg_dmq_peer_liveness_enable == 0)
		return;
	if(dlg_dmq_live_lock != NULL)
		return;
	dlg_dmq_live_lock = lock_alloc();
	if(dlg_dmq_live_lock == NULL) {
		LM_ERR("peer liveness lock alloc failed\n");
		return;
	}
	if(lock_init(dlg_dmq_live_lock) == 0) {
		LM_ERR("peer liveness lock init failed\n");
		lock_dealloc(dlg_dmq_live_lock);
		dlg_dmq_live_lock = NULL;
		return;
	}
	LM_INFO("dialog DMQ peer liveness: interval=%ds failures_before_purge=%d "
			"(pings use dmq node list)\n",
			dlg_dmq_peer_liveness_interval, dlg_dmq_peer_liveness_failures);
}

void dlg_dmq_peer_liveness_timer_exec(unsigned int ticks, void *param)
{
	typedef struct ping_uri
	{
		char *s;
		int len;
		struct ping_uri *next;
	} ping_uri_t;
	ping_uri_t *plist = NULL, *pu, *pun;
	dmq_node_t *node;

	(void)ticks;
	(void)param;

	if(dlg_dmq_peer_liveness_enable == 0 || dlg_dmq_peer_liveness_interval <= 0)
		return;
	if(dlg_dmq_live_lock == NULL || dlg_dmq_peer == NULL
			|| dmq_node_list == NULL)
		return;

	lock_get(&dmq_node_list->lock);
	for(node = dmq_node_list->nodes; node; node = node->next) {
		if(node->local || node->status != DMQ_NODE_ACTIVE)
			continue;
		if(node->orig_uri.s == NULL || node->orig_uri.len <= 0)
			continue;
		pu = (ping_uri_t *)pkg_malloc(sizeof(*pu) + node->orig_uri.len);
		if(pu == NULL)
			continue;
		pu->s = (char *)pu + sizeof(*pu);
		memcpy(pu->s, node->orig_uri.s, node->orig_uri.len);
		pu->len = node->orig_uri.len;
		pu->next = plist;
		plist = pu;
	}
	lock_release(&dmq_node_list->lock);

	for(pu = plist; pu; pu = pun) {
		str uri = {pu->s, pu->len};
		pun = pu->next;
		dlg_dmq_send_ping(&uri);
		pkg_free(pu);
	}
}


/**
* @brief ht dmq callback
*/
int dlg_dmq_handle_msg(
		struct sip_msg *msg, peer_reponse_t *resp, dmq_node_t *node)
{
	int content_length;
	str body;
	dlg_cell_t *dlg = NULL;
	int unref = 0;
	int ret;
	srjson_doc_t jdoc, prof_jdoc;
	srjson_t *it = NULL;

	dlg_dmq_action_t action = DLG_DMQ_NONE;
	dlg_iuid_t iuid = {0};
	str profiles = {0, 0}, callid = {0, 0}, tag1 = {0, 0}, tag2 = {0, 0},
		contact1 = {0, 0}, contact2 = {0, 0}, k = {0, 0}, v = {0, 0};
	str cseq1 = {0, 0}, cseq2 = {0, 0}, route_set1 = {0, 0},
		route_set2 = {0, 0}, from_uri = {0, 0}, to_uri = {0, 0},
		req_uri = {0, 0};
	unsigned int init_ts = 0, start_ts = 0, lifetime = 0;
	unsigned int state = 1;
	srjson_t *vj;
	int newdlg = 0;
	dlg_entry_t *d_entry = NULL;

	/* received dmq message */
	LM_DBG("dmq message received\n");

	if(!msg->content_length) {
		LM_ERR("no content length header found\n");
		goto invalid2;
	}
	content_length = get_content_length(msg);
	if(!content_length) {
		LM_DBG("content length is 0\n");
		goto invalid2;
	}

	body.s = get_body(msg);
	body.len = content_length;

	if(!body.s) {
		LM_ERR("unable to get body\n");
		goto error;
	}

	/* parse body */
	LM_DBG("body: %.*s\n", body.len, body.s);

	srjson_InitDoc(&jdoc, NULL);
	jdoc.buf = body;

	if(jdoc.root == NULL) {
		jdoc.root = srjson_Parse(&jdoc, jdoc.buf.s);
		if(jdoc.root == NULL) {
			LM_ERR("invalid json doc [[%s]]\n", jdoc.buf.s);
			goto invalid;
		}
	}

	for(it = jdoc.root->child; it; it = it->next) {
		if((it->string == NULL) || (strcmp(it->string, "vars") == 0))
			continue;

		LM_DBG("found field: %s\n", it->string);

		if(strcmp(it->string, "action") == 0) {
			action = SRJSON_GET_UINT(it);
		} else if(strcmp(it->string, "h_entry") == 0) {
			iuid.h_entry = SRJSON_GET_UINT(it);
		} else if(strcmp(it->string, "h_id") == 0) {
			iuid.h_id = SRJSON_GET_UINT(it);
		} else if(strcmp(it->string, "init_ts") == 0) {
			init_ts = SRJSON_GET_UINT(it);
		} else if(strcmp(it->string, "start_ts") == 0) {
			start_ts = SRJSON_GET_UINT(it);
		} else if(strcmp(it->string, "state") == 0) {
			state = SRJSON_GET_UINT(it);
		} else if(strcmp(it->string, "lifetime") == 0) {
			lifetime = SRJSON_GET_UINT(it);
		} else if(strcmp(it->string, "callid") == 0) {
			callid.s = it->valuestring;
			callid.len = strlen(callid.s);
		} else if(strcmp(it->string, "profiles") == 0) {
			profiles.s = it->valuestring;
			profiles.len = strlen(profiles.s);
		} else if(strcmp(it->string, "tag1") == 0) {
			tag1.s = it->valuestring;
			tag1.len = strlen(tag1.s);
		} else if(strcmp(it->string, "tag2") == 0) {
			tag2.s = it->valuestring;
			tag2.len = strlen(tag2.s);
		} else if(strcmp(it->string, "cseq1") == 0) {
			cseq1.s = it->valuestring;
			cseq1.len = strlen(cseq1.s);
		} else if(strcmp(it->string, "cseq2") == 0) {
			cseq2.s = it->valuestring;
			cseq2.len = strlen(cseq2.s);
		} else if(strcmp(it->string, "route_set1") == 0) {
			route_set1.s = it->valuestring;
			route_set1.len = strlen(route_set1.s);
		} else if(strcmp(it->string, "route_set2") == 0) {
			route_set2.s = it->valuestring;
			route_set2.len = strlen(route_set2.s);
		} else if(strcmp(it->string, "contact1") == 0) {
			contact1.s = it->valuestring;
			contact1.len = strlen(contact1.s);
		} else if(strcmp(it->string, "contact2") == 0) {
			contact2.s = it->valuestring;
			contact2.len = strlen(contact2.s);
		} else if(strcmp(it->string, "from_uri") == 0) {
			from_uri.s = it->valuestring;
			from_uri.len = strlen(from_uri.s);
		} else if(strcmp(it->string, "to_uri") == 0) {
			to_uri.s = it->valuestring;
			to_uri.len = strlen(to_uri.s);
		} else if(strcmp(it->string, "req_uri") == 0) {
			req_uri.s = it->valuestring;
			req_uri.len = strlen(req_uri.s);
		} else {
			LM_ERR("unrecognized field in json object\n");
		}
	}

	if(action == DLG_DMQ_PING) {
		srjson_DestroyDoc(&jdoc);
		resp->reason = dmq_200_rpl;
		resp->resp_code = 200;
		return 0;
	}

	dlg = dlg_get_by_iuid_mode(&iuid, 1);
	if(dlg) {
		LM_DBG("found dialog [%u:%u] at %p\n", iuid.h_entry, iuid.h_id, dlg);
		d_entry = &(d_table->entries[dlg->h_entry]);
		unref++;
	}

	switch(action) {
		case DLG_DMQ_UPDATE:
			LM_DBG("Updating dlg [%u:%u] with callid [%.*s]\n", iuid.h_entry,
					iuid.h_id, callid.len, callid.s);
			if(!dlg) {
				dlg = build_new_dlg(
						&callid, &from_uri, &to_uri, &tag1, &req_uri);
				if(!dlg) {
					LM_ERR("failed to build new dialog\n");
					goto error;
				}

				if(dlg->h_entry != iuid.h_entry) {
					LM_ERR("inconsistent hash data from peer: "
						   "make sure all Kamailio's use the same hash size\n");
					shm_free(dlg);
					dlg = NULL;
					goto error;
				}

				/* link the dialog */
				link_dlg(dlg, 0, 0);
				dlg_set_leg_info(dlg, &tag1, &route_set1, &contact1, &cseq1, 0);
				/* override generated h_id */
				dlg->h_id = iuid.h_id;
				/* prevent DB sync */
				dlg->dflags &= ~(DLG_FLAG_NEW | DLG_FLAG_CHANGED);
				dlg->iflags |= DLG_IFLAG_DMQ_SYNC | DLG_IFLAG_DMQ_REPLICA;
				dlg_dmq_replica_register(dlg, node);
				newdlg = 1;
			} else {
				/* remove existing profiles */
				if(dlg->profile_links != NULL) {
					destroy_linkers(dlg->profile_links);
					dlg->profile_links = NULL;
				}
			}

			dlg->init_ts = init_ts;
			dlg->start_ts = start_ts;

			vj = srjson_GetObjectItem(&jdoc, jdoc.root, "vars");
			if(vj != NULL) {
				for(it = vj->child; it; it = it->next) {
					k.s = it->string;
					k.len = strlen(k.s);
					v.s = it->valuestring;
					v.len = strlen(v.s);
					set_dlg_variable(dlg, &k, &v);
				}
			}
			/* add profiles */
			if(profiles.s != NULL) {
				srjson_InitDoc(&prof_jdoc, NULL);
				prof_jdoc.buf = profiles;
				dlg_json_to_profiles(dlg, &prof_jdoc);
				srjson_DestroyDoc(&prof_jdoc);
			}
			if(state == dlg->state) {
				break;
			}
			/* intentional fallthrough */

		case DLG_DMQ_STATE:
			if(!dlg) {
				LM_ERR("dialog [%u:%u] not found\n", iuid.h_entry, iuid.h_id);
				goto error;
			}
			if(state < dlg->state) {
				LM_NOTICE("Ignoring backwards state change on dlg [%u:%u]"
						  " with callid [%.*s] from state [%u] to state [%u]\n",
						iuid.h_entry, iuid.h_id, dlg->callid.len, dlg->callid.s,
						dlg->state, state);
				break;
			}
			LM_DBG("State update dlg [%u:%u] with callid [%.*s] from state [%u]"
				   " to state [%u]\n",
					iuid.h_entry, iuid.h_id, dlg->callid.len, dlg->callid.s,
					dlg->state, state);
			switch(state) {
				case DLG_STATE_EARLY:
					dlg->start_ts = start_ts;
					dlg->lifetime = lifetime;
					dlg_set_leg_info(
							dlg, &tag1, &route_set1, &contact1, &cseq1, 0);
					break;
				case DLG_STATE_CONFIRMED:
					dlg->start_ts = start_ts;
					dlg->lifetime = lifetime;
					dlg_set_leg_info(
							dlg, &tag1, &route_set1, &contact1, &cseq1, 0);
					dlg_set_leg_info(
							dlg, &tag2, &route_set2, &contact2, &cseq2, 1);
					if(insert_dlg_timer(&dlg->tl, dlg->lifetime) != 0) {
						LM_CRIT("Unable to insert dlg timer %p [%u:%u]\n", dlg,
								dlg->h_entry, dlg->h_id);
					} else {
						/* dialog pointer inserted in timer list */
						dlg_ref(dlg, 1);
					}
					break;
				case DLG_STATE_DELETED:
					if(dlg->state == DLG_STATE_CONFIRMED) {
						ret = remove_dialog_timer(&dlg->tl);
						if(ret == 0) {
							/* one extra unref due to removal from timer list */
							unref++;
						} else if(ret < 0) {
							LM_CRIT("unable to unlink the timer on dlg %p "
									"[%u:%u]\n",
									dlg, dlg->h_entry, dlg->h_id);
						}
					}

					/* remove dialog from profiles when no longer active */
					if(dlg->profile_links != NULL) {
						destroy_linkers(dlg->profile_links);
						dlg->profile_links = NULL;
					}

					/* prevent DB sync */
					dlg->dflags |= DLG_FLAG_NEW;
					/* keep dialog around for a bit, to prevent out-of-order
					 * syncs to reestablish the dlg */
					dlg->init_ts = ksr_time_uint(NULL, NULL);
					break;
				default:
					LM_ERR("unhandled state update to state %u\n", state);
					dlg_unref(dlg, unref);
					goto error;
			}
			if(newdlg == 1) {
				if(state == DLG_STATE_CONFIRMED_NA
						|| state == DLG_STATE_CONFIRMED) {
					if_update_stat(dlg_enable_stats, active_dlgs, 1);
				} else if(dlg->state == DLG_STATE_EARLY) {
					if_update_stat(dlg_enable_stats, early_dlgs, 1);
				}
			}
			dlg->state = state;
			break;

		case DLG_DMQ_RM:
			if(!dlg) {
				LM_DBG("dialog [%u:%u] not found\n", iuid.h_entry, iuid.h_id);
				goto error;
			}
			dlg_dmq_replica_unmap(dlg);
			LM_DBG("Removed dlg [%u:%u] with callid [%.*s] int state [%u]\n",
					iuid.h_entry, iuid.h_id, dlg->callid.len, dlg->callid.s,
					dlg->state);
			if(dlg->state == DLG_STATE_CONFIRMED
					|| dlg->state == DLG_STATE_EARLY) {
				ret = remove_dialog_timer(&dlg->tl);
				if(ret == 0) {
					/* one extra unref due to removal from timer list */
					unref++;
				} else if(ret < 0) {
					LM_CRIT("unable to unlink the timer on dlg %p [%u:%u]\n",
							dlg, dlg->h_entry, dlg->h_id);
				}
			}
			if(state == DLG_STATE_CONFIRMED_NA
					|| state == DLG_STATE_CONFIRMED) {
				if_update_stat(dlg_enable_stats, active_dlgs, -1);
			} else if(dlg->state == DLG_STATE_EARLY) {
				if_update_stat(dlg_enable_stats, early_dlgs, -1);
			}
			/* prevent DB sync */
			dlg->dflags |= DLG_FLAG_NEW;
			dlg->iflags &= ~(DLG_IFLAG_DMQ_SYNC | DLG_IFLAG_DMQ_REPLICA);
			unref++;
			break;

		case DLG_DMQ_SYNC:
			dmq_send_all_dlgs(0);
			break;

		case DLG_DMQ_NONE:
		case DLG_DMQ_PING:
			break;
	}
	if(dlg) {
		if(unref) {
			dlg_unref(dlg, unref);
		}
	}
	if(newdlg == 0 && d_entry != NULL) {
		dlg_unlock(d_table, d_entry);
	}

	srjson_DestroyDoc(&jdoc);
	resp->reason = dmq_200_rpl;
	resp->resp_code = 200;
	return 0;

invalid:
	srjson_DestroyDoc(&jdoc);
invalid2:
	resp->reason = dmq_400_rpl;
	resp->resp_code = 400;
	return 0;

error:
	if(newdlg == 0 && d_entry != NULL) {
		dlg_unlock(d_table, d_entry);
	}
	srjson_DestroyDoc(&jdoc);
	resp->reason = dmq_500_rpl;
	resp->resp_code = 500;
	return 0;
}


int dlg_dmq_request_sync()
{
	srjson_doc_t jdoc;

	LM_DBG("requesting sync from dmq peers\n");

	srjson_InitDoc(&jdoc, NULL);

	jdoc.root = srjson_CreateObject(&jdoc);
	if(jdoc.root == NULL) {
		LM_ERR("cannot create json root\n");
		goto error;
	}

	srjson_AddNumberToObject(&jdoc, jdoc.root, "action", DLG_DMQ_SYNC);
	jdoc.buf.s = srjson_PrintUnformatted(&jdoc, jdoc.root);
	if(jdoc.buf.s == NULL) {
		LM_ERR("unable to serialize data\n");
		goto error;
	}
	jdoc.buf.len = strlen(jdoc.buf.s);
	LM_DBG("sending serialized data %.*s\n", jdoc.buf.len, jdoc.buf.s);
	if(dlg_dmq_send(&jdoc.buf, 0) != 0) {
		goto error;
	}

	jdoc.free_fn(jdoc.buf.s);
	jdoc.buf.s = NULL;
	srjson_DestroyDoc(&jdoc);
	return 0;

error:
	if(jdoc.buf.s != NULL) {
		jdoc.free_fn(jdoc.buf.s);
		jdoc.buf.s = NULL;
	}
	srjson_DestroyDoc(&jdoc);
	return -1;
}


int dlg_dmq_replicate_action(dlg_dmq_action_t action, dlg_cell_t *dlg,
		int needlock, dmq_node_t *node)
{

	srjson_doc_t jdoc, prof_jdoc;
	dlg_var_t *var;

	LM_DBG("replicating action [%d] on [%u:%u] to dmq peers\n", action,
			dlg->h_entry, dlg->h_id);

	if(action == DLG_DMQ_UPDATE) {
		if(!node && (dlg->iflags & DLG_IFLAG_DMQ_SYNC)
				&& ((dlg->dflags & DLG_FLAG_CHANGED_PROF) == 0)) {
			LM_DBG("dlg not changed, no sync\n");
			return 1;
		}
	} else if((dlg->iflags & DLG_IFLAG_DMQ_SYNC) == 0) {
		LM_DBG("dlg not synced, no sync\n");
		return 1;
	}
	if(action == DLG_DMQ_STATE
			&& (dlg->state != DLG_STATE_CONFIRMED
					&& dlg->state != DLG_STATE_DELETED
					&& dlg->state != DLG_STATE_EARLY)) {
		LM_DBG("not syncing state %u\n", dlg->state);
		return 1;
	}

	srjson_InitDoc(&jdoc, NULL);

	jdoc.root = srjson_CreateObject(&jdoc);
	if(jdoc.root == NULL) {
		LM_ERR("cannot create json root\n");
		goto error;
	}

	if(needlock)
		dlg_lock(d_table, &(d_table->entries[dlg->h_entry]));

	srjson_AddNumberToObject(&jdoc, jdoc.root, "action", action);
	srjson_AddNumberToObject(&jdoc, jdoc.root, "h_entry", dlg->h_entry);
	srjson_AddNumberToObject(&jdoc, jdoc.root, "h_id", dlg->h_id);

	switch(action) {
		case DLG_DMQ_UPDATE:
			dlg->iflags |= DLG_IFLAG_DMQ_SYNC;
			dlg->dflags &= ~DLG_FLAG_CHANGED_PROF;
			srjson_AddNumberToObject(&jdoc, jdoc.root, "init_ts", dlg->init_ts);
			srjson_AddStrToObject(
					&jdoc, jdoc.root, "callid", dlg->callid.s, dlg->callid.len);

			srjson_AddStrToObject(&jdoc, jdoc.root, "from_uri", dlg->from_uri.s,
					dlg->from_uri.len);
			srjson_AddStrToObject(
					&jdoc, jdoc.root, "to_uri", dlg->to_uri.s, dlg->to_uri.len);
			srjson_AddStrToObject(&jdoc, jdoc.root, "req_uri", dlg->req_uri.s,
					dlg->req_uri.len);

			srjson_AddStrToObject(
					&jdoc, jdoc.root, "tag1", dlg->tag[0].s, dlg->tag[0].len);
			srjson_AddStrToObject(&jdoc, jdoc.root, "cseq1", dlg->cseq[0].s,
					dlg->cseq[0].len);
			srjson_AddStrToObject(&jdoc, jdoc.root, "route_set1",
					dlg->route_set[0].s, dlg->route_set[0].len);
			srjson_AddStrToObject(&jdoc, jdoc.root, "contact1",
					dlg->contact[0].s, dlg->contact[0].len);

			if(dlg->vars != NULL) {
				srjson_t *pj = NULL;
				pj = srjson_CreateObject(&jdoc);
				for(var = dlg->vars; var; var = var->next) {
					srjson_AddStrToObject(&jdoc, pj, var->key.s, var->value.s,
							var->value.len);
				}
				srjson_AddItemToObject(&jdoc, jdoc.root, "vars", pj);
			}

			if(dlg->profile_links) {
				srjson_InitDoc(&prof_jdoc, NULL);
				dlg_profiles_to_json(dlg, &prof_jdoc);
				if(prof_jdoc.buf.s != NULL) {
					LM_DBG("adding profiles: [%.*s]\n", prof_jdoc.buf.len,
							prof_jdoc.buf.s);
					srjson_AddStrToObject(&jdoc, jdoc.root, "profiles",
							prof_jdoc.buf.s, prof_jdoc.buf.len);
					prof_jdoc.free_fn(prof_jdoc.buf.s);
					prof_jdoc.buf.s = NULL;
				}
				srjson_DestroyDoc(&prof_jdoc);
			}
			/* intentional fallthrough */

		case DLG_DMQ_STATE:
			srjson_AddNumberToObject(&jdoc, jdoc.root, "state", dlg->state);
			switch(dlg->state) {
				case DLG_STATE_EARLY:
					srjson_AddNumberToObject(
							&jdoc, jdoc.root, "start_ts", dlg->start_ts);
					srjson_AddNumberToObject(
							&jdoc, jdoc.root, "lifetime", dlg->lifetime);

					if(action != DLG_DMQ_UPDATE) {
						srjson_AddStrToObject(&jdoc, jdoc.root, "tag1",
								dlg->tag[0].s, dlg->tag[0].len);
						srjson_AddStrToObject(&jdoc, jdoc.root, "cseq1",
								dlg->cseq[0].s, dlg->cseq[0].len);
						srjson_AddStrToObject(&jdoc, jdoc.root, "route_set1",
								dlg->route_set[0].s, dlg->route_set[0].len);
						srjson_AddStrToObject(&jdoc, jdoc.root, "contact1",
								dlg->contact[0].s, dlg->contact[0].len);
					}
					break;
				case DLG_STATE_CONFIRMED:
					srjson_AddNumberToObject(
							&jdoc, jdoc.root, "start_ts", dlg->start_ts);
					srjson_AddNumberToObject(
							&jdoc, jdoc.root, "lifetime", dlg->lifetime);

					if(action != DLG_DMQ_UPDATE) {
						srjson_AddStrToObject(&jdoc, jdoc.root, "tag1",
								dlg->tag[0].s, dlg->tag[0].len);
						srjson_AddStrToObject(&jdoc, jdoc.root, "cseq1",
								dlg->cseq[0].s, dlg->cseq[0].len);
						srjson_AddStrToObject(&jdoc, jdoc.root, "route_set1",
								dlg->route_set[0].s, dlg->route_set[0].len);
						srjson_AddStrToObject(&jdoc, jdoc.root, "contact1",
								dlg->contact[0].s, dlg->contact[0].len);
					}
					srjson_AddStrToObject(&jdoc, jdoc.root, "tag2",
							dlg->tag[1].s, dlg->tag[1].len);
					srjson_AddStrToObject(&jdoc, jdoc.root, "cseq2",
							dlg->cseq[1].s, dlg->cseq[1].len);
					srjson_AddStrToObject(&jdoc, jdoc.root, "route_set2",
							dlg->route_set[1].s, dlg->route_set[1].len);
					srjson_AddStrToObject(&jdoc, jdoc.root, "contact2",
							dlg->contact[1].s, dlg->contact[1].len);
					break;
				case DLG_STATE_DELETED:
					//dlg->iflags &= ~DLG_IFLAG_DMQ_SYNC;
					break;
				default:
					LM_DBG("not syncing state %u\n", dlg->state);
			}
			break;

		case DLG_DMQ_RM:
			srjson_AddNumberToObject(&jdoc, jdoc.root, "state", dlg->state);
			dlg->iflags &= ~(DLG_IFLAG_DMQ_SYNC | DLG_IFLAG_DMQ_REPLICA);
			break;

		case DLG_DMQ_NONE:
		case DLG_DMQ_SYNC:
		case DLG_DMQ_PING:
			break;
	}
	if(needlock)
		dlg_unlock(d_table, &(d_table->entries[dlg->h_entry]));

	jdoc.buf.s = srjson_PrintUnformatted(&jdoc, jdoc.root);
	if(jdoc.buf.s == NULL) {
		LM_ERR("unable to serialize data\n");
		goto error;
	}
	jdoc.buf.len = strlen(jdoc.buf.s);
	LM_DBG("sending serialized data %.*s\n", jdoc.buf.len, jdoc.buf.s);
	if(dlg_dmq_send(&jdoc.buf, node) != 0) {
		goto error;
	}

	jdoc.free_fn(jdoc.buf.s);
	jdoc.buf.s = NULL;
	srjson_DestroyDoc(&jdoc);
	return 0;

error:
	if(jdoc.buf.s != NULL) {
		jdoc.free_fn(jdoc.buf.s);
		jdoc.buf.s = NULL;
	}
	srjson_DestroyDoc(&jdoc);
	return -1;
}


int dmq_send_all_dlgs(dmq_node_t *dmq_node)
{
	int index;
	dlg_entry_t *entry;
	dlg_cell_t *dlg;

	LM_DBG("sending all dialogs \n");

	for(index = 0; index < d_table->size; index++) {
		/* lock the whole entry */
		entry = &d_table->entries[index];
		dlg_lock(d_table, entry);

		for(dlg = entry->first; dlg != NULL; dlg = dlg->next) {
			dlg->dflags |= DLG_FLAG_CHANGED_PROF;
			dlg_dmq_replicate_action(DLG_DMQ_UPDATE, dlg, 0, dmq_node);
		}

		dlg_unlock(d_table, entry);
	}

	return 0;
}
