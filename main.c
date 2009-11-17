/*

jj a FIFO and filesystem based Jabber/XMPP client.

Copyright (C) 2009 Petteri Klemola

jj is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

jj is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.

For more information about jj visit http://23.fi/jj .

*/

#include <loudmouth/loudmouth.h>
#include <glib/gprintf.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#define _GNU_SOURCE

#define JJ_NS_MUC "http://jabber.org/protocol/muc"
#define JJ_NS_VER "jabber:iq:version"
#define JJ_NS_DISCO "http://jabber.org/protocol/disco#info"

#define JJ_SUCCESS 0

#define jj_error(...) fprintf (stderr, __VA_ARGS__)
#define jj_printf(...) fprintf (stdout, __VA_ARGS__)

#ifdef DEBUG
#define jj_debug(format, ...) jj_printf("%s " format, __FUNCTION__, __VA_ARGS__)
#else
#define jj_debug(...) {}
#endif

static GMainLoop *jj_main_loop;
static GMainContext *jj_context;
static LmConnection *jj_connection;


typedef struct {
  gchar *name;
  GSList *users;
  gboolean join_complete;
} jj_muc_t;


static struct user {
  gchar *username;
  gchar *password;
  gchar *server;
  gchar *muc_username;
  gchar *base_path;
  gchar *server_in;
  gchar *server_out;
  GSList *mucs;
} jj_user;


typedef struct {
  GSource *source;
  char *path;
} jj_pipe_data_t;


/* some prototypes */
static void jj_make_named_pipe(gchar *path, gboolean muc);
static void jj_make_named_pipe_1(gchar *path);


static jj_muc_t *jj_user_muc_find(gchar *muc) {
  jj_muc_t *umuc;
  GSList *i;

  for (i = jj_user.mucs; i != NULL; i = i->next) {
    umuc = (jj_muc_t*) i->data;
    if (strcmp(umuc->name, muc) == 0) {
      return umuc;
    }
  }
  return NULL;
}


static void jj_user_muc_add(gchar *muc) {
  jj_muc_t *umuc;

  umuc = g_malloc(sizeof(jj_muc_t));
  umuc->name = g_strdup(muc);
  umuc->users = NULL;
  jj_user.mucs = g_slist_append(jj_user.mucs, umuc);
}


static GSList *jj_user_muc_remove(char *muc) {
  jj_muc_t *umuc;

  umuc = jj_user_muc_find(muc);
  if (umuc != NULL) {
    /* found muc */
    g_slist_foreach(umuc->users, (GFunc) g_free, NULL);
    g_slist_free(umuc->users);
    g_free(umuc->name);
    return g_slist_remove(jj_user.mucs, umuc);
  }
  return jj_user.mucs;
}


static void jj_user_muc_add_user(gchar *muc, gchar *user) {
  jj_muc_t *umuc;

  umuc = jj_user_muc_find(muc);
  if (umuc != NULL) {
    umuc->users = g_slist_append(umuc->users, g_strdup(user));
    jj_debug("added user=%s\n", user);
  }
}


static void jj_user_muc_remove_user(gchar *muc, gchar *user) {
  jj_muc_t *umuc;

  umuc = jj_user_muc_find(muc);
  if (umuc != NULL) {
    umuc->users = g_slist_remove(umuc->users, user);
    jj_debug("removed user=%s\n", user);
    g_free(user);
  }
}


static gchar *jj_user_muc_find_user(gchar *muc, gchar *user) {
  jj_muc_t *umuc;
  GSList *i;

  umuc = jj_user_muc_find(muc);
  if (umuc != NULL) {
    for (i = umuc->users; i != NULL; i = i->next) {
      if (strcmp((gchar *)i->data, user) == 0) {
        return (gchar *) i->data;
      }
    }
  }
  return NULL;
}


static int jj_make_mucs_path(void) {
  gchar *mucs_path;
  struct stat buf;
  int ret = JJ_SUCCESS;

  /* try to create mucs dir if it does not exist yet */
  mucs_path = g_strconcat(jj_user.base_path, "/mucs", NULL);
  if (stat(mucs_path, &buf) != 0) {
    if (errno == ENOENT) { /* no such dir, lets create it */
      if (mkdir(mucs_path, S_IRWXU) != 0) {
	perror("trying to make dir");
	ret = 1; /* define proper error */
      }
    }
  }

  g_free(mucs_path);
  return ret;
}


static int jj_scan_for_fifos() {
  DIR *d;
  struct dirent *drt;
  struct stat sb;
  struct stat sb2;
  gchar *fifo_path;
  gchar *full_path;

  d = opendir(jj_user.base_path);

  if (d != NULL) {
    while ((drt = readdir(d)) != NULL) {
      full_path = g_strconcat(jj_user.base_path, "/", drt->d_name, NULL);
      if ((stat(full_path, &sb)) == -1) {
        g_free(full_path);
        perror("stat");
        jj_error("stat failed for %s", full_path);
        continue;
      }
      g_free(full_path);
      if (!S_ISDIR(sb.st_mode) ||
          strcmp(drt->d_name, "..") == 0 ||
          strcmp(drt->d_name, ".") == 0) {
        /* we care only for directories */
        continue;
      }
      if (strcmp(drt->d_name, "mucs") != 0) {
        /* found some other directory, propably just a normal
           jid. Lets find out fifo */
        fifo_path = g_strconcat(jj_user.base_path, "/", drt->d_name, "/in" ,NULL);
        jj_debug("fifo_path=%s\n", fifo_path);
        if (stat(fifo_path, &sb2) != -1 && S_ISFIFO(sb2.st_mode)) {
          /* found fifo add it your watchs list */
          jj_make_named_pipe_1(fifo_path);
        }
        g_free(fifo_path);
      } else { /* is mucs */
        /* We don't watch fifos in mucs dir since one has to to
           join mucs before sending messages. Later we could add
           some logic for this. Example we could join muc if not
           joined, but message coming in from fifo*/
      }
    }
    closedir(d);
  } else {
    jj_error("Error opening base path: %s", jj_user.base_path);
    return -1;
  }
  return JJ_SUCCESS;
}


/* Try to find jid (something like user@domain/resource), if no jid
   found returns NULL. Caller should call g_free for the returned
   jid. */
static gchar *jj_get_jid(gchar *input) {
  gchar **tmp = g_strsplit(input, " ", 2);
  gchar *jid = g_strdup(tmp[0]);

  g_strfreev(tmp);

  /* simple validation */
  if (strchr(jid, '@') != NULL || strlen(jid) > 3) {
    return jid;
  }
  return NULL;
}


static void jj_writeout(char *path, char *fmt, ...) {
  FILE *output;
  va_list ap;
  char outstr[200] = "23:23";
  time_t t;
  struct tm *tmp;

  jj_debug("path=%s\n", path);

  /* create output file if it does not exist yet */
  output = fopen(path, "a");
  if (output != NULL) {
    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
      jj_error("localtime\n");
    } else {
      if (strftime(outstr, sizeof(outstr), "%H:%M", tmp) == 0) {
        jj_error("strftime returned 0\n");
      }
    }
    fprintf(output, "%s ", outstr);
    va_start(ap, fmt);
    vfprintf(output, fmt, ap);
    va_end(ap);
    fclose(output);
  } else {
    perror(NULL);
  }
}


#define jj_write_out_server(...)                \
  jj_writeout(jj_user.server_out, __VA_ARGS__)


/* Send message to channel with printf style. */
static void jj_send_message_1(LmMessageSubType stype,
                              const gchar *jid, const gchar *fmt, ...) {
  char *msg;
  LmMessage *m;
  va_list ap;
  gchar *xml;

  jj_debug("jid=%s\n", jid);

  va_start(ap, fmt);
  g_vasprintf(&msg, fmt, ap);
  m = lm_message_new_with_sub_type(jid,
				   LM_MESSAGE_TYPE_MESSAGE,
				   stype);
  lm_message_node_add_child(m->node, "body", msg);
  xml = lm_message_node_to_string(m->node);
  if (!lm_connection_send (jj_connection, m, NULL)) {
    jj_error("Failed to send message:'%s'\n", xml);
  } else {
    jj_debug("Sent message:'%s'\n", xml);
  }
  va_end(ap);
  lm_message_unref(m);
  g_free(xml);
  free(msg);
}


#define jj_send_message(...)                                    \
  jj_send_message_1(LM_MESSAGE_SUB_TYPE_CHAT, __VA_ARGS__)


#define jj_send_message_to_muc(...)                             \
  jj_send_message_1(LM_MESSAGE_SUB_TYPE_GROUPCHAT, __VA_ARGS__)


/* Queries muc information from server. This is done when we are first
   time sending message to channel without joining. Adds also muc to
   waited list. Muc will be removed from there when we get answer form
   muc, see jj_handle_iq for details. */
static int jj_send_muc_query(gchar *muc) {
  LmMessage *m;
  LmMessageNode *node;
  gchar *recoded;
  gchar *xml;
  int ret = JJ_SUCCESS;

  m = lm_message_new_with_sub_type(recoded, LM_MESSAGE_TYPE_IQ,
                                   LM_MESSAGE_SUB_TYPE_GET);
  g_free(recoded);
  node = lm_message_node_add_child(m->node, "query", NULL);
  lm_message_node_set_attribute(node, "xmlns", JJ_NS_DISCO);
  xml = lm_message_node_to_string(m->node);
  if (!lm_connection_send (jj_connection, m, NULL)) {
    jj_error("Failed to send message:'%s'\n", xml);
    ret = -1;
  } else {
    jj_debug("Sent message:'%s'\n", xml);
  }
  lm_message_unref(m);
  g_free(xml);
  return ret;
}


static int jj_send_join(gchar *muc) {
  LmMessage *msg;
  LmMessageNode *child;
  int ret = JJ_SUCCESS;
  gchar *xml;
  gchar *mucuser = g_strconcat(muc, "/", jj_user.muc_username, NULL);

  jj_debug("\n%s", muc);
  jj_write_out_server("Joining muc %s\n", muc);

  msg = lm_message_new(mucuser, LM_MESSAGE_TYPE_PRESENCE);
  child = lm_message_node_add_child(msg->node, "x", NULL);
  lm_message_node_set_attribute(child, "xmlns", JJ_NS_MUC);

  /* no history */
  child = lm_message_node_add_child(child, "history", NULL);
  lm_message_node_set_attribute(child, "maxchars", "0");

  xml = lm_message_node_to_string(msg->node);
  jj_debug("%s\n", xml);

  if (!lm_connection_send(jj_connection, msg, NULL)) {
    jj_error("Cannot join muc %s", muc);
    ret = 1; /* define error */
  }

  lm_message_unref(msg);
  g_free(mucuser);
  g_free(xml);
  return ret;
}


static void jj_send_ver(char *to, char* id) {
  LmMessage *msg;
  LmMessageNode *node;

  jj_debug("to=%s id=%s", to, id);

  msg = lm_message_new_with_sub_type(to, LM_MESSAGE_TYPE_IQ,
				     LM_MESSAGE_SUB_TYPE_RESULT);

  if (id != NULL) {
    lm_message_node_set_attribute(msg->node, "id", id);
  }

  node = lm_message_node_add_child(msg->node, "query", NULL);
  lm_message_node_set_attribute(node, "xmlns", JJ_NS_VER);

  lm_message_node_add_child(node, "name",
			    "jj");
  lm_message_node_add_child(node, "version",
			    "0.1a");

  lm_message_node_add_child(node, "os", "Debian GNU/Linux");
  lm_connection_send(jj_connection, msg, NULL);
  lm_message_unref(msg);
}


static LmHandlerResult jj_handle_message(LmMessageHandler *handler,
                                         LmConnection *connection,
                                         LmMessage *m,
                                         gpointer data) {
  gchar *msg;
  gchar **line;
  gchar *outpath;
  gchar *nick;
  gchar *xml;
  LmMessageNode *child = lm_message_node_get_child(m->node, "body");

  xml = lm_message_node_to_string(m->node);
  jj_debug("\n%s\n", xml);

  if (child != NULL) {
    msg = (gchar *) child->value ? child->value : "";
    line = g_strsplit(lm_message_node_get_attribute(m->node, "from"),
                      "/", 2);

    if (lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_GROUPCHAT) {
      outpath = g_strconcat(jj_user.base_path, "/mucs/", line[0], "/out", NULL);
      nick = line[1];
    } else { /* not group chat */
      outpath = g_strconcat(jj_user.base_path, "/", line[0], "/out", NULL);
      nick = line[0];
    }
    jj_writeout(outpath, "<%s> %s\n", nick, msg);
    g_free(outpath);
    g_strfreev(line);
  } else {
    jj_printf("no child\n"); /* ? */
  }
  g_free(xml);
  return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}


static LmHandlerResult jj_handle_presence(LmMessageHandler *handler,
                                          LmConnection *connection,
                                          LmMessage *m,
                                          gpointer data) {
  gchar *path;
  gchar **tmp;
  gchar *muc_user;
  gchar *xml;
  gchar *xml2;
  const gchar *from;
  LmMessageNode *child;


  xml = lm_message_node_to_string(m->node);
  jj_debug("\n%s\n", xml);

  if (lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_ERROR) {
    child = lm_message_node_get_child(m->node, "error");

    xml2 = lm_message_node_to_string(child);
    jj_debug("CHILD: %s\n", xml2);
    g_free(xml2);

    jj_write_out_server("<%s> %s\n",
			lm_message_node_get_attribute (m->node, "from"),
			"FIXME ERROR");
  }
  else if (lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_UNAVAILABLE) {
    /* handler parts from mucs */
    from = lm_message_node_get_attribute(m->node, "from");
    tmp = g_strsplit(from, "/", 2); /* tmp[0] is muc and tmp[1] is user */
    muc_user = jj_user_muc_find_user(tmp[0], tmp[1]);
    if (muc_user != NULL) {
      jj_user_muc_remove_user(tmp[0], muc_user);
      path = g_strconcat(jj_user.base_path,
                         "/mucs/", tmp[0], "/out", NULL);
      jj_writeout(path, "-!- %s has left %s\n", tmp[1], tmp[0]);
      g_free(path);
    }
    g_strfreev(tmp);
  } else if (lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_AVAILABLE) {
    /* normal presence */
    /* check if this is from muc */
    from = lm_message_node_get_attribute(m->node, "from");
    tmp = g_strsplit(from, "/", 2); /* tmp[0] is muc and tmp[1] is user */
    if (jj_user_muc_find(tmp[0]) != NULL) {
      if (jj_user_muc_find_user(tmp[0], tmp[1]) == NULL) {
        /* user has joined */
        jj_user_muc_add_user(tmp[0], tmp[1]);
        path = g_strconcat(jj_user.base_path,
                           "/mucs/", tmp[0], "/out", NULL);
        jj_writeout(path, "-!- %s has joined %s\n", tmp[1], tmp[0]);
        g_free(path);
      }
    }
    g_strfreev(tmp);
  }
  g_free(xml);
  return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}


static LmHandlerResult jj_handle_iq(LmMessageHandler *handler,
                                    LmConnection *connection,
                                    LmMessage *msg,
                                    gpointer jj_user) {
  LmMessageNode *query_node = lm_message_node_get_child(msg->node, "query");
  gchar *xmlns = (gchar *) lm_message_node_get_attribute(query_node, "xmlns");
  gchar *xml;

  xml = lm_message_node_to_string(msg->node);
  jj_debug("\n%s\n", xml);
  jj_debug("Incoming message from: %s\n",
	   lm_message_node_get_attribute (msg->node, "from"));

  switch(lm_message_get_sub_type(msg)) {
  case LM_MESSAGE_SUB_TYPE_GET:
    if(query_node != NULL &&
       g_ascii_strcasecmp(xmlns, JJ_NS_VER) == 0) {
      jj_send_ver((gchar *) lm_message_node_get_attribute(msg->node, "from"),
		  (gchar *) lm_message_node_get_attribute(msg->node, "id"));
    }
    break;
  default:
    break;
  }

  g_free(xml);
  return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}


static int jj_parse_input(const gchar *input,
			   const gchar *path) {
  gchar **line;
  gchar *jid;
  int return_value = 0;

  /* message sent to server. Like /join or /msg */
  if (strcmp(path, jj_user.server_in) == 0) {
    if (input[0] == '/' && strlen(input) > 3 && strchr(input, ' ') != NULL) {
      line = g_strsplit(input, " ", 3);
      switch (input[1]) {
      case 'j': /* /join to join a muc, example usage:
		   /join chat@jabber.org */
        {
          if (g_strv_length(line) < 2) {
            return_value = -EINVAL;
            goto free_and_out;
          }
          jid = jj_get_jid(line[1]);
          if (jid == NULL) {
            return_value = -EINVAL;
            goto free_and_out;
          }
          if (jj_send_join(jid) == JJ_SUCCESS) {
	    jj_make_named_pipe(jid, TRUE);
            jj_user_muc_add(jid);
          }
          g_free(jid);
        }
	break;
      case 'm': /* /msg send private message, example usage:
		   /msg user@domain/resource hello world! */
        {
          /* do some validation */
          if (g_strv_length(line) < 2) {
            return_value = -EINVAL;
            goto free_and_out;
          }
          jid = jj_get_jid(line[1]);
          if (jid == NULL) {
            return_value = -EINVAL;
            goto free_and_out;
          }
          jj_make_named_pipe(jid, FALSE);
          /* the actual message would be third string. Send message
             only if there is message */
          if (g_strv_length(line) > 2) {
            jj_send_message(jid, line[2]);
          }
          g_free(jid);
        }
	break;
      default:
	jj_printf("default %s", input);
	break;
      }
    free_and_out:
      g_strfreev(line);
    }
  } else { /* just general input to some of the watched FIFOs */
    line = g_strsplit(path, "/", 0);
    assert(g_strv_length(line) - 2 > 0);

    if (g_strv_length(line) > 3 &&
        strcmp(line[g_strv_length(line) -3], "mucs") == 0) {
      jj_send_message_to_muc(line[g_strv_length(line) - 2], input);
    } else {
      jj_send_message(line[g_strv_length(line) - 2], input);
    }
    g_strfreev(line);
  }
  return return_value;
}


static gboolean jj_read_pipe(GIOChannel *channel,
			     GIOCondition condition,
			     gpointer data) {
  gchar *str;
  GError *error = NULL;
  int fd;
  jj_pipe_data_t *jdata = (jj_pipe_data_t*) data;
  char *path = jdata->path;
  GSource *source = jdata->source;

  if (condition & (G_IO_IN)) {
    if (g_io_channel_read_line
	(channel, &str, NULL, NULL, &error) == G_IO_STATUS_NORMAL) {
      /* Strip the string. There are rare cases where one would like
	 to input leading or trailing whitespace, but it is just so
	 much easier this way. */
      str = g_strstrip(str);
      if (jj_parse_input(str, path) < 0) {
	jj_error("parsing input\n");
      }
      g_free(str);
    }
  }

  if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
    /* watch again, loop, not good! */
    fd =g_io_channel_unix_get_fd(channel);
    g_io_channel_shutdown(channel, TRUE, NULL);
    g_source_remove(g_source_get_id(source));
    g_io_channel_unref(channel);
    jj_make_named_pipe_1(path);
    free(jdata->path);
    free(jdata);
    return 0;
  }
  return 1;
}


/* wrapper function to do the dir etc, use this instead of
   jj_make_named_pipe_1 */
static void jj_make_named_pipe(gchar *path, gboolean muc) {
  struct stat buf;
  gchar *fullpath;
  gchar *outpath;

  if (muc == TRUE) {
    fullpath = g_strconcat(jj_user.base_path, "/mucs/", path, NULL);
  } else {
    fullpath = g_strconcat(jj_user.base_path, "/", path, NULL);
  }

  jj_debug("fullpath %s\n", fullpath);

  if (stat(fullpath, &buf) != 0) {
    if (errno == ENOENT) { /* no such dir, lets create it */
      if (mkdir(fullpath, S_IRWXU) != 0) {
	perror("trying to make dir");
	goto out;
      }
      /* try again */
      if (stat(fullpath, &buf) != 0) {
	perror("jj_make_named_pipe");
	goto out;
      }
    }
    else {
      perror("jj_make_named_pipe");
      goto out;
    }
  }

  if (!S_ISDIR(buf.st_mode)) {
    jj_error("%s not a dir\n", path);
    goto out;
  }

  outpath = g_strconcat(fullpath, "/in", NULL);
  jj_make_named_pipe_1(outpath);
  g_free(outpath);

 out:
  g_free(fullpath);
  return;
}


/* Add new named pipe to main loop to poll events. Callback
   jj_read_pipe is set to handle events from the pipe. I also
   deallocates resources when not needed anymore. */
static void jj_make_named_pipe_1(gchar *path) {
  GIOChannel *chan;
  GSource *source;
  jj_pipe_data_t *jdata;

  if (mkfifo(path, S_IRWXU) != 0 && errno != EEXIST) {
    perror(NULL);
  } else {
    chan = g_io_channel_unix_new(open(path, O_RDONLY | O_NONBLOCK, 0));
    source = g_io_create_watch(chan, G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL);
    jdata = g_malloc(sizeof(jj_pipe_data_t));
    jdata->source = source;
    jdata->path = g_strdup(path);
    g_source_set_callback(source, (GSourceFunc)jj_read_pipe,
			  jdata, NULL);
    g_source_attach(source, jj_context);
    g_source_unref(source);
  }
}


void jj_callback_auth(LmConnection *con,
		      gboolean success,
		      void *x) {
  if(!success) {
    jj_error("connection failed");
    jj_write_out_server("Authentication to %s failed\n",
                        jj_user.server);
  }
  else {
    jj_write_out_server("Authentication to %s succeeded\n",
                        jj_user.server);
    LmMessage *m = lm_message_new_with_sub_type (NULL,
						 LM_MESSAGE_TYPE_PRESENCE,
						 LM_MESSAGE_SUB_TYPE_AVAILABLE);
    success = lm_connection_send (con, m, NULL);
    lm_message_unref (m);

    if (!success) {
      g_error ("lm_connection_send failed");
    }
  }
}


void jj_callback_open(LmConnection *con,
		      gboolean success,
		      void *x) {
  if(!success) {
    jj_error("Connecting failed");
    jj_write_out_server("Connecting to server %s failed\n",
                        jj_user.server);
  }
  else {
    jj_write_out_server("Connected to server %s\n",
                        jj_user.server);
    if(!lm_connection_authenticate(con,
				   jj_user.username,
				   jj_user.password,
				   "jj",
				   (LmResultFunction) jj_callback_auth,
				   NULL,
				   NULL,
				   NULL))
      jj_error("authentication faield");
  }
}


void jj_callback_close(LmConnection *con,
		       LmDisconnectReason  reason,
		       gpointer jj_user) {
  const char *str;
  switch (reason) {
  case LM_DISCONNECT_REASON_OK:
    str = "LM_DISCONNECT_REASON_OK";
    break;
  case LM_DISCONNECT_REASON_PING_TIME_OUT:
    str = "LM_DISCONNECT_REASON_PING_TIME_OUT";
    break;
  case LM_DISCONNECT_REASON_HUP:
    str = "LM_DISCONNECT_REASON_HUP";
    break;
  case LM_DISCONNECT_REASON_ERROR:
    str = "LM_DISCONNECT_REASON_ERROR";
    break;
  case LM_DISCONNECT_REASON_UNKNOWN:
  default:
    str = "LM_DISCONNECT_REASON_UNKNOWN";
    break;
  }

  jj_printf("Disconnected, reason:%d->'%s'\n", reason, str);
}


/* Print program usage */
void jj_usage(char *pname) {
  jj_printf("Usage: %s [OPTIONS]\n", pname);
  jj_printf("\
  -s server\n\
  -j jabber id\n\
  -u username\n\
  -p password\n\
  -m muc username\n");
  exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[]) {
  gchar server[200] = "";
  gchar username[200] = "";
  gchar password[200] = "";
  gchar jid[200] = "";
  gchar muc_username[200] = "";

  GError *error = NULL;
  LmMessageHandler *handler;
  int option;
  char *pname = argv[0];

  /* Parse command line options */
  while ((option = getopt(argc, argv, "s:j:p:u:m:")) != -1) {
    switch (option) {
    case 's':
      if (optarg) {
  	sscanf(optarg, "%s", server);
      }
      break;
    case 'j':
      if (optarg) {
  	sscanf(optarg, "%s", jid);
      }
      break;
    case 'p':
      if (optarg) {
  	sscanf(optarg, "%s", password);
      }
      break;
    case 'u':
      if (optarg) {
  	sscanf(optarg, "%s", username);
      }
    case 'm':
      if (optarg) {
  	sscanf(optarg, "%s", muc_username);
      }
      break;
    default:
      jj_usage(pname);
    }
  }

  if (strlen(server) == 0 || strlen(jid) == 0 ||
      strlen(password) == 0 || strlen(username) == 0) {
    jj_usage(pname);
  }

  /* Init jj_user */
  jj_user.username = username;
  jj_user.password = password;
  jj_user.server = server;
  jj_user.mucs = NULL;

  if (strlen(muc_username) > 0) {
    jj_user.muc_username = muc_username;
  } else {
    jj_user.muc_username = username;
  }

  /* Init context before scanning for fifos */
  jj_context = g_main_context_new();

  /* Init and scan paths */
  jj_user.base_path = ".";
  jj_make_named_pipe(server, FALSE);
  jj_user.server_in = g_strconcat(jj_user.base_path,
				    "/", server, "/" "in",
				    NULL);
  jj_user.server_out = g_strconcat(jj_user.base_path,
				   "/", server, "/" "out",
				   NULL);
  jj_user.base_path = g_strconcat(jj_user.base_path,
				  "/",
				  server,
				  NULL);

  if (jj_make_mucs_path() != JJ_SUCCESS ||
      jj_scan_for_fifos() != JJ_SUCCESS) {
    exit(EXIT_FAILURE);
  }

  /* Init loudmouth stuff */
  jj_connection = lm_connection_new_with_context(server, jj_context);
  lm_connection_set_jid(jj_connection, jid);

  /* Register message handlers */
  handler = lm_message_handler_new(jj_handle_message, NULL, NULL);
  lm_connection_register_message_handler(jj_connection,
  					 handler,
  					 LM_MESSAGE_TYPE_MESSAGE,
  					 LM_HANDLER_PRIORITY_NORMAL);
  lm_message_handler_unref(handler);

  handler = lm_message_handler_new(jj_handle_presence, NULL, NULL);
  lm_connection_register_message_handler(jj_connection,
  					 handler,
  					 LM_MESSAGE_TYPE_PRESENCE,
  					 LM_HANDLER_PRIORITY_NORMAL);
  lm_message_handler_unref(handler);

  handler = lm_message_handler_new(jj_handle_iq, NULL, NULL);
  lm_connection_register_message_handler(jj_connection,
  					 handler,
  					 LM_MESSAGE_TYPE_IQ,
  					 LM_HANDLER_PRIORITY_NORMAL);
  lm_message_handler_unref(handler);

  lm_connection_set_disconnect_function(jj_connection,
  					jj_callback_close,
  					NULL, NULL);

  if(!lm_connection_open(jj_connection,
  			 (LmResultFunction) jj_callback_open,
  			 NULL,
  			 NULL,
  			 &error)) {
    jj_error("Error while connecting: %s", error->message);
    exit(EXIT_FAILURE);
  }

  jj_debug("mainloop %d\n", 1);

  jj_main_loop = g_main_loop_new(jj_context, FALSE);

  g_main_loop_run(jj_main_loop);

  exit(EXIT_SUCCESS);
}
