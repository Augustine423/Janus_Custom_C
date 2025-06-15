/*
 * Janus Streaming Monitor Plugin
 * Monitors RTP streams, logs to MySQL, and provides WebSocket API for stream management.
 * Supports auto-detection, recording, and viewer management.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <json-glib/json-glib.h>
#include <glib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "plugin.h"
#include "debug.h"
#include "apierror.h"
#include "config.h"
#include "mutex.h"
#include "rtp.h"
#include "rtcp.h"
#include "record.h"
#include "events.h"

#define JANUS_STREAMING_MONITOR_VERSION			1
#define JANUS_STREAMING_MONITOR_VERSION_STRING	"0.0.2"
#define JANUS_STREAMING_MONITOR_DESCRIPTION		"RTP Stream Monitor Plugin with MySQL and WebSocket"
#define JANUS_STREAMING_MONITOR_NAME			"JANUS Streaming Monitor Plugin"
#define JANUS_STREAMING_MONITOR_AUTHOR			"Custom"
#define JANUS_STREAMING_MONITOR_PACKAGE			"janus.plugin.streamingmonitor"

#define DEFAULT_RTP_LISTEN_PORT 5004
#define MAX_PACKET_SIZE 1500
#define MYSQL_UPDATE_INTERVAL 1000
#define STREAM_TIMEOUT_US 60000000 /* 60 seconds */

/* Plugin information */
janus_plugin janus_streaming_monitor_plugin = {
	.version = JANUS_STREAMING_MONITOR_VERSION,
	.version_str = JANUS_STREAMING_MONITOR_VERSION_STRING,
	.description = JANUS_STREAMING_MONITOR_DESCRIPTION,
	.name = JANUS_STREAMING_MONITOR_NAME,
	.author = JANUS_STREAMING_MONITOR_AUTHOR,
	.package = JANUS_STREAMING_MONITOR_PACKAGE,
	.init = janus_streaming_monitor_init,
	.destroy = janus_streaming_monitor_destroy,
	.get_api_compatibility = janus_streaming_monitor_get_api_compatibility,
	.get_version = janus_streaming_monitor_get_version,
	.get_version_string = janus_streaming_monitor_get_version_string,
	.get_description = janus_streaming_monitor_get_description,
	.get_name = janus_streaming_monitor_get_name,
	.get_author = janus_streaming_monitor_get_author,
	.get_package = janus_streaming_monitor_get_package,
	.create_session = janus_streaming_monitor_create_session,
	.handle_message = janus_streaming_monitor_handle_message,
	.handle_admin_message = janus_streaming_monitor_handle_admin_message,
	.setup_media = janus_streaming_monitor_setup_media,
	.incoming_rtp = janus_streaming_monitor_incoming_rtp,
	.incoming_rtcp = janus_streaming_monitor_incoming_rtcp,
	.incoming_data = janus_streaming_monitor_incoming_data,
	.data_ready = janus_streaming_monitor_data_ready,
	.slow_link = janus_streaming_monitor_slow_link,
	.hangup_media = janus_streaming_monitor_hangup_media,
	.destroy_session = janus_streaming_monitor_destroy_session,
	.query_session = janus_streaming_monitor_query_session
};

/* Stream key for efficient lookup */
typedef struct {
	guint32 ssrc;
	char *source_ip;
	guint16 source_port;
} stream_key_t;

/* RTP Stream structure */
typedef struct janus_streaming_rtp_source {
	guint32 stream_id;
	char *source_ip;
	guint16 source_port;
	guint32 ssrc;
	gint64 first_seen;
	gint64 last_seen;
	guint64 packet_count;
	guint64 byte_count;
	gboolean active;
	gboolean recording;
	janus_recorder *recorder;
	GHashTable *viewers; /* Sessions watching this stream */
} janus_streaming_rtp_source;

/* Session structure */
typedef struct janus_streaming_session {
	janus_plugin_session *handle;
	guint32 watching_stream_id;
	gboolean started;
	gboolean destroyed;
	janus_mutex mutex;
} janus_streaming_session;

/* Global variables */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static janus_mutex streams_mutex;
static GHashTable *rtp_streams = NULL; /* stream_key_t -> janus_streaming_rtp_source */
static guint32 next_stream_id = 1;
static MYSQL *mysql_conn = NULL;
static pthread_t rtp_listener_thread;
static pthread_t cleanup_thread;
static int rtp_listen_socket = -1;
static guint16 rtp_listen_port = DEFAULT_RTP_LISTEN_PORT;

/* MySQL configuration */
static char *mysql_host = NULL;
static char *mysql_user = NULL;
static char *mysql_password = NULL;
static char *mysql_database = NULL;
static guint16 mysql_port = 3306;

/* Function declarations */
static void janus_streaming_monitor_load_config(const char *config_path);
static void janus_streaming_monitor_rtp_listener(void);
static void janus_streaming_monitor_cleanup_thread(void);
static void janus_streaming_monitor_process_rtp_packet(char *buffer, int len, struct sockaddr_storage *addr);
static janus_streaming_rtp_source *janus_streaming_monitor_create_stream(const char *ip, guint16 port, guint32 ssrc);
static void janus_streaming_monitor_update_stream_stats(janus_streaming_rtp_source *stream, int packet_size);
static gboolean janus_streaming_monitor_mysql_reconnect(void);
static void janus_streaming_monitor_save_to_mysql(janus_streaming_rtp_source *stream);
static json_t *janus_streaming_monitor_get_streams_list(void);
static guint stream_key_hash(gconstpointer key);
static gboolean stream_key_equal(gconstpointer a, gconstpointer b);
static void stream_key_destroy(gpointer key);

/* Stream key hash and equality functions */
static guint stream_key_hash(gconstpointer key) {
	const stream_key_t *k = (const stream_key_t *)key;
	return g_str_hash(k->source_ip) ^ k->ssrc ^ k->source_port;
}

static gboolean stream_key_equal(gconstpointer a, gconstpointer b) {
	const stream_key_t *ka = (const stream_key_t *)a;
	const stream_key_t *kb = (const stream_key_t *)b;
	return ka->ssrc == kb->ssrc &&
	       ka->source_port == kb->source_port &&
	       strcmp(ka->source_ip, kb->source_ip) == 0;
}

static void stream_key_destroy(gpointer key) {
	stream_key_t *k = (stream_key_t *)key;
	g_free(k->source_ip);
	g_free(k);
}

/* Load configuration from file */
static void janus_streaming_monitor_load_config(const char *config_path) {
	janus_config *config = janus_config_parse(config_path);
	if(!config) {
		JANUS_LOG(LOG_WARN, "Failed to load config file: %s\n", config_path);
		return;
	}

	janus_config_item *item;
	item = janus_config_get_item(config, "general", "mysql_host");
	if(item && item->value) mysql_host = g_strdup(item->value);
	else mysql_host = g_strdup("localhost");

	item = janus_config_get_item(config, "general", "mysql_user");
	if(item && item->value) mysql_user = g_strdup(item->value);
	else mysql_user = g_strdup("janus");

	item = janus_config_get_item(config, "general", "mysql_password");
	if(item && item->value) mysql_password = g_strdup(item->value);
	else mysql_password = g_strdup("password");

	item = janus_config_get_item(config, "general", "mysql_database");
	if(item && item->value) mysql_database = g_strdup(item->value);
	else mysql_database = g_strdup("janus_streams");

	item = janus_config_get_item(config, "general", "mysql_port");
	if(item && item->value) mysql_port = atoi(item->value);
	else mysql_port = 3306;

	item = janus_config_get_item(config, "general", "rtp_listen_port");
	if(item && item->value) rtp_listen_port = atoi(item->value);
	else rtp_listen_port = DEFAULT_RTP_LISTEN_PORT;

	janus_config_destroy(config);
	JANUS_LOG(LOG_INFO, "Configuration loaded: MySQL=%s:%d, RTP port=%d\n",
	          mysql_host, mysql_port, rtp_listen_port);
}

/* Plugin initialization */
int janus_streaming_monitor_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		return -1;
	}
	if(!callback || !config_path) {
		JANUS_LOG(LOG_ERR, "Invalid initialization parameters\n");
		return -1;
	}

	gateway = callback;
	janus_mutex_init(&streams_mutex);
	rtp_streams = g_hash_table_new_full(stream_key_hash, stream_key_equal, stream_key_destroy, g_free);

	/* Load configuration */
	janus_streaming_monitor_load_config(config_path);

	/* Initialize MySQL connection */
	mysql_conn = mysql_init(NULL);
	if(!janus_streaming_monitor_mysql_reconnect()) {
		JANUS_LOG(LOG_ERR, "MySQL initialization failed\n");
		g_hash_table_destroy(rtp_streams);
		return -1;
	}

	/* Create table if not exists */
	const char *create_table =
		"CREATE TABLE IF NOT EXISTS rtp_streams ("
		"id INT AUTO_INCREMENT PRIMARY KEY,"
		"stream_id INT UNIQUE,"
		"source_ip VARCHAR(45),"
		"source_port INT,"
		"ssrc BIGINT,"
		"first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
		"last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
		"packet_count BIGINT DEFAULT 0,"
		"byte_count BIGINT DEFAULT 0,"
		"active BOOLEAN DEFAULT TRUE"
		")";
	if(mysql_query(mysql_conn, create_table)) {
		JANUS_LOG(LOG_ERR, "Failed to create table: %s\n", mysql_error(mysql_conn));
	}

	/* Create RTP listening socket */
	rtp_listen_socket = socket(AF_INET6, SOCK_DGRAM, 0);
	if(rtp_listen_socket < 0) {
		JANUS_LOG(LOG_ERR, "Failed to create RTP socket: %s\n", strerror(errno));
		mysql_close(mysql_conn);
		return -1;
	}

	/* Enable IPv4 compatibility */
	int v6only = 0;
	if(setsockopt(rtp_listen_socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
		JANUS_LOG(LOG_ERR, "Failed to set IPV6_V6ONLY: %s\n", strerror(errno));
		close(rtp_listen_socket);
		return -1;
	}

	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(rtp_listen_port);

	if(bind(rtp_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		JANUS_LOG(LOG_ERR, "Failed to bind RTP socket to port %d: %s\n", rtp_listen_port, strerror(errno));
		close(rtp_listen_socket);
		mysql_close(mysql_conn);
		return -1;
	}

	/* Start RTP listener thread */
	if(pthread_create(&rtp_listener_thread, NULL, (void*(*)(void*))janus_streaming_monitor_rtp_listener, NULL) != 0) {
		JANUS_LOG(LOG_ERR, "Failed to create RTP listener thread\n");
		close(rtp_listen_socket);
		mysql_close(mysql_conn);
		return -1;
	}

	/* Start cleanup thread */
	if(pthread_create(&cleanup_thread, NULL, (void*(*)(void*))janus_streaming_monitor_cleanup_thread, NULL) != 0) {
		JANUS_LOG(LOG_ERR, "Failed to create cleanup thread\n");
		close(rtp_listen_socket);
		mysql_close(mysql_conn);
		return -1;
	}

	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "Streaming Monitor plugin initialized\n");
	return 0;
}

/* Plugin destruction */
void janus_streaming_monitor_destroy(void) {
	if(!g_atomic_int_get(&initialized)) return;
	g_atomic_int_set(&stopping, 1);

	if(rtp_listen_socket >= 0) {
		close(rtp_listen_socket);
		rtp_listen_socket = -1;
	}
	pthread_join(rtp_listener_thread, NULL);
	pthread_join(cleanup_thread, NULL);

	janus_mutex_lock(&streams_mutex);
	if(rtp_streams) {
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, rtp_streams);
		while(g_hash_table_iter_next(&iter, &key, &value)) {
			janus_streaming_rtp_source *stream = (janus_streaming_rtp_source *)value;
			g_free(stream->source_ip);
			if(stream->recorder) janus_recorder_close(stream->recorder);
			g_hash_table_destroy(stream->viewers);
		}
		g_hash_table_destroy(rtp_streams);
		rtp_streams = NULL;
	}
	janus_mutex_unlock(&streams_mutex);

	if(mysql_conn) {
		mysql_close(mysql_conn);
		mysql_conn = NULL;
	}

	g_free(mysql_host);
	g_free(mysql_user);
	g_free(mysql_password);
	g_free(mysql_database);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "Streaming Monitor plugin destroyed\n");
}

/* RTP listener thread */
static void janus_streaming_monitor_rtp_listener(void) {
	char buffer[MAX_PACKET_SIZE];
	struct sockaddr_storage client_addr;
	socklen_t addr_len = sizeof(client_addr);

	JANUS_LOG(LOG_INFO, "RTP listener thread started on port %d\n", rtp_listen_port);

	while(!g_atomic_int_get(&stopping)) {
		int bytes_received = recvfrom(rtp_listen_socket, buffer, sizeof(buffer), 0,
		                              (struct sockaddr*)&client_addr, &addr_len);
		if(bytes_received < 0) {
			JANUS_LOG(LOG_ERR, "recvfrom failed: %s\n", strerror(errno));
			continue;
		}
		if(bytes_received > 0) {
			janus_streaming_monitor_process_rtp_packet(buffer, bytes_received, &client_addr);
		}
	}

	JANUS_LOG(LOG_INFO, "RTP listener thread stopped\n");
}

/* Cleanup thread for inactive streams */
static void janus_streaming_monitor_cleanup_thread(void) {
	while(!g_atomic_int_get(&stopping)) {
		janus_mutex_lock(&streams_mutex);
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, rtp_streams);
		while(g_hash_table_iter_next(&iter, &key, &value)) {
			janus_streaming_rtp_source *stream = (janus_streaming_rtp_source *)value;
			if(janus_get_monotonic_time() - stream->last_seen > STREAM_TIMEOUT_US) {
				g_hash_table_iter_remove(&iter);
				JANUS_LOG(LOG_INFO, "Removed inactive stream %d\n", stream->stream_id);
				g_free(stream->source_ip);
				if(stream->recorder) janus_recorder_close(stream->recorder);
				g_hash_table_destroy(stream->viewers);
			}
		}
		janus_mutex_unlock(&streams_mutex);
		g_usleep(1000000); /* Check every second */
	}
}

/* Process incoming RTP packet */
static void janus_streaming_monitor_process_rtp_packet(char *buffer, int len, struct sockaddr_storage *addr) {
	if(len < 12) return; /* Invalid RTP packet */

	janus_rtp_header *rtp = (janus_rtp_header *)buffer;
	guint32 ssrc = ntohl(rtp->ssrc);

	char ip_str[INET6_ADDRSTRLEN];
	if(addr->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
	}
	guint16 source_port = ntohs(((struct sockaddr_in *)addr)->sin_port);

	janus_mutex_lock(&streams_mutex);

	/* Find or create stream */
	stream_key_t key = { .ssrc = ssrc, .source_ip = ip_str, .source_port = source_port };
	janus_streaming_rtp_source *stream = g_hash_table_lookup(rtp_streams, &key);
	if(!stream) {
		stream_key_t *new_key = g_malloc(sizeof(stream_key_t));
		new_key->ssrc = ssrc;
		new_key->source_ip = g_strdup(ip_str);
		new_key->source_port = source_port;
		stream = janus_streaming_monitor_create_stream(ip_str, source_port, ssrc);
		if(stream) {
			g_hash_table_insert(rtp_streams, new_key, stream);
			JANUS_LOG(LOG_INFO, "New RTP stream: ID=%d, IP=%s, Port=%d, SSRC=%u\n",
			          stream->stream_id, ip_str, source_port, ssrc);
		} else {
			g_free(new_key->source_ip);
			g_free(new_key);
		}
	}

	if(stream) {
		janus_streaming_monitor_update_stream_stats(stream, len);

		/* Forward to viewers */
		if(stream->viewers) {
			GHashTableIter viewer_iter;
			gpointer key, value;
			g_hash_table_iter_init(&viewer_iter, stream->viewers);
			while(g_hash_table_iter_next(&viewer_iter, &key, &value)) {
				janus_streaming_session *session = (janus_streaming_session *)value;
				if(session && session->handle && session->started) {
					gateway->relay_rtp(session->handle, buffer, len);
				}
			}
		}

		/* Record if enabled */
		if(stream->recording && stream->recorder) {
			janus_recorder_save_frame(stream->recorder, buffer, len);
		}
	}

	janus_mutex_unlock(&streams_mutex);
}

/* Create a new RTP stream */
static janus_streaming_rtp_source *janus_streaming_monitor_create_stream(const char *ip, guint16 port, guint32 ssrc) {
	janus_streaming_rtp_source *stream = g_malloc0(sizeof(janus_streaming_rtp_source));
	if(!stream) {
		JANUS_LOG(LOG_ERR, "Failed to allocate stream\n");
		return NULL;
	}

	stream->stream_id = next_stream_id++;
	stream->source_ip = g_strdup(ip);
	if(!stream->source_ip) {
		g_free(stream);
		JANUS_LOG(LOG_ERR, "Failed to allocate source_ip\n");
		return NULL;
	}
	stream->source_port = port;
	stream->ssrc = ssrc;
	stream->first_seen = janus_get_monotonic_time();
	stream->last_seen = stream->first_seen;
	stream->active = TRUE;
	stream->viewers = g_hash_table_new(g_direct_hash, g_direct_equal);

	/* Create recorder */
	char filename[256];
	snprintf(filename, sizeof(filename), "stream_%d_%s_%d", stream->stream_id, ip, port);
	stream->recorder = janus_recorder_create(NULL, janus_recorder_medium_video, filename);
	if(stream->recorder) {
		stream->recording = TRUE;
	} else {
		JANUS_LOG(LOG_ERR, "Failed to create recorder for stream %d\n", stream->stream_id);
	}

	janus_streaming_monitor_save_to_mysql(stream);
	return stream;
}

/* Update stream statistics */
static void janus_streaming_monitor_update_stream_stats(janus_streaming_rtp_source *stream, int packet_size) {
	stream->last_seen = janus_get_monotonic_time();
	stream->packet_count++;
	stream->byte_count += packet_size;

	if(stream->packet_count % MYSQL_UPDATE_INTERVAL == 0) {
		janus_streaming_monitor_save_to_mysql(stream);
	}
}

/* Reconnect to MySQL */
static gboolean janus_streaming_monitor_mysql_reconnect(void) {
	if(mysql_conn) mysql_close(mysql_conn);
	mysql_conn = mysql_init(NULL);
	if(!mysql_real_connect(mysql_conn, mysql_host, mysql_user, mysql_password,
	                       mysql_database, mysql_port, NULL, 0)) {
		JANUS_LOG(LOG_ERR, "MySQL connection failed: %s\n", mysql_error(mysql_conn));
		mysql_conn = NULL;
		return FALSE;
	}
	JANUS_LOG(LOG_INFO, "MySQL connected successfully\n");
	return TRUE;
}

/* Save stream data to MySQL using prepared statements */
static void janus_streaming_monitor_save_to_mysql(janus_streaming_rtp_source *stream) {
	if(!mysql_conn && !janus_streaming_monitor_mysql_reconnect()) return;

	MYSQL_STMT *stmt = mysql_stmt_init(mysql_conn);
	if(!stmt) {
		JANUS_LOG(LOG_ERR, "MySQL statement init failed: %s\n", mysql_error(mysql_conn));
		return;
	}

	const char *query = "INSERT INTO rtp_streams (stream_id, source_ip, source_port, ssrc, packet_count, byte_count) "
	                    "VALUES (?, ?, ?, ?, ?, ?) "
	                    "ON DUPLICATE KEY UPDATE packet_count=?, byte_count=?, last_seen=NOW()";
	if(mysql_stmt_prepare(stmt, query, strlen(query))) {
		JANUS_LOG(LOG_ERR, "MySQL statement prepare failed: %s\n", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return;
	}

	MYSQL_BIND bind[8];
	memset(bind, 0, sizeof(bind));
	bind[0].buffer_type = MYSQL_TYPE_LONG;
	bind[0].buffer = &stream->stream_id;
	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = stream->source_ip;
	bind[1].buffer_length = strlen(stream->source_ip);
	bind[2].buffer_type = MYSQL_TYPE_LONG;
	bind[2].buffer = &stream->source_port;
	bind[3].buffer_type = MYSQL_TYPE_LONG;
	bind[3].buffer = &stream->ssrc;
	bind[4].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[4].buffer = &stream->packet_count;
	bind[5].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[5].buffer = &stream->byte_count;
	bind[6].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[6].buffer = &stream->packet_count;
	bind[7].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[7].buffer = &stream->byte_count;

	if(mysql_stmt_bind_param(stmt, bind) || mysql_stmt_execute(stmt)) {
		JANUS_LOG(LOG_ERR, "MySQL statement execution failed: %s\n", mysql_stmt_error(stmt));
	}

	mysql_stmt_close(stmt);
}

/* Handle WebSocket API messages */
void janus_streaming_monitor_handle_message(janus_plugin_session *handle, char *transaction,
	                                       json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) return;

	janus_streaming_session *session = (janus_streaming_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with handle\n");
		json_t *response = json_object();
		json_object_set_new(response, "error", json_string("No session associated"));
		janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR, NULL, response);
		gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
		janus_plugin_result_destroy(result);
		json_decref(response);
		return;
	}

	json_t *request = json_object_get(message, "request");
	const char *request_text = json_string_value(request);
	if(!request_text) {
		json_t *response = json_object();
		json_object_set_new(response, "error", json_string("Missing request"));
		janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR, NULL, response);
		gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
		janus_plugin_result_destroy(result);
		json_decref(response);
		return;
	}

	if(!strcasecmp(request_text, "list")) {
		json_t *streams_list = janus_streaming_monitor_get_streams_list();
		json_t *response = json_object();
		json_object_set_new(response, "streaming", json_string("list"));
		json_object_set_new(response, "streams", streams_list);
		janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
		janus_plugin_result_destroy(result);
		json_decref(response);

	} else if(!strcasecmp(request_text, "watch")) {
		json_t *stream_id_json = json_object_get(message, "id");
		if(!stream_id_json) {
			json_t *response = json_object();
			json_object_set_new(response, "error", json_string("Missing stream ID"));
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR, NULL, response);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
			json_decref(response);
			return;
		}

		guint32 stream_id = json_integer_value(stream_id_json);
		janus_mutex_lock(&streams_mutex);
		GHashTableIter iter;
		gpointer key, value;
		janus_streaming_rtp_source *stream = NULL;
		g_hash_table_iter_init(&iter, rtp_streams);
		while(g_hash_table_iter_next(&iter, &key, &value)) {
			janus_streaming_rtp_source *s = (janus_streaming_rtp_source *)value;
			if(s->stream_id == stream_id) {
				stream = s;
				break;
			}
		}

		if(stream) {
			session->watching_stream_id = stream_id;
			g_hash_table_insert(stream->viewers, session, session);
			json_t *response = json_object();
			json_object_set_new(response, "streaming", json_string("watch"));
			json_object_set_new(response, "result", json_string("ok"));
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
			json_decref(response);
		} else {
			json_t *response = json_object();
			json_object_set_new(response, "error", json_string("Stream not found"));
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR, NULL, response);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
			json_decref(response);
		}
		janus_mutex_unlock(&streams_mutex);

	} else if(!strcasecmp(request_text, "stop")) {
		janus_mutex_lock(&streams_mutex);
		if(session->watching_stream_id > 0) {
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, rtp_streams);
			while(g_hash_table_iter_next(&iter, &key, &value)) {
				janus_streaming_rtp_source *stream = (janus_streaming_rtp_source *)value;
				if(stream->stream_id == session->watching_stream_id) {
					g_hash_table_remove(stream->viewers, session);
					break;
				}
			}
			session->watching_stream_id = 0;
			json_t *response = json_object();
			json_object_set_new(response, "streaming", json_string("stop"));
			json_object_set_new(response, "result", json_string("ok"));
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
			json_decref(response);
		} else {
			json_t *response = json_object();
			json_object_set_new(response, "error", json_string("Not watching any stream"));
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR, NULL, response);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
			json_decref(response);
		}
		janus_mutex_unlock(&streams_mutex);
	}
}

/* Get list of active streams */
static json_t *janus_streaming_monitor_get_streams_list(void) {
	json_t *streams_array = json_array();
	janus_mutex_lock(&streams_mutex);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, rtp_streams);
	while(g_hash_table_iter_next(&iter, &key, &value)) {
		janus_streaming_rtp_source *stream = (janus_streaming_rtp_source *)value;
		json_t *stream_obj = json_object();
		json_object_set_new(stream_obj, "id", json_integer(stream->stream_id));
		json_object_set_new(stream_obj, "ip", json_string(stream->source_ip));
		json_object_set_new(stream_obj, "port", json_integer(stream->source_port));
		json_object_set_new(stream_obj, "ssrc", json_integer(stream->ssrc));
		json_object_set_new(stream_obj, "packet_count", json_integer(stream->packet_count));
		json_object_set_new(stream_obj, "byte_count", json_integer(stream->byte_count));
		json_object_set_new(stream_obj, "active", json_boolean(stream->active));
		json_object_set_new(stream_obj, "viewers", json_integer(g_hash_table_size(stream->viewers)));
		json_array_append_new(streams_array, stream_obj);
	}
	janus_mutex_unlock(&streams_mutex);
	return streams_array;
}

/* Create a new session */
janus_plugin_session *janus_streaming_monitor_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return NULL;
	}

	janus_streaming_session *session = g_malloc0(sizeof(janus_streaming_session));
	if(!session) {
		*error = -2;
		JANUS_LOG(LOG_ERR, "Failed to allocate session\n");
		return NULL;
	}

	session->handle = handle;
	session->watching_stream_id = 0;
	session->started = FALSE;
	session->destroyed = FALSE;
	janus_mutex_init(&session->mutex);
	handle->plugin_handle = session;

	return session;
}

/* Destroy a session */
void janus_streaming_monitor_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}

	janus_streaming_session *session = (janus_streaming_session *)handle->plugin_handle;
	if(!session) {
		*error = -2;
		return;
	}

	if(session->watching_stream_id > 0) {
		janus_mutex_lock(&streams_mutex);
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, rtp_streams);
		while(g_hash_table_iter_next(&iter, &key, &value)) {
			janus_streaming_rtp_source *stream = (janus_streaming_rtp_source *)value;
			if(stream->stream_id == session->watching_stream_id) {
				g_hash_table_remove(stream->viewers, session);
				break;
			}
		}
		janus_mutex_unlock(&streams_mutex);
	}

	session->destroyed = TRUE;
	janus_mutex_destroy(&session->mutex);
	g_free(session);
	handle->plugin_handle = NULL;
}

/* Plugin method stubs */
int janus_streaming_monitor_get_api_compatibility(void) { return JANUS_PLUGIN_API_VERSION; }
int janus_streaming_monitor_get_version(void) { return JANUS_STREAMING_MONITOR_VERSION; }
const char *janus_streaming_monitor_get_version_string(void) { return JANUS_STREAMING_MONITOR_VERSION_STRING; }
const char *janus_streaming_monitor_get_description(void) { return JANUS_STREAMING_MONITOR_DESCRIPTION; }
const char *janus_streaming_monitor_get_name(void) { return JANUS_STREAMING_MONITOR_NAME; }
const char *janus_streaming_monitor_get_author(void) { return JANUS_STREAMING_MONITOR_AUTHOR; }
const char *janus_streaming_monitor_get_package(void) { return JANUS_STREAMING_MONITOR_PACKAGE; }

void janus_streaming_monitor_setup_media(janus_plugin_session *handle) {
	janus_streaming_session *session = (janus_streaming_session *)handle->plugin_handle;
	if(!session) return;
	session->started = TRUE;
	JANUS_LOG(LOG_INFO, "Media setup for session %p\n", session);
}

void janus_streaming_monitor_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	/* Not used in this plugin; all RTP packets are processed via UDP socket */
}

void janus_streaming_monitor_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {
	/* TODO: Process RTCP for stream quality metrics */
}

void janus_streaming_monitor_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet) {
	/* Not used in this plugin */
}

void janus_streaming_monitor_data_ready(janus_plugin_session *handle) {
	/* Not used in this plugin */
}

void janus_streaming_monitor_slow_link(janus_plugin_session *handle, int uplink, int video) {
	JANUS_LOG(LOG_WARN, "Slow link detected for session %p\n", handle);
}

void janus_streaming_monitor_hangup_media(janus_plugin_session *handle) {
	janus_streaming_session *session = (janus_streaming_session *)handle->plugin_handle;
	if(!session) return;
	session->started = FALSE;
	JANUS_LOG(LOG_INFO, "Media hung up for session %p\n", session);
}

void janus_streaming_monitor_handle_admin_message(json_t *message, json_t *transaction) {
	/* TODO: Implement admin API if needed */
}

json_t *janus_streaming_monitor_query_session(janus_plugin_session *handle) {
	janus_streaming_session *session = (janus_streaming_session *)handle->plugin_handle;
	if(!session) return NULL;
	json_t *response = json_object();
	json_object_set_new(response, "watching_stream_id", json_integer(session->watching_stream_id));
	json_object_set_new(response, "started", json_boolean(session->started));
	return response;
}