/*
 * Modified Janus Streaming Plugin for RTP Stream Monitoring
 * Supports auto-detection of RTP streams, MySQL logging, and WebSocket API
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <json-glib/json-glib.h>
#include <glib.h>
#include <pthread.h>

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
#define JANUS_STREAMING_MONITOR_VERSION_STRING	"0.0.1"
#define JANUS_STREAMING_MONITOR_DESCRIPTION		"RTP Stream Monitor Plugin"
#define JANUS_STREAMING_MONITOR_NAME			"JANUS Streaming Monitor plugin"
#define JANUS_STREAMING_MONITOR_AUTHOR			"Custom"
#define JANUS_STREAMING_MONITOR_PACKAGE			"janus.plugin.streamingmonitor"

/* Plugin information */
janus_plugin janus_streaming_monitor_plugin = {
	JANUS_PLUGIN_API_VERSION,
	JANUS_STREAMING_MONITOR_VERSION,
	JANUS_STREAMING_MONITOR_NAME,
	JANUS_STREAMING_MONITOR_VERSION_STRING,
	JANUS_STREAMING_MONITOR_DESCRIPTION,
	JANUS_STREAMING_MONITOR_AUTHOR,
	JANUS_STREAMING_MONITOR_PACKAGE,
	janus_streaming_monitor_init,
	janus_streaming_monitor_destroy,
	janus_streaming_monitor_get_api_compatibility,
	janus_streaming_monitor_get_version,
	janus_streaming_monitor_get_version_string,
	janus_streaming_monitor_get_description,
	janus_streaming_monitor_get_name,
	janus_streaming_monitor_get_author,
	janus_streaming_monitor_get_package,
	janus_streaming_monitor_create_session,
	janus_streaming_monitor_handle_message,
	janus_streaming_monitor_handle_admin_message,
	janus_streaming_monitor_setup_media,
	janus_streaming_monitor_incoming_rtp,
	janus_streaming_monitor_incoming_rtcp,
	janus_streaming_monitor_incoming_data,
	janus_streaming_monitor_data_ready,
	janus_streaming_monitor_slow_link,
	janus_streaming_monitor_hangup_media,
	janus_streaming_monitor_destroy_session,
	janus_streaming_monitor_query_session
};

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
	GHashTable *viewers;  /* Sessions watching this stream */
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
static GHashTable *rtp_streams = NULL;  /* stream_id -> janus_streaming_rtp_source */
static guint32 next_stream_id = 1;
static MYSQL *mysql_conn = NULL;
static pthread_t rtp_listener_thread;
static int rtp_listen_socket = -1;
static guint16 rtp_listen_port = 5004;

/* MySQL configuration */
static char *mysql_host = "localhost";
static char *mysql_user = "janus";
static char *mysql_password = "password";
static char *mysql_database = "janus_streams";
static guint16 mysql_port = 3306;

/* Function declarations */
static void janus_streaming_monitor_rtp_listener(void);
static void janus_streaming_monitor_process_rtp_packet(char *buffer, int len, struct sockaddr_in *addr);
static janus_streaming_rtp_source *janus_streaming_monitor_create_stream(const char *ip, guint16 port, guint32 ssrc);
static void janus_streaming_monitor_update_stream_stats(janus_streaming_rtp_source *stream, int packet_size);
static void janus_streaming_monitor_save_to_mysql(janus_streaming_rtp_source *stream);
static json_t *janus_streaming_monitor_get_streams_list(void);

/* Plugin implementation */
int janus_streaming_monitor_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		return -1;
	}
	
	gateway = callback;
	
	/* Initialize mutex */
	janus_mutex_init(&streams_mutex);
	
	/* Initialize streams hash table */
	rtp_streams = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, 
		(GDestroyNotify)g_free);
	
	/* Initialize MySQL connection */
	mysql_conn = mysql_init(NULL);
	if(!mysql_real_connect(mysql_conn, mysql_host, mysql_user, mysql_password, 
						   mysql_database, mysql_port, NULL, 0)) {
		JANUS_LOG(LOG_ERR, "MySQL connection failed: %s\n", mysql_error(mysql_conn));
		mysql_close(mysql_conn);
		mysql_conn = NULL;
	} else {
		JANUS_LOG(LOG_INFO, "MySQL connected successfully\n");
		
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
	}
	
	/* Create RTP listening socket */
	rtp_listen_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if(rtp_listen_socket < 0) {
		JANUS_LOG(LOG_ERR, "Failed to create RTP listening socket\n");
		return -1;
	}
	
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(rtp_listen_port);
	
	if(bind(rtp_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		JANUS_LOG(LOG_ERR, "Failed to bind RTP listening socket to port %d\n", rtp_listen_port);
		close(rtp_listen_socket);
		return -1;
	}
	
	/* Start RTP listener thread */
	if(pthread_create(&rtp_listener_thread, NULL, 
					  (void*(*)(void*))janus_streaming_monitor_rtp_listener, NULL) != 0) {
		JANUS_LOG(LOG_ERR, "Failed to create RTP listener thread\n");
		close(rtp_listen_socket);
		return -1;
	}
	
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "Streaming Monitor plugin initialized\n");
	
	return 0;
}

void janus_streaming_monitor_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);
	
	/* Stop RTP listener */
	if(rtp_listen_socket >= 0) {
		close(rtp_listen_socket);
		rtp_listen_socket = -1;
	}
	pthread_join(rtp_listener_thread, NULL);
	
	/* Cleanup streams */
	janus_mutex_lock(&streams_mutex);
	g_hash_table_destroy(rtp_streams);
	rtp_streams = NULL;
	janus_mutex_unlock(&streams_mutex);
	
	/* Close MySQL connection */
	if(mysql_conn) {
		mysql_close(mysql_conn);
		mysql_conn = NULL;
	}
	
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "Streaming Monitor plugin destroyed\n");
}

void janus_streaming_monitor_rtp_listener(void) {
	char buffer[1500];
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	
	JANUS_LOG(LOG_INFO, "RTP listener thread started on port %d\n", rtp_listen_port);
	
	while(!g_atomic_int_get(&stopping)) {
		int bytes_received = recvfrom(rtp_listen_socket, buffer, sizeof(buffer), 0,
									  (struct sockaddr*)&client_addr, &addr_len);
		
		if(bytes_received > 0) {
			janus_streaming_monitor_process_rtp_packet(buffer, bytes_received, &client_addr);
		}
	}
	
	JANUS_LOG(LOG_INFO, "RTP listener thread stopped\n");
}

void janus_streaming_monitor_process_rtp_packet(char *buffer, int len, struct sockaddr_in *addr) {
	if(len < 12) return;  /* Invalid RTP packet */
	
	janus_rtp_header *rtp = (janus_rtp_header *)buffer;
	guint32 ssrc = ntohl(rtp->ssrc);
	char *source_ip = inet_ntoa(addr->sin_addr);
	guint16 source_port = ntohs(addr->sin_port);
	
	janus_mutex_lock(&streams_mutex);
	
	/* Find existing stream or create new one */
	janus_streaming_rtp_source *stream = NULL;
	GHashTableIter iter;
	gpointer key, value;
	
	g_hash_table_iter_init(&iter, rtp_streams);
	while(g_hash_table_iter_next(&iter, &key, &value)) {
		janus_streaming_rtp_source *s = (janus_streaming_rtp_source *)value;
		if(s->ssrc == ssrc && strcmp(s->source_ip, source_ip) == 0 && s->source_port == source_port) {
			stream = s;
			break;
		}
	}
	
	if(!stream) {
		stream = janus_streaming_monitor_create_stream(source_ip, source_port, ssrc);
		if(stream) {
			g_hash_table_insert(rtp_streams, GUINT_TO_POINTER(stream->stream_id), stream);
			JANUS_LOG(LOG_INFO, "New RTP stream detected: ID=%d, IP=%s, Port=%d, SSRC=%u\n",
					  stream->stream_id, source_ip, source_port, ssrc);
		}
	}
	
	if(stream) {
		janus_streaming_monitor_update_stream_stats(stream, len);
		
		/* Forward to viewers */
		if(stream->viewers) {
			GHashTableIter viewer_iter;
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

janus_streaming_rtp_source *janus_streaming_monitor_create_stream(const char *ip, guint16 port, guint32 ssrc) {
	janus_streaming_rtp_source *stream = g_malloc0(sizeof(janus_streaming_rtp_source));
	stream->stream_id = next_stream_id++;
	stream->source_ip = g_strdup(ip);
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
	}
	
	/* Save to MySQL */
	janus_streaming_monitor_save_to_mysql(stream);
	
	return stream;
}

void janus_streaming_monitor_update_stream_stats(janus_streaming_rtp_source *stream, int packet_size) {
	stream->last_seen = janus_get_monotonic_time();
	stream->packet_count++;
	stream->byte_count += packet_size;
	
	/* Update MySQL every 100 packets */
	if(stream->packet_count % 100 == 0) {
		janus_streaming_monitor_save_to_mysql(stream);
	}
}

void janus_streaming_monitor_save_to_mysql(janus_streaming_rtp_source *stream) {
	if(!mysql_conn) return;
	
	char query[512];
	snprintf(query, sizeof(query),
			 "INSERT INTO rtp_streams (stream_id, source_ip, source_port, ssrc, packet_count, byte_count) "
			 "VALUES (%d, '%s', %d, %u, %llu, %llu) "
			 "ON DUPLICATE KEY UPDATE "
			 "packet_count=%llu, byte_count=%llu, last_seen=NOW()",
			 stream->stream_id, stream->source_ip, stream->source_port, stream->ssrc,
			 stream->packet_count, stream->byte_count,
			 stream->packet_count, stream->byte_count);
	
	if(mysql_query(mysql_conn, query)) {
		JANUS_LOG(LOG_ERR, "MySQL query failed: %s\n", mysql_error(mysql_conn));
	}
}

/* WebSocket API message handler */
void janus_streaming_monitor_handle_message(janus_plugin_session *handle, char *transaction, 
											json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	
	janus_streaming_session *session = (janus_streaming_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR,
															  "No session associated with this handle", NULL);
		gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
		janus_plugin_result_destroy(result);
		return;
	}
	
	json_t *request = json_object_get(message, "request");
	const char *request_text = json_string_value(request);
	
	if(!strcasecmp(request_text, "list")) {
		/* Return list of active streams */
		json_t *streams_list = janus_streaming_monitor_get_streams_list();
		json_t *response = json_object();
		json_object_set_new(response, "streaming", json_string("list"));
		json_object_set_new(response, "streams", streams_list);
		
		janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
		janus_plugin_result_destroy(result);
		
	} else if(!strcasecmp(request_text, "watch")) {
		/* Watch a specific stream */
		json_t *stream_id_json = json_object_get(message, "id");
		if(!stream_id_json) {
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR,
																  "Missing stream ID", NULL);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
			return;
		}
		
		guint32 stream_id = json_integer_value(stream_id_json);
		
		janus_mutex_lock(&streams_mutex);
		janus_streaming_rtp_source *stream = g_hash_table_lookup(rtp_streams, 
																 GUINT_TO_POINTER(stream_id));
		if(stream) {
			session->watching_stream_id = stream_id;
			g_hash_table_insert(stream->viewers, session, session);
			
			json_t *response = json_object();
			json_object_set_new(response, "streaming", json_string("watch"));
			json_object_set_new(response, "result", json_string("ok"));
			
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
		} else {
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_ERROR,
																  "Stream not found", NULL);
			gateway->push_event(handle, &janus_streaming_monitor_plugin, transaction, result, NULL);
			janus_plugin_result_destroy(result);
		}
		janus_mutex_unlock(&streams_mutex);
	}
}

json_t *janus_streaming_monitor_get_streams_list(void) {
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
		json_object_set_new(stream_obj, "viewers", 
							json_integer(g_hash_table_size(stream->viewers)));
		
		json_array_append_new(streams_array, stream_obj);
	}
	janus_mutex_unlock(&streams_mutex);
	
	return streams_array;
}

/* Other required plugin functions */
janus_plugin_session *janus_streaming_monitor_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return NULL;
	}
	
	janus_streaming_session *session = g_malloc0(sizeof(janus_streaming_session));
	session->handle = handle;
	session->watching_stream_id = 0;
	session->started = FALSE;
	session->destroyed = FALSE;
	janus_mutex_init(&session->mutex);
	
	handle->plugin_handle = session;
	
	return session;
}

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
	
	/* Remove from stream viewers */
	if(session->watching_stream_id > 0) {
		janus_mutex_lock(&streams_mutex);
		janus_streaming_rtp_source *stream = g_hash_table_lookup(rtp_streams,
																 GUINT_TO_POINTER(session->watching_stream_id));
		if(stream && stream->viewers) {
			g_hash_table_remove(stream->viewers, session);
		}
		janus_mutex_unlock(&streams_mutex);
	}
	
	session->destroyed = TRUE;
	g_free(session);
	handle->plugin_handle = NULL;
}

/* Stub implementations for required functions */
int janus_streaming_monitor_get_api_compatibility(void) { return JANUS_PLUGIN_API_VERSION; }
int janus_streaming_monitor_get_version(void) { return JANUS_STREAMING_MONITOR_VERSION; }
const char *janus_streaming_monitor_get_version_string(void) { return JANUS_STREAMING_MONITOR_VERSION_STRING; }
const char *janus_streaming_monitor_get_description(void) { return JANUS_STREAMING_MONITOR_DESCRIPTION; }
const char *janus_streaming_monitor_get_name(void) { return JANUS_STREAMING_MONITOR_NAME; }
const char *janus_streaming_monitor_get_author(void) { return JANUS_STREAMING_MONITOR_AUTHOR; }
const char *janus_streaming_monitor_get_package(void) { return JANUS_STREAMING_MONITOR_PACKAGE; }
void janus_streaming_monitor_handle_admin_message(json_t *message, json_t *transaction) {}
void janus_streaming_monitor_setup_media(janus_plugin_session *handle) {}
void janus_streaming_monitor_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {}
void janus_streaming_monitor_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {}
void janus_streaming_monitor_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet) {}
void janus_streaming_monitor_data_ready(janus_plugin_session *handle) {}
void janus_streaming_monitor_slow_link(janus_plugin_session *handle, int uplink, int video) {}
void janus_streaming_monitor_hangup_media(janus_plugin_session *handle) {}
json_t *janus_streaming_monitor_query_session(janus_plugin_session *handle) { return NULL; }