/*
 * wireshark_bridge.c - VPP plugin for bridging traffic to Wireshark
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlib/unix/unix.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

// Add forward declaration for vl_api_get_main
extern void *vl_api_get_main(void);

// Make sure the packet structure is defined only once at the top
typedef struct {
  u32 sw_if_index;
  u8 *packet_data;
  u32 packet_length;
  f64 timestamp;
  u8 direction;
} wireshark_bridge_packet_t;

// Define the queue structure correctly
typedef struct {
  wireshark_bridge_packet_t *packets;
  volatile u8 should_stop;
  u32 queue_overflows;
} wireshark_bridge_queue_t;

// Declare our global queue
wireshark_bridge_queue_t wireshark_bridge_queue;

// Protocol message format
#define WIRESHARK_BRIDGE_VERSION 1

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/un.h>  // Added for Unix domain sockets

#include "wireshark_bridge.api_enum.h"
#include "wireshark_bridge.api_types.h"

// Version information
#define WIRESHARK_BRIDGE_PLUGIN_VERSION_MAJOR "1"
#define WIRESHARK_BRIDGE_PLUGIN_VERSION_MINOR "0"
#define WIRESHARK_BRIDGE_PLUGIN_VERSION_PATCH "0"

// Packet direction constants
#define WIRESHARK_BRIDGE_DIRECTION_RX 0
#define WIRESHARK_BRIDGE_DIRECTION_TX 1

// Configuration constants
#define WIRESHARK_BRIDGE_MAX_QUEUE_SIZE 10000  // Maximum packets in queue
#define WIRESHARK_BRIDGE_PACKET_HEADER_SIZE 17 // Size of packet header in bytes
#define WIRESHARK_BRIDGE_CONNECT_TIMEOUT_SEC 5 // Socket connection timeout
#define WIRESHARK_BRIDGE_BATCH_SIZE 32         // Number of packets to batch send
#define WIRESHARK_BRIDGE_MAX_DATAGRAM_SIZE 65507 // Maximum UDP datagram size

// Interface data structure
typedef struct {
  u32 sw_if_index;
  u8 is_enabled;
  u64 packets_sent_rx;
  u64 bytes_sent_rx;
  u64 packets_sent_tx;
  u64 bytes_sent_tx;
} wireshark_bridge_interface_t;

// Main plugin context structure
typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* Vector of interfaces */
  wireshark_bridge_interface_t *interfaces;
  
  /* Hash table for faster interface lookup */
  uword *interface_index_by_sw_if_index;

  /* Bridge socket */
  int bridge_socket;
  union {
    struct sockaddr_in inet_addr;  // For backward compatibility
    struct sockaddr_un unix_addr;  // For Unix domain sockets
  } bridge_addr;
  u8 bridge_connected;
  u8 use_unix_socket;  // Flag to indicate if we're using a Unix socket
  char socket_path[108];  // Store Unix socket path (max path length)

  /* Thread for sending packets */
  pthread_t sender_thread;
  u8 sender_thread_running;
  pthread_mutex_t sender_mutex;
  pthread_cond_t sender_cond;
  
  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} wireshark_bridge_main_t;

wireshark_bridge_main_t wireshark_bridge_main;

/* Forward declarations */
static void *wireshark_bridge_sender_thread_fn (void *arg);
extern vlib_node_registration_t wireshark_bridge_rx_node;
extern vlib_node_registration_t wireshark_bridge_tx_node;
static void wireshark_bridge_send_packets (wireshark_bridge_main_t * wbm, wireshark_bridge_packet_t * packets, u32 n_packets);

/* Feature registration structures */
VNET_FEATURE_INIT (wireshark_bridge_rx_feature, static) = {
  .arc_name = "device-input",
  .node_name = "wireshark-bridge-rx",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (wireshark_bridge_tx_feature, static) = {
  .arc_name = "interface-output",
  .node_name = "wireshark-bridge-tx",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

/* Packet trace structure */
typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u8 direction;
} wireshark_bridge_trace_t;

/**
 * @brief Format trace data for output
 */
static u8 *
format_wireshark_bridge_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  wireshark_bridge_trace_t *t = va_arg (*args, wireshark_bridge_trace_t *);

  s = format (s, "wireshark-bridge: sw_if_index %d, next index %d, direction %s",
              t->sw_if_index, t->next_index, t->direction ? "TX" : "RX");
  return s;
}

/**
 * @brief Find interface in the registry
 */
static wireshark_bridge_interface_t *
wireshark_bridge_find_interface (wireshark_bridge_main_t *wbm, u32 sw_if_index)
{
  uword *p;
  u32 index;
  
  p = hash_get (wbm->interface_index_by_sw_if_index, sw_if_index);
  if (p == NULL)
    return NULL;
    
  index = p[0];
  if (index >= vec_len (wbm->interfaces))
    return NULL;
    
  return &wbm->interfaces[index];
}

/**
 * @brief Add interface to the registry
 */
static wireshark_bridge_interface_t *
wireshark_bridge_add_interface (wireshark_bridge_main_t *wbm, u32 sw_if_index)
{
  wireshark_bridge_interface_t *wbi;
  u32 index;
  
  // Check if interface already exists
  wbi = wireshark_bridge_find_interface (wbm, sw_if_index);
  if (wbi)
    return wbi;
    
  // Add new interface
  wireshark_bridge_interface_t new_wbi = {0};
  new_wbi.sw_if_index = sw_if_index;
  index = vec_len (wbm->interfaces);
  vec_add1 (wbm->interfaces, new_wbi);
  hash_set (wbm->interface_index_by_sw_if_index, sw_if_index, index);
  
  return &wbm->interfaces[index];
}

/**
 * @brief Thread function for sending packets to bridge
 */
static void *
wireshark_bridge_sender_thread_fn (void *arg)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  wireshark_bridge_queue_t *queue = &wireshark_bridge_queue;
  
  while (!queue->should_stop)
    {
      // Wait for packets to process or stop signal
      pthread_mutex_lock (&wbm->sender_mutex);
      while (vec_len (queue->packets) == 0 && !queue->should_stop) {
        struct timespec ts;
        clock_gettime (CLOCK_REALTIME, &ts);
        ts.tv_sec += 1; // 1 second timeout to recheck should_stop periodically
        pthread_cond_timedwait (&wbm->sender_cond, &wbm->sender_mutex, &ts);
      }
      
      if (queue->should_stop) {
        pthread_mutex_unlock (&wbm->sender_mutex);
        break;
      }
      
      // Get packets to send
      u32 n_packets = vec_len (queue->packets);
      wireshark_bridge_packet_t *packets = queue->packets;
      
      // Clear queue for next batch
      queue->packets = 0;
      pthread_mutex_unlock (&wbm->sender_mutex);
      
      // Send packets
      if (n_packets > 0 && wbm->bridge_connected) {
        wireshark_bridge_send_packets (wbm, packets, n_packets);
      }
      
      // Free packet data
      for (u32 i = 0; i < n_packets; i++) {
        vec_free (packets[i].packet_data);
      }
      vec_free (packets);
    }
  
  return NULL;
}

/**
 * @brief Send packet to the bridge
 */
static void
wireshark_bridge_send_packet (u32 sw_if_index, u8 *packet_data, u32 packet_length, f64 timestamp, u8 direction)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  wireshark_bridge_queue_t *queue = &wireshark_bridge_queue;
  wireshark_bridge_interface_t *wbi = NULL;

  // Quick check if bridge is connected before locking
  if (!wbm->bridge_connected)
    return;

  // Find interface - use hash lookup
  wbi = wireshark_bridge_find_interface (wbm, sw_if_index);
  if (wbi == NULL || !wbi->is_enabled)
    return;

  // Lock to modify queue
  pthread_mutex_lock (&wbm->sender_mutex);
  
  // Check queue size limit
  if (vec_len (queue->packets) >= WIRESHARK_BRIDGE_MAX_QUEUE_SIZE) {
    // Queue full - increment overflow counter and drop packet
    queue->queue_overflows++;
    pthread_mutex_unlock (&wbm->sender_mutex);
    return;
  }
  
  // Create a copy of the packet data
  u8 *packet_copy = vec_new (u8, packet_length);
  clib_memcpy (packet_copy, packet_data, packet_length);
  
  // Add packet to queue
  wireshark_bridge_packet_t packet = {0};
  packet.sw_if_index = sw_if_index;
  packet.packet_data = packet_copy;
  packet.packet_length = packet_length;
  packet.timestamp = timestamp;
  packet.direction = direction;
  vec_add1 (queue->packets, packet);
  
  // Signal sender thread
  pthread_cond_signal (&wbm->sender_cond);
  
  pthread_mutex_unlock (&wbm->sender_mutex);
}

/**
 * @brief Send packets to bridge
 */
static void
wireshark_bridge_send_packets (wireshark_bridge_main_t * wbm, wireshark_bridge_packet_t * packets, u32 n_packets)
{
  /* Removed unused variables: struct iovec *iov, u32 iov_count, u32 total_size */
  u32 i;
  wireshark_bridge_interface_t *wbi = NULL;
  u8 *buffer = NULL;
  u32 buffer_offset = 0;

  // Allocate a buffer for the entire batch
  vec_validate(buffer, WIRESHARK_BRIDGE_MAX_DATAGRAM_SIZE - 1);
  
  // Process each packet
  for (i = 0; i < n_packets; i++)
    {
      wireshark_bridge_packet_t *p = &packets[i];
      
      // Find interface
      wbi = wireshark_bridge_find_interface (wbm, p->sw_if_index);
      if (!wbi || !wbi->is_enabled)
        continue;
      
      // Calculate header values
      u32 timestamp_sec = (u32) p->timestamp;
      u32 timestamp_usec = (u32) ((p->timestamp - timestamp_sec) * 1000000);
      
      // Check if this packet would exceed maximum datagram size
      if (buffer_offset + WIRESHARK_BRIDGE_PACKET_HEADER_SIZE + p->packet_length > WIRESHARK_BRIDGE_MAX_DATAGRAM_SIZE)
      {
        // Send current buffer
        if (buffer_offset > 0 && wbm->bridge_connected)
        {
          if (wbm->use_unix_socket)
          {
            ssize_t sent = sendto(wbm->bridge_socket, buffer, buffer_offset, 0,
                                 (struct sockaddr *)&wbm->bridge_addr.unix_addr,
                                 sizeof(wbm->bridge_addr.unix_addr));
            if (sent < 0)
            {
              // Handle socket error
              clib_warning ("Failed to send packets to Unix socket: %s", strerror (errno));
              close (wbm->bridge_socket);
              wbm->bridge_connected = 0;
            }
          }
          else
          {
            ssize_t sent = sendto(wbm->bridge_socket, buffer, buffer_offset, 0,
                                 (struct sockaddr *)&wbm->bridge_addr.inet_addr,
                                 sizeof(wbm->bridge_addr.inet_addr));
            if (sent < 0)
            {
              // Handle socket error
              clib_warning ("Failed to send packets to bridge: %s", strerror (errno));
              close (wbm->bridge_socket);
              wbm->bridge_connected = 0;
            }
          }
        }
        
        // Reset buffer
        buffer_offset = 0;
      }
      
      // Add header to buffer
      /* Interface index (4 bytes) */
      buffer[buffer_offset++] = (p->sw_if_index >> 24) & 0xFF;
      buffer[buffer_offset++] = (p->sw_if_index >> 16) & 0xFF;
      buffer[buffer_offset++] = (p->sw_if_index >> 8) & 0xFF;
      buffer[buffer_offset++] = p->sw_if_index & 0xFF;
      
      /* Timestamp seconds (4 bytes) */
      buffer[buffer_offset++] = (timestamp_sec >> 24) & 0xFF;
      buffer[buffer_offset++] = (timestamp_sec >> 16) & 0xFF;
      buffer[buffer_offset++] = (timestamp_sec >> 8) & 0xFF;
      buffer[buffer_offset++] = timestamp_sec & 0xFF;
      
      /* Timestamp microseconds (4 bytes) */
      buffer[buffer_offset++] = (timestamp_usec >> 24) & 0xFF;
      buffer[buffer_offset++] = (timestamp_usec >> 16) & 0xFF;
      buffer[buffer_offset++] = (timestamp_usec >> 8) & 0xFF;
      buffer[buffer_offset++] = timestamp_usec & 0xFF;
      
      /* Packet length (4 bytes) */
      buffer[buffer_offset++] = (p->packet_length >> 24) & 0xFF;
      buffer[buffer_offset++] = (p->packet_length >> 16) & 0xFF;
      buffer[buffer_offset++] = (p->packet_length >> 8) & 0xFF;
      buffer[buffer_offset++] = p->packet_length & 0xFF;
      
      /* Direction (1 byte) */
      buffer[buffer_offset++] = p->direction;
      
      // Add packet data to buffer
      clib_memcpy(buffer + buffer_offset, p->packet_data, p->packet_length);
      buffer_offset += p->packet_length;
      
      // Update statistics
      if (p->direction == WIRESHARK_BRIDGE_DIRECTION_RX) {
        wbi->packets_sent_rx++;
        wbi->bytes_sent_rx += p->packet_length;
      } else {
        wbi->packets_sent_tx++;
        wbi->bytes_sent_tx += p->packet_length;
      }
    }
  
  // Send any remaining data
  if (buffer_offset > 0 && wbm->bridge_connected)
  {
    if (wbm->use_unix_socket)
    {
      ssize_t sent = sendto(wbm->bridge_socket, buffer, buffer_offset, 0,
                           (struct sockaddr *)&wbm->bridge_addr.unix_addr,
                           sizeof(wbm->bridge_addr.unix_addr));
      if (sent < 0)
      {
        // Handle socket error
        clib_warning ("Failed to send packets to Unix socket: %s", strerror (errno));
        close (wbm->bridge_socket);
        wbm->bridge_connected = 0;
      }
    }
    else
    {
      ssize_t sent = sendto(wbm->bridge_socket, buffer, buffer_offset, 0,
                           (struct sockaddr *)&wbm->bridge_addr.inet_addr,
                           sizeof(wbm->bridge_addr.inet_addr));
      if (sent < 0)
      {
        // Handle socket error
        clib_warning ("Failed to send packets to bridge: %s", strerror (errno));
        close (wbm->bridge_socket);
        wbm->bridge_connected = 0;
      }
    }
  }
  
  vec_free(buffer);
}

/* RX Node function */
static uword
wireshark_bridge_rx_node_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_processed = 0;
  CLIB_UNUSED (wireshark_bridge_main_t *wbm) = &wireshark_bridge_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0;
          u32 sw_if_index0;
          /* Removed unused variable: ethernet_header_t *eh0 */

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
          /* Removed: eh0 = vlib_buffer_get_current (b0); */

          /* Send packet to bridge */
          wireshark_bridge_send_packet (sw_if_index0, 
                                       vlib_buffer_get_current (b0),
                                       b0->current_length,
                                       vlib_time_now(vm),
                                       WIRESHARK_BRIDGE_DIRECTION_RX);

          pkts_processed++;

          /* Используем vnet_feature_next для автоматического следования по арке */
          vnet_feature_next (&next0, b0);

          if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                             && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              wireshark_bridge_trace_t *t =
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->direction = WIRESHARK_BRIDGE_DIRECTION_RX;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* TX Node function */
static uword
wireshark_bridge_tx_node_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_processed = 0;
  CLIB_UNUSED (wireshark_bridge_main_t *wbm) = &wireshark_bridge_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0;
          u32 sw_if_index0;
          /* Removed unused variable: ethernet_header_t *eh0 */

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
          /* Removed: eh0 = vlib_buffer_get_current (b0); */

          /* Send packet to bridge */
          wireshark_bridge_send_packet (sw_if_index0, 
                                       vlib_buffer_get_current (b0),
                                       b0->current_length,
                                       vlib_time_now(vm),
                                       WIRESHARK_BRIDGE_DIRECTION_TX);

          pkts_processed++;

          /* Используем vnet_feature_next для автоматического следования по арке */
          vnet_feature_next (&next0, b0);

          if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                             && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              wireshark_bridge_trace_t *t =
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->direction = WIRESHARK_BRIDGE_DIRECTION_TX;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

#define WIRESHARK_BRIDGE_RX_N_NEXT 1
#define WIRESHARK_BRIDGE_RX_NEXT_DROP 0

/* RX Node registration */
VLIB_REGISTER_NODE (wireshark_bridge_rx_node) = {
  .function = wireshark_bridge_rx_node_fn,
  .name = "wireshark-bridge-rx",
  .vector_size = sizeof (u32),
  .format_trace = format_wireshark_bridge_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = WIRESHARK_BRIDGE_RX_N_NEXT,
  .next_nodes = {
    [WIRESHARK_BRIDGE_RX_NEXT_DROP] = "error-drop",
  },
};

#define WIRESHARK_BRIDGE_TX_N_NEXT 1
#define WIRESHARK_BRIDGE_TX_NEXT_DROP 0

/* TX Node registration */
VLIB_REGISTER_NODE (wireshark_bridge_tx_node) = {
  .function = wireshark_bridge_tx_node_fn,
  .name = "wireshark-bridge-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_wireshark_bridge_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = WIRESHARK_BRIDGE_TX_N_NEXT,
  .next_nodes = {
    [WIRESHARK_BRIDGE_TX_NEXT_DROP] = "error-drop",
  },
};

/**
 * @brief Handler for wireshark_bridge_enable API call
 */
static void
vl_api_wireshark_bridge_enable_t_handler (vl_api_wireshark_bridge_enable_t * mp)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  vl_api_wireshark_bridge_enable_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  char *bridge_address = (char *) mp->bridge_address;
  char *bridge_address_copy = NULL;
  
  // Create a copy of the bridge address for safe manipulation
  bridge_address_copy = strdup(bridge_address);
  if (!bridge_address_copy) {
    rv = VNET_API_ERROR_INVALID_VALUE;
    goto done;
  }
  
  /* Check if this is a Unix socket path (starts with /) */
  if (bridge_address[0] == '/') {
    /* Unix socket path */
    wbm->use_unix_socket = 1;
    
    /* Copy socket path, ensuring it's not too long */
    if (strlen(bridge_address) >= sizeof(wbm->socket_path)) {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
    
    strncpy(wbm->socket_path, bridge_address, sizeof(wbm->socket_path) - 1);
    wbm->socket_path[sizeof(wbm->socket_path) - 1] = '\0';
    
    /* Connect to bridge if not already connected */
    if (!wbm->bridge_connected) {
      // Close any existing socket
      if (wbm->bridge_socket > 0) {
        close (wbm->bridge_socket);
      }
      
      wbm->bridge_socket = socket (AF_UNIX, SOCK_DGRAM, 0);
      if (wbm->bridge_socket < 0) {
        rv = VNET_API_ERROR_SYSCALL_ERROR_1;
        goto done;
      }
      
      memset (&wbm->bridge_addr.unix_addr, 0, sizeof (wbm->bridge_addr.unix_addr));
      wbm->bridge_addr.unix_addr.sun_family = AF_UNIX;
      strncpy (wbm->bridge_addr.unix_addr.sun_path, wbm->socket_path, 
               sizeof(wbm->bridge_addr.unix_addr.sun_path) - 1);
      
      // For UDP, we don't need to connect, just store the address for sending
      wbm->bridge_connected = 1;
      
      /* Start sender thread if not already running */
      if (!wbm->sender_thread_running) {
        // Initialize packet queue
        wireshark_bridge_queue.packets = 0; /* Initialize empty vector */
        wireshark_bridge_queue.should_stop = 0;
        wireshark_bridge_queue.queue_overflows = 0;
        
        if (pthread_create (&wbm->sender_thread, NULL, wireshark_bridge_sender_thread_fn, NULL) != 0) {
          close (wbm->bridge_socket);
          wbm->bridge_connected = 0;
          rv = VNET_API_ERROR_SYSCALL_ERROR_3;
          goto done;
        }
        
        wbm->sender_thread_running = 1;
      }
    }
  } else {
    /* Traditional IP:port address */
    wbm->use_unix_socket = 0;
    
    /* Parse bridge address - use the copy for safe manipulation */
    char *colon = strchr (bridge_address_copy, ':');
    if (colon == NULL) {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
    
    *colon = '\0';  // Safely modify our copy
    char *ip_address = bridge_address_copy;
    int port = atoi (colon + 1);
    
    if (port <= 0 || port > 65535) {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
    
    /* Connect to bridge if not already connected */
    if (!wbm->bridge_connected) {
      // Close any existing socket
      if (wbm->bridge_socket > 0) {
        close (wbm->bridge_socket);
      }
      
      wbm->bridge_socket = socket (AF_INET, SOCK_DGRAM, 0);
      if (wbm->bridge_socket < 0) {
        rv = VNET_API_ERROR_SYSCALL_ERROR_1;
        goto done;
      }
      
      /* Set socket options */
      int optval = 1;
      if (setsockopt (wbm->bridge_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        clib_warning ("Failed to set SO_KEEPALIVE: %s", strerror (errno));
      }
      
      // For UDP, we don't need to connect, just store the address for sending
      wbm->bridge_connected = 1;
      wbm->use_unix_socket = 0;
      
      /* Set socket address */
      memset (&wbm->bridge_addr.inet_addr, 0, sizeof (wbm->bridge_addr.inet_addr));
      wbm->bridge_addr.inet_addr.sin_family = AF_INET;
      wbm->bridge_addr.inet_addr.sin_port = htons (port);
      
      if (inet_pton (AF_INET, ip_address, &wbm->bridge_addr.inet_addr.sin_addr) <= 0) {
        rv = VNET_API_ERROR_INVALID_VALUE;
        close (wbm->bridge_socket);
        goto done;
      }
    }
  }
  
  /* Enable packet capture on the interface */
  wireshark_bridge_interface_t *wb_if = wireshark_bridge_find_interface (wbm, sw_if_index);
  if (wb_if == NULL) {
    wb_if = wireshark_bridge_add_interface (wbm, sw_if_index);
    if (wb_if == NULL) {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto done;
    }
  }
  
  /* Only enable features if interface is not already enabled */
  if (!wb_if->is_enabled) {
    /* Enable feature nodes */
    vnet_feature_enable_disable ("device-input", "wireshark-bridge-rx", sw_if_index, 1, 0, 0);
    vnet_feature_enable_disable ("interface-output", "wireshark-bridge-tx", sw_if_index, 1, 0, 0);
  }
  
  wb_if->is_enabled = 1;

done:
  if (bridge_address_copy) {
    free(bridge_address_copy);
  }

  /* Send reply */
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs(VL_API_WIRESHARK_BRIDGE_ENABLE_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl(rv);
  
  vl_api_send_msg (vl_api_get_main(), (u8 *) rmp);
}

static void
vl_api_wireshark_bridge_disable_t_handler (vl_api_wireshark_bridge_disable_t * mp)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  vl_api_wireshark_bridge_disable_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  
  /* Disable interface */
  u32 i;
  wireshark_bridge_interface_t *wbi = NULL;
  
  for (i = 0; i < vec_len(wbm->interfaces); i++)
    {
      if (wbm->interfaces[i].sw_if_index == sw_if_index)
        {
          wbi = &wbm->interfaces[i];
          break;
        }
    }
  
  if (wbi != NULL)
    {
      wbi->is_enabled = 0;
    }
  
  /* Check if all interfaces are disabled */
  u8 all_disabled = 1;
  for (i = 0; i < vec_len(wbm->interfaces); i++)
    {
      if (wbm->interfaces[i].is_enabled)
        {
          all_disabled = 0;
          break;
        }
    }
  
  /* Disconnect from bridge if all interfaces are disabled */
  if (all_disabled && wbm->bridge_connected)
    {
      /* Stop sender thread */
      if (wbm->sender_thread_running)
        {
          wireshark_bridge_queue.should_stop = 1;
          pthread_join(wbm->sender_thread, NULL);
          wbm->sender_thread_running = 0;
        }
      
      close(wbm->bridge_socket);
      wbm->bridge_connected = 0;
    }
  
  /* Send reply */
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs(VL_API_WIRESHARK_BRIDGE_DISABLE_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  
  vl_api_send_msg (vl_api_get_main(), (u8 *) rmp);
}

static void
vl_api_wireshark_bridge_get_interfaces_t_handler (vl_api_wireshark_bridge_get_interfaces_t * mp)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  vl_api_wireshark_bridge_get_interfaces_reply_t *rmp;
  vnet_main_t *vnm = wbm->vnet_main;
  int rv = 0;
  
  /* Count interfaces */
  u32 count = 0;
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si;
  
  /* *INDENT-OFF* */
  pool_foreach (si, im->sw_interfaces)
   {
    if (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
      count++;
  }
  /* *INDENT-ON* */
  
  /* Allocate space for interface info */
  vl_api_interface_info_t *interfaces = 0;
  vec_validate (interfaces, count - 1);
  
  /* Fill interface data */
  u32 i = 0;
  /* *INDENT-OFF* */
  pool_foreach (si, im->sw_interfaces)
   {
    if (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP && i < count)
      {
        interfaces[i].sw_if_index = htonl (si->sw_if_index);
        
        /* Get interface name */
        u8 *if_name = format (0, "%U%c", format_vnet_sw_interface_name, vnm, si, 0);
        strncpy ((char *) interfaces[i].name, (char *) if_name, 63);
        interfaces[i].name[63] = '\0';
        vec_free (if_name);
        
        i++;
      }
  }
  /* *INDENT-ON* */
  
  /* Allocate message with space for interface data */
  u32 msg_size = sizeof (*rmp) + count * sizeof (vl_api_interface_info_t);
  rmp = vl_msg_api_alloc (msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_WIRESHARK_BRIDGE_GET_INTERFACES_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  rmp->count = htonl (count);
  
  /* Copy interface data to the message */
  if (count > 0) {
    vl_api_interface_info_t *rmp_interfaces = (vl_api_interface_info_t *) (rmp + 1);
    memcpy(rmp_interfaces, interfaces, count * sizeof(vl_api_interface_info_t));
  }
  
  vl_api_send_msg (vl_api_get_main(), (u8 *) rmp);
  
  /* Free allocated memory */
  vec_free (interfaces);
}

static void
vl_api_wireshark_bridge_get_stats_t_handler (vl_api_wireshark_bridge_get_stats_t * mp)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  vl_api_wireshark_bridge_get_stats_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  
  /* Count interfaces */
  u32 count = 0;
  u32 i;
  
  if (sw_if_index != ~0)
    {
      /* Single interface */
      for (i = 0; i < vec_len(wbm->interfaces); i++)
        {
          if (wbm->interfaces[i].sw_if_index == sw_if_index)
            {
              count = 1;
              break;
            }
        }
    }
  else
    {
      /* All interfaces */
      count = vec_len(wbm->interfaces);
    }
  
  /* Allocate space for stats */
  vl_api_interface_stats_t *stats = 0;
  vec_validate (stats, count - 1);
  
  /* Fill statistics */
  if (sw_if_index != ~0)
    {
      /* Single interface */
      for (i = 0; i < vec_len(wbm->interfaces); i++)
        {
          if (wbm->interfaces[i].sw_if_index == sw_if_index)
            {
              stats[0].sw_if_index = htonl (wbm->interfaces[i].sw_if_index);
              stats[0].packets_sent_rx = clib_host_to_net_u64 (wbm->interfaces[i].packets_sent_rx);
              stats[0].bytes_sent_rx = clib_host_to_net_u64 (wbm->interfaces[i].bytes_sent_rx);
              stats[0].packets_sent_tx = clib_host_to_net_u64 (wbm->interfaces[i].packets_sent_tx);
              stats[0].bytes_sent_tx = clib_host_to_net_u64 (wbm->interfaces[i].bytes_sent_tx);
              break;
            }
        }
    }
  else
    {
      /* All interfaces */
      for (i = 0; i < vec_len(wbm->interfaces); i++)
        {
          stats[i].sw_if_index = htonl (wbm->interfaces[i].sw_if_index);
          stats[i].packets_sent_rx = clib_host_to_net_u64 (wbm->interfaces[i].packets_sent_rx);
          stats[i].bytes_sent_rx = clib_host_to_net_u64 (wbm->interfaces[i].bytes_sent_rx);
          stats[i].packets_sent_tx = clib_host_to_net_u64 (wbm->interfaces[i].packets_sent_tx);
          stats[i].bytes_sent_tx = clib_host_to_net_u64 (wbm->interfaces[i].bytes_sent_tx);
        }
    }
  
  /* Allocate message with space for stats data */
  u32 msg_size = sizeof (*rmp) + count * sizeof (vl_api_interface_stats_t);
  rmp = vl_msg_api_alloc (msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_WIRESHARK_BRIDGE_GET_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  rmp->count = htonl (count);
  
  /* Copy stats data to the message */
  if (count > 0) {
    vl_api_interface_stats_t *rmp_stats = (vl_api_interface_stats_t *) (rmp + 1);
    memcpy(rmp_stats, stats, count * sizeof(vl_api_interface_stats_t));
  }
  
  vl_api_send_msg (vl_api_get_main(), (u8 *) rmp);
  
  /* Free allocated memory */
  vec_free (stats);
}

/* CLI command functions */

/**
 * @brief CLI command to enable the Wireshark bridge for an interface
 */
static clib_error_t *
wireshark_bridge_enable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  u32 sw_if_index = ~0;
  char *bridge_address = 0;
  char *bridge_address_copy = 0;  // Create a copy for safe manipulation

  /* Parse arguments */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, wbm->vnet_main, &sw_if_index))
        ;
      else if (unformat (input, "%s", &bridge_address))
        ;
      else
        return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface not specified");

  if (!bridge_address)
    return clib_error_return (0, "Bridge address not specified");

  // Create a copy of the bridge address to safely manipulate
  bridge_address_copy = strdup(bridge_address);
  if (!bridge_address_copy)
    return clib_error_return (0, "Memory allocation failed");

  /* Check if this is a Unix socket path (starts with /) */
  if (bridge_address[0] == '/') {
    /* Unix socket path */
    wbm->use_unix_socket = 1;
    
    /* Copy socket path, ensuring it's not too long */
    if (strlen(bridge_address) >= sizeof(wbm->socket_path)) {
      free(bridge_address_copy);
      return clib_error_return (0, "Unix socket path too long");
    }
    
    strncpy(wbm->socket_path, bridge_address, sizeof(wbm->socket_path) - 1);
    wbm->socket_path[sizeof(wbm->socket_path) - 1] = '\0';
    
    /* Connect to bridge if not already connected */
    if (wbm->bridge_socket > 0) {
      close (wbm->bridge_socket);
    }
    
    wbm->bridge_socket = socket (AF_UNIX, SOCK_DGRAM, 0);
    if (wbm->bridge_socket < 0) {
      free(bridge_address_copy);
      return clib_error_return (0, "Failed to create socket: %s", strerror (errno));
    }
    
    memset (&wbm->bridge_addr.unix_addr, 0, sizeof (wbm->bridge_addr.unix_addr));
    wbm->bridge_addr.unix_addr.sun_family = AF_UNIX;
    strncpy (wbm->bridge_addr.unix_addr.sun_path, wbm->socket_path, 
             sizeof(wbm->bridge_addr.unix_addr.sun_path) - 1);
    
    // For UDP, we don't need to connect, just store the address for sending
    wbm->bridge_connected = 1;
    
    /* Start sender thread if not already running */
    if (!wbm->sender_thread_running) {
      pthread_mutex_lock (&wbm->sender_mutex);
      wireshark_bridge_queue.packets = 0; /* Initialize empty vector */
      wireshark_bridge_queue.should_stop = 0;
      wireshark_bridge_queue.queue_overflows = 0;
      pthread_mutex_unlock (&wbm->sender_mutex);
      
      if (pthread_create (&wbm->sender_thread, NULL, wireshark_bridge_sender_thread_fn, NULL) != 0) {
        close (wbm->bridge_socket);
        wbm->bridge_connected = 0;
        free(bridge_address_copy);
        return clib_error_return (0, "Failed to create sender thread: %s", strerror (errno));
      }
      
      wbm->sender_thread_running = 1;
    }
  } else {
    /* Traditional IP:port address */
    wbm->use_unix_socket = 0;
    
    /* Parse bridge address - use the copy for manipulation */
    char *colon = strchr (bridge_address_copy, ':');
    if (colon == NULL) {
      free(bridge_address_copy);
      return clib_error_return (0, "Invalid bridge address format, expected IP:PORT");
    }
    
    *colon = '\0';  // Safely modify our copy
    char *ip_address = bridge_address_copy;
    int port = atoi (colon + 1);
    
    if (port <= 0 || port > 65535) {
      free(bridge_address_copy);
      return clib_error_return (0, "Invalid port number");
    }
    
    /* Connect to bridge if not already connected */
    // Close any existing socket
    if (wbm->bridge_socket > 0) {
      close (wbm->bridge_socket);
    }
    
    wbm->bridge_socket = socket (AF_INET, SOCK_DGRAM, 0);
    if (wbm->bridge_socket < 0) {
      free(bridge_address_copy);
      return clib_error_return (0, "Failed to create socket: %s", strerror (errno));
    }
    
    /* Set socket options */
    int optval = 1;
    if (setsockopt (wbm->bridge_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
      clib_warning ("Failed to set SO_KEEPALIVE: %s", strerror (errno));
    }
    
    // For UDP, we don't need to connect, just store the address for sending
    wbm->bridge_connected = 1;
    wbm->use_unix_socket = 0;
    
    /* Set socket address */
    memset (&wbm->bridge_addr.inet_addr, 0, sizeof (wbm->bridge_addr.inet_addr));
    wbm->bridge_addr.inet_addr.sin_family = AF_INET;
    wbm->bridge_addr.inet_addr.sin_port = htons (port);
    
    if (inet_pton (AF_INET, ip_address, &wbm->bridge_addr.inet_addr.sin_addr) <= 0) {
      close (wbm->bridge_socket);
      wbm->bridge_connected = 0;
      free(bridge_address_copy);
      return clib_error_return (0, "Invalid IP address");
    }
  }

  /* Start sender thread if not already running */
  if (!wbm->sender_thread_running) {
    pthread_mutex_lock (&wbm->sender_mutex);
    wireshark_bridge_queue.packets = 0; /* Initialize empty vector */
    wireshark_bridge_queue.should_stop = 0;
    wireshark_bridge_queue.queue_overflows = 0;
    pthread_mutex_unlock (&wbm->sender_mutex);
    
    if (pthread_create (&wbm->sender_thread, NULL, wireshark_bridge_sender_thread_fn, NULL) != 0) {
      close (wbm->bridge_socket);
      wbm->bridge_connected = 0;
      free(bridge_address_copy);
      return clib_error_return (0, "Failed to create sender thread: %s", strerror (errno));
    }
    
    wbm->sender_thread_running = 1;
  }

  /* Free our copy now that we're done with it */
  free(bridge_address_copy);

  /* Enable packet capture on the interface */
  wireshark_bridge_interface_t *wb_if = wireshark_bridge_find_interface (wbm, sw_if_index);
  if (wb_if == NULL) {
    wb_if = wireshark_bridge_add_interface (wbm, sw_if_index);
    if (wb_if == NULL) {
      return clib_error_return (0, "Failed to add interface");
    }
  }
  
  /* Only enable features if interface is not already enabled */
  if (!wb_if->is_enabled) {
    /* Enable feature nodes */
    vnet_feature_enable_disable ("device-input", "wireshark-bridge-rx", sw_if_index, 1, 0, 0);
    vnet_feature_enable_disable ("interface-output", "wireshark-bridge-tx", sw_if_index, 1, 0, 0);
  }
  
  wb_if->is_enabled = 1;

  return clib_error_return (0, "Wireshark bridge enabled for interface %U",
                           format_vnet_sw_if_index_name, wbm->vnet_main, sw_if_index);
}

/**
 * @brief CLI command to disable the Wireshark bridge for an interface
 */
static clib_error_t *
wireshark_bridge_disable_command_fn (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  u32 sw_if_index = ~0;
  int found = 0;
  u32 i;

  /* Parse arguments */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, wbm->vnet_main, &sw_if_index))
        ;
      else
        return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface not specified");

  /* Find interface in the vector */
  pthread_mutex_lock (&wbm->sender_mutex);
  for (i = 0; i < vec_len (wbm->interfaces); i++)
    {
      if (wbm->interfaces[i].sw_if_index == sw_if_index)
        {
          found = 1;
          wbm->interfaces[i].is_enabled = 0;
          break;
        }
    }
  pthread_mutex_unlock (&wbm->sender_mutex);

  if (!found)
    return clib_error_return (0, "Interface not found in bridge");

  /* Disable feature nodes */
  vnet_feature_enable_disable ("device-input", "wireshark-bridge-rx", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("interface-output", "wireshark-bridge-tx", sw_if_index, 0, 0, 0);

  vlib_cli_output (vm, "Wireshark bridge disabled for interface %U",
                  format_vnet_sw_if_index_name, wbm->vnet_main, sw_if_index);

  return 0;
}

/**
 * @brief CLI command to show Wireshark bridge statistics
 */
static clib_error_t *
wireshark_bridge_stats_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  u32 sw_if_index = ~0;
  int show_one = 0;
  u32 i;

  /* Parse arguments */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, wbm->vnet_main, &sw_if_index))
        show_one = 1;
      else
        return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  /* Print header */
  vlib_cli_output (vm, "%-25s %-10s %-15s %-15s %-15s %-15s",
                  "Interface", "Enabled", "RX Packets", "RX Bytes", "TX Packets", "TX Bytes");
  vlib_cli_output (vm, "-------------------------------------------------------------------------");

  pthread_mutex_lock (&wbm->sender_mutex);
  if (show_one)
    {
      /* Show stats for specific interface */
      for (i = 0; i < vec_len (wbm->interfaces); i++)
        {
          if (wbm->interfaces[i].sw_if_index == sw_if_index)
            {
              vlib_cli_output (vm, "%-25U %-10s %-15llu %-15llu %-15llu %-15llu",
                              format_vnet_sw_if_index_name, wbm->vnet_main, wbm->interfaces[i].sw_if_index,
                              wbm->interfaces[i].is_enabled ? "Yes" : "No",
                              wbm->interfaces[i].packets_sent_rx,
                              wbm->interfaces[i].bytes_sent_rx,
                              wbm->interfaces[i].packets_sent_tx,
                              wbm->interfaces[i].bytes_sent_tx);
              break;
            }
        }
    }
  else
    {
      /* Show stats for all interfaces */
      for (i = 0; i < vec_len (wbm->interfaces); i++)
        {
          vlib_cli_output (vm, "%-25U %-10s %-15llu %-15llu %-15llu %-15llu",
                          format_vnet_sw_if_index_name, wbm->vnet_main, wbm->interfaces[i].sw_if_index,
                          wbm->interfaces[i].is_enabled ? "Yes" : "No",
                          wbm->interfaces[i].packets_sent_rx,
                          wbm->interfaces[i].bytes_sent_rx,
                          wbm->interfaces[i].packets_sent_tx,
                          wbm->interfaces[i].bytes_sent_tx);
        }
    }
  pthread_mutex_unlock (&wbm->sender_mutex);

  return 0;
}

/* CLI command definitions */
VLIB_CLI_COMMAND (wireshark_bridge_enable_command, static) = {
  .path = "wireshark bridge enable",
  .short_help = "wireshark bridge enable <interface> <bridge_address> - where bridge_address can be IP:port or /path/to/unix/socket",
  .function = wireshark_bridge_enable_command_fn,
};

VLIB_CLI_COMMAND (wireshark_bridge_disable_command, static) = {
  .path = "wireshark bridge disable",
  .short_help = "wireshark bridge disable <interface>",
  .function = wireshark_bridge_disable_command_fn,
};

VLIB_CLI_COMMAND (wireshark_bridge_stats_command, static) = {
  .path = "wireshark bridge stats",
  .short_help = "wireshark bridge stats [<interface>]",
  .function = wireshark_bridge_stats_command_fn,
};

/* API definitions */
#include <wireshark_bridge/wireshark_bridge.api.c>

/**
 * @brief Initialize the plugin
 */
static clib_error_t *
wireshark_bridge_init (vlib_main_t * vm)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  clib_error_t *error = 0;

  wbm->vlib_main = vm;
  wbm->vnet_main = vnet_get_main();
  wbm->ethernet_main = ethernet_get_main(vm);
  
  /* Initialize API */
  wbm->msg_id_base = setup_message_id_table ();
  
  /* Initialize interfaces vector and hash table */
  wbm->interfaces = 0; /* Initialize empty vector */
  wbm->interface_index_by_sw_if_index = hash_create (0, sizeof (uword));
  
  /* Initialize bridge socket and sender thread */
  wbm->bridge_socket = -1;
  wbm->bridge_connected = 0;
  wbm->use_unix_socket = 0;  /* Default to TCP socket */
  memset(wbm->socket_path, 0, sizeof(wbm->socket_path));
  
  /* Initialize mutex and condition variable */
  pthread_mutex_init (&wbm->sender_mutex, NULL);
  pthread_cond_init (&wbm->sender_cond, NULL);
  wbm->sender_thread_running = 0;
  
  /* Initialize packet queue */
  wireshark_bridge_queue.packets = 0; /* Initialize empty vector */
  wireshark_bridge_queue.should_stop = 0;
  wireshark_bridge_queue.queue_overflows = 0;
  
  return error;
}

/**
 * @brief Clean up resources when plugin is unloaded
 */
static clib_error_t *
wireshark_bridge_exit (vlib_main_t * vm)
{
  wireshark_bridge_main_t *wbm = &wireshark_bridge_main;
  
  /* Stop sender thread */
  if (wbm->sender_thread_running) {
    pthread_mutex_lock (&wbm->sender_mutex);
    wireshark_bridge_queue.should_stop = 1;
    pthread_cond_signal (&wbm->sender_cond);
    pthread_mutex_unlock (&wbm->sender_mutex);
    
    pthread_join (wbm->sender_thread, NULL);
    wbm->sender_thread_running = 0;
  }
  
  /* Close socket */
  if (wbm->bridge_socket > 0) {
    close (wbm->bridge_socket);
    wbm->bridge_socket = -1;
    wbm->bridge_connected = 0;
  }
  
  /* Free resources */
  vec_free (wbm->interfaces);
  hash_free (wbm->interface_index_by_sw_if_index);
  
  /* Destroy synchronization primitives */
  pthread_mutex_destroy (&wbm->sender_mutex);
  pthread_cond_destroy (&wbm->sender_cond);
  
  return 0;
}

VLIB_INIT_FUNCTION (wireshark_bridge_init);
VLIB_MAIN_LOOP_EXIT_FUNCTION (wireshark_bridge_exit);

/* Plugin definition */
VLIB_PLUGIN_REGISTER () = {
  .version = WIRESHARK_BRIDGE_PLUGIN_VERSION_MAJOR "." WIRESHARK_BRIDGE_PLUGIN_VERSION_MINOR "." WIRESHARK_BRIDGE_PLUGIN_VERSION_PATCH,
  .description = "Wireshark Bridge Plugin",
};
