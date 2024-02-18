#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>

#include "chord.h"
#include "chord_arg_parser.h"
#define MAX_CLIENTS 1024

/* macro for finding min of two comparable values */
#define min(a,b) ( (a) < (b) ? (a) : (b) ) 

/* Bundles relevant arguments the dedicated threads may need into this struct */
struct argsToThread {
  struct chord_arguments args;
};

void *req_handler( void *clientfd ); /* this chord instance should be able to process requests from several other instances */
void *stabilize( void *args ); /* executed by a dedicated thread that runs in the background stabilizing periodically */
void *check_predecessor( void *args );/* executed by a dedicated thread that runs in the background checking this instance's pred periodically */
void *fix_fingers( void *args ); /* refresh my finger table entries periodically */
void *cmd_handler( void *args ); /* executed by a dedicated thread that runs in the background processing stdin commands */

NetworkAddr config_my_server( struct chord_arguments args );
int connect_to_peer( char *peerip, int peerport );
void get_cmd( char **cmd, char **key ); /* parses command input from stdin */
uint64_t compute_key_hash( char *key ); /* hashes the key str to some 64 bit value */
uint64_t make_id( char *ip, size_t ip_len, uint32_t port );
void create( struct chord_arguments args );
void join( struct chord_arguments args );
void notify( int peerfd );/* peerfd is a connected socket to the node being notified */
Node *get_successor_list( int peer_fd, int *ret_len ); /* get my successor's successor list */
Node *find_successor( int peer_fd, uint64_t target_key ); /* recursively find the successor of the given target key hash */
void print_state();
void lookup( char *key, int my_client_fd );
int read_msg_from_peer( int sockfd, ChordMessage **chord_msg );/* we may get a ChordMessage from a peer */
int write_msg_to_peer( int sockfd, ChordMessage *chord_msg );/* we may want to write a ChordMessage to a peer */
void construct_finger_table( int contact_fd );
int accept_a_connection( void );
Node *get_predecessor( int peer_fd ); /* needed by stabilizing */
Node *closest_preceding_node( uint64_t key ); /* queries this host's finger table for the node closest to the one responsible for key */
#endif
