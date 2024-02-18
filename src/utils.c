#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <endian.h>
#include <netdb.h>
#include "utils.h"
#include "chord_arg_parser.h"
#include "chord.pb-c.h"
#include "hash.h"
#include "chord.h"

/* Non-NULL only if this chord instance is participating in a ring */
ChordNode *self = NULL;/* calls to create() and join() should define its value */
pthread_mutex_t self_mutex;

/* server-side address settings for this chord instance -- accept() can be called on addr.sockfd */
NetworkAddr config_my_server( struct chord_arguments args ) {
  int serverfd, ret = 0;
  struct sockaddr_in server_addr;
  NetworkAddr addr;

  serverfd = socket( AF_INET, SOCK_STREAM, 0 );
  assert( serverfd >= 0 );

  /* the arg parser should've filled args->my_address with the relevant info */
  server_addr = args.my_address;

  ret = bind(serverfd, (struct sockaddr *)&server_addr, sizeof(server_addr) );
  assert( ret != -1 );

  ret = listen( serverfd, MAX_CLIENTS );
  assert( ret != -1 );

  /* set socket, port, and ip fields of the NetworkAddr */
  addr.sockfd = serverfd;
  addr.port = ntohs( server_addr.sin_port );
  char *my_ip = inet_ntoa( server_addr.sin_addr );
  assert( my_ip != NULL );
  strcpy( addr.ip, my_ip );/* copy the ip into my NetworkAddr */

  return addr;

}


/* establishes a client connection to the sever side of a peer and returns the socket descriptor */
int connect_to_peer( char *peerip, int peerport ) {
  int clientfd = -1;
  struct sockaddr_in server_addr;

  clientfd = socket( AF_INET, SOCK_STREAM, 0 );

  /* configure socket server address settings for the peer */
  memset( &server_addr, 0, sizeof(server_addr) );
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons( peerport );
  server_addr.sin_addr.s_addr = inet_addr( peerip );

  /* establish the connection and return the connected socket descriptor */
  connect( clientfd, (struct sockaddr*)&server_addr, sizeof(server_addr) );

  return clientfd;

}


/* returns the 64 bit hash of the string argument key */
uint64_t compute_key_hash( char *key ) {
  uint8_t *hash_val = (uint8_t *)malloc( 20 * sizeof(uint8_t) );/* must be able to hold atleast 20 bytes */
  struct sha1sum_ctx *ctx = sha1sum_create(NULL, 0);/* hashing context */
  assert( ctx != NULL );

  sha1sum_finish(ctx, (uint8_t *)key, strlen(key), hash_val );
  sha1sum_reset(ctx); /* reset the context */

  /* return the first 8 bytes of the computed hash value */
  return sha1sum_truncated_head( hash_val );
}


/* will compute the 64 bit id of the chord instance with the given ip and port */
uint64_t make_id( char *ip, size_t ip_len, uint32_t port ) {
  uint8_t *hash_val = (uint8_t *)malloc( 20 * sizeof(uint8_t) );
  struct sha1sum_ctx *ctx = sha1sum_create(NULL, 0);
  assert( ctx != NULL );

  /* we only need the bytes in the ip and port arguments without any context given to the bytes */
  uint8_t *material = (uint8_t *)malloc( ip_len + 4 ); /* memory large enough to hold the concatenated bytes */
  memcpy( material, ip, ip_len );/* copy the ip bytes */
  memcpy( material+ip_len, &port, 4 );/* append the 4 byte port number */

  sha1sum_finish(ctx, material, ip_len+4, hash_val );
  sha1sum_reset(ctx);

  return sha1sum_truncated_head( hash_val );

}



/* begins a new logical ring for this chord instance */
void create( struct chord_arguments args ) {
  self = (ChordNode *)malloc( sizeof(ChordNode) );
  self->myserveraddr = config_my_server( args );/* get a NetworkAddr */
  char *my_ip = self->myserveraddr.ip;
  size_t ip_len = strlen( self->myserveraddr.ip );

  if( args.id == 0 /* default value => no specific id given */ ) {
    self->id = make_id( my_ip, ip_len, (self->myserveraddr).port ); 
  } else {
    self->id = args.id;
  }

  self->pred = NULL; /* for now, no predecessor to hold hands with */   
  self->r = args.num_successors;

  /* initial successor list for this instance is the instance, self->r times */
  self->succ = (Node *)malloc( sizeof(Node) * self->r );
  Node self_node;/* Node version of self(a ChordNode type ) */
  self_node.key = self->id;
  self_node.address = be32toh( args.my_address.sin_addr.s_addr );
  self_node.port = (self->myserveraddr).port;
  int r = self->r;
  int i = 0;
  while( r ) {
    (self->succ)[i] = self_node;
    --r;
    ++i;
  }

  /* initialize its finger table */
  int M = 64;
  for( int j = 0; j < M; j++ ) {
    self->finger_table[j].start = ( self->id + (1 << j) ) % ( 1 << M );
    self->finger_table[j].node = (Node *)malloc( sizeof(Node) );
    *(self->finger_table[j].node) = self_node; /* responsible for all key queries */
  }

}


/* adds this chord instance to an existing ring */
void join( struct chord_arguments args ) {    
  self = (ChordNode *)malloc( sizeof(ChordNode) );
  self->myserveraddr = config_my_server( args );
  char *my_ip = self->myserveraddr.ip;
  size_t ip_len = strlen( self->myserveraddr.ip );

  if( args.id == 0 /* default value => no specific id given */ ) {
    self->id = make_id( my_ip, ip_len, (self->myserveraddr).port ); 
  } else {
    self->id = args.id;
  }

  self->pred = NULL;  
  self->r = args.num_successors;

  /* find the position of this chord in the ring and construct its successor list */
  self->succ = (Node *)malloc( self->r * sizeof(Node) );
  /* to find my position, recursively find my successor starting from the contact node */
  char *contact_ip = inet_ntoa( args.join_address.sin_addr );
  int contact_port = args.join_address.sin_port;
  int contact_fd = connect_to_peer( contact_ip, contact_port );
  Node *succ = find_successor( contact_fd, self->id );
  self->succ[0] = *succ;/* my successor will be the first node in my succ list */

  /* get my successor's succ list and append (self->r - 1) nodes to complete my succ list */
  struct in_addr addr;
  addr.s_addr = htobe32( succ->address );
  char *succ_ip = inet_ntoa( addr );
  int succ_port = succ->port;
  int succ_list_len = 0;
  int succ_fd = connect_to_peer( succ_ip, succ_port );
  Node *succ_list = get_successor_list( succ_fd, &succ_list_len );
  close( succ_fd );
  if( succ_list_len == 0 ) {/* pad my succ list with self->succ[0] */
    for( int i = 1; i < self->r; i++ )
      self->succ[i] = self->succ[0];
    close( contact_fd );
    return;
  }
  int num_succ = min( self->r, succ_list_len );
  for( int i = 0; i < num_succ; i++ ) {
    self->succ[i+1] = succ_list[i];
  }

  /* if my r value is greater than that of my succ, pad my succ list with the last node in succ_list */
  if( num_succ < self->r ) {
    for( int i = num_succ; i < self->r; i++ ) {
      self->succ[i] = succ_list[num_succ - 1];
    }
  }

  construct_finger_table( contact_fd );
  close( contact_fd );

}


/* called after join() -- populate my finger table entries */
void construct_finger_table( int contact_fd ) {
  int M = 64;
  for( int i = 0; i < M; i++ ) {/* recursively find start's owner, starting from contact node */
    self->finger_table[i].start = ( self->id + (1 << i) ) % ( 1 << M );
    self->finger_table[i].node = find_successor( contact_fd, self->finger_table[i].start );
  }
}

/* called when joining an existing ring */
Node *get_successor_list( int peer_fd, int *ret_len ) {

  /* write the request to the successor */
  ChordMessage getsucclist_message;
  chord_message__init( &getsucclist_message );
  getsucclist_message.msg_case = CHORD_MESSAGE__MSG_GET_SUCCESSOR_LIST_REQUEST;
  GetSuccessorListRequest getsucc_req;
  get_successor_list_request__init( &getsucc_req );
  getsucclist_message.get_successor_list_request = &getsucc_req;
  write_msg_to_peer( peer_fd, &getsucclist_message );

  /* read the response from the successor */
  ChordMessage *response;
  read_msg_from_peer( peer_fd, &response );
  GetSuccessorListResponse *succ_response = response->get_successor_list_response;

  /* store the list into a Node buffer, free resources being used by the response and return the list */
  int n = succ_response->n_successors;
  Node *ret = (Node *)malloc( n * sizeof(Node) );
  *ret_len = n;/* number of nodes back to the caller of this function */
  if( n == 0 ) {
    return NULL;
  }
  for( int i = 0; i < n; i++ ) {
    ret[i] = **(succ_response->successors+i);
  }

  chord_message__free_unpacked( response, NULL );
  return ret;
}


/* refresh all entries -- one per update period */
void *fix_fingers( void *args ) { /* needed since nodes may join and leave the network at random */
  struct chord_arguments arguments = ( (struct argsToThread *)args )->args;   
  int M = 64;
  char *my_ip = inet_ntoa( arguments.my_address.sin_addr );
  int my_port = ntohs( arguments.my_address.sin_port );
  uint64_t start = 0;
  int my_client_fd = 0;
  Node *ret = NULL;

  pthread_detach( pthread_self() );

  int entry = 0; /* fix one per update period */

  while( 1 ) {

    usleep( arguments.fix_fingers_period * 1000 );
    if( entry < M ) {
      pthread_mutex_lock( &self_mutex );
      self->finger_table[entry].start = ( self->id + (1 << entry) ) % ( 1 << M );
      start = self->finger_table[entry].start;
      pthread_mutex_unlock( &self_mutex );

      my_client_fd = connect_to_peer( my_ip, my_port );
      ret = find_successor( my_client_fd, start );
      close( my_client_fd );

      pthread_mutex_lock( &self_mutex );
      self->finger_table[entry].node = ret;
      pthread_mutex_unlock( &self_mutex );
      ++entry;
    } else {
      entry = 0;/* start all over*/
    }

  }
  return NULL;
}


/* command processing -- executed by a dedicated thread */
void *cmd_handler( void *args ) {
  struct chord_arguments arguments = ( (struct argsToThread *)args )->args;    
  char *my_ip = inet_ntoa( arguments.my_address.sin_addr );
  int my_port = ntohs( arguments.my_address.sin_port );
  int my_client_fd = 0;

  char *cmd = (char *)malloc( sizeof(char) );
  char *key = (char *)malloc( sizeof(char) );

  pthread_detach( pthread_self() );

  while( 1 ) {
    get_cmd( &cmd, &key );
    if( strcmp( cmd, "Lookup" ) == 0 ) {
      my_client_fd = connect_to_peer( my_ip, my_port );
      lookup( key, my_client_fd );
      close( my_client_fd );
    } else if( strcmp( cmd, "PrintState\n" ) == 0 ) {
      print_state();
    }
  }
  return NULL;
}


/* parse command from stdin */
void get_cmd( char **cmd, char **key ) {
  char *input = NULL;
  char *token = NULL;
  int counter = 0;
  ssize_t num_bytes = 0;
  size_t n_alloc = 0;
  printf( "> " );
  num_bytes = getline( &input, &n_alloc, stdin );
  assert( num_bytes >= 0 );

  do {
    token = strtok_r( input, " ", &input );
    if( token == NULL )
      break;
    if( counter == 0 )
      *cmd = token;
    else if( counter == 1 ) {
      if( token[strlen(token)-1] == '\n' )
        token[strlen(token)-1] = '\0'; /* token string */
      *key = token;
    } 
    ++counter;
  } while( token != NULL );

}


/* finds owner of the given key and prints out its information */
void lookup( char *key, int my_client_fd ) {
  uint64_t key_hash = compute_key_hash( key );
  printf( "< %s ", key );
  printKey( key_hash );
  putchar( '\n' );

  Node *succ = NULL;
  succ = find_successor( my_client_fd, key_hash );/* find node responsible for the key */

  pthread_mutex_lock( &self_mutex );
  printf( "< " );
  printKey( succ->key );/* the node's identifier */
  struct in_addr addr;
  char *succ_ip;
  int succ_port;
  addr.s_addr = htobe32( succ->address );
  succ_ip = inet_ntoa( addr );
  succ_port = succ->port;
  printf( " %s %d\n", succ_ip, succ_port );/* the node's ip and port */
  pthread_mutex_unlock( &self_mutex );
}


void print_state() {

  pthread_mutex_lock( &self_mutex );
  printf("< Self ");
  printKey( self->id ); /* this Node's id */
  printf( " %s %d\n", self->myserveraddr.ip, self->myserveraddr.port );
  struct in_addr addr;
  char *node_ip;
  int node_port;
  for( int i = 0; i < self->r; i++ ) {/* its successors */
    printf( "< Successor [%d] ", i+1 );
    printKey( (self->succ[i]).key );
    addr.s_addr = htobe32( (self->succ[i]).address );
    node_ip = inet_ntoa( addr );
    node_port = (self->succ[i]).port;
    printf( " %s %d\n", node_ip, node_port ); 
  }
  for( int j = 0; j < 64; j++ ) {/* its finger table entries */
    printf( "< Finger [%d] ", j+1 );
    printKey( (self->finger_table[j].node)->key );
    addr.s_addr = htobe32( (self->finger_table[j].node)->address );
    node_ip = inet_ntoa( addr );
    node_port = (self->finger_table[j].node)->port;
    printf( " %s %d\n", node_ip, node_port );
  }
  pthread_mutex_unlock( &self_mutex );

}


/* Advertises this node to its successor as its predecessor */
void notify( int peerfd ) {/* peerfd is a connected socket to the node being notified */
  struct in_addr addr;

  Node self_node;
  pthread_mutex_lock( &self_mutex );     
  inet_aton( self->myserveraddr.ip, &addr );
  self_node.key = self->id;
  self_node.address = be32toh( addr.s_addr );
  self_node.port = (self->myserveraddr).port;
  pthread_mutex_unlock( &self_mutex );

  ChordMessage message;
  chord_message__init( &message );
  message.msg_case = CHORD_MESSAGE__MSG_NOTIFY_REQUEST;
  NotifyRequest notify_req;
  notify_request__init( &notify_req );
  Node my_node;
  node__init( &my_node );
  my_node.key = self_node.key;
  my_node.address = self_node.address;
  my_node.port = self_node.port;
  notify_req.node = &my_node;
  message.notify_request = &notify_req;
  write_msg_to_peer( peerfd, &message );

  /* nothing useful to do with the reply */
  ChordMessage *response;
  read_msg_from_peer( peerfd, &response );

  /* free resources */
  chord_message__free_unpacked( response, NULL );

}


/* processing requests from other chord instances */
void *req_handler( void *clientfd ) { /* *clientfd should already be in an established state */
  int sockfd = *( (int *)clientfd );
  ChordMessage *chord_msg = NULL;
  
  pthread_detach( pthread_self() );

  read_msg_from_peer( sockfd, &chord_msg );
  
  switch( chord_msg->msg_case ) {/* use chord_msg->msg_case to determine the message type */
    case CHORD_MESSAGE__MSG_NOTIFY_REQUEST: /* received ad for a pred */
      NotifyRequest *notify_req  = chord_msg->notify_request;
      Node *possible_pred = notify_req->node; /* the Node being advertised to this chord Node */

      pthread_mutex_lock( &self_mutex );
      if( self->pred == NULL ) {
        /* this node is not holding hands with any pred node => the notifier becomes this node's predecessor */
        self->pred = (Node *)malloc( sizeof(Node) );/* chord_msg gets destroyed, we need new memory for the pred */
        (self->pred)->key = possible_pred->key;
        (self->pred)->address = possible_pred->address;
        (self->pred)->port = possible_pred->port;
      } else if( possible_pred->key < self->id && possible_pred->key > (self->pred)->key ) {
        /* this node is currently holding hands with a pred node, but the advertised node */
        /* has to be in-between them in the clockwise direction */
        free( self->pred );
        self->pred = (Node *)malloc( sizeof(Node) );
        (self->pred)->key = possible_pred->key;
        (self->pred)->address = possible_pred->address;
        (self->pred)->port = possible_pred->port;
      } else if( (possible_pred->key < self->id || possible_pred->key > (self->pred)->key) && self->id < (self->pred)->key ) {
        /* this node is currently holding hands with a pred node, but the advertised node */
        /* has to be in-between them in the counter-clockwise direction */
        free( self->pred );
        self->pred = (Node *)malloc( sizeof(Node) );
        (self->pred)->key = possible_pred->key;
        (self->pred)->address = possible_pred->address;
        (self->pred)->port = possible_pred->port;
      }

      /* we've fixed hand holding for the pred side of this node, but it is possible that this */
      /* node is holding hands with itself, r times on its succ side => hold hands with the node on the pred side, r times */
      if( (self->succ[0]).key == self->id ) {
        int r = self->r;
        int i = 0;
        while( r ) {
          (self->succ)[i] = *possible_pred;
          --r;
          ++i;
        }
      }
      pthread_mutex_unlock( &self_mutex );

      /* write the response */
      ChordMessage notify_message;
      chord_message__init( &notify_message );
      notify_message.msg_case = CHORD_MESSAGE__MSG_NOTIFY_RESPONSE;
      NotifyResponse notify_res;
      notify_response__init( &notify_res );/* use defaults */
      notify_message.notify_response = &notify_res;
      write_msg_to_peer( sockfd, &notify_message );
      close( sockfd );
      break; 

    case CHORD_MESSAGE__MSG_FIND_SUCCESSOR_REQUEST:/* requester wants the owner of the given key */
      Node ret;
      ret.address = 0;
      ret.port = 0;
      ret.key = 0;

      FindSuccessorRequest *findsucc_req = chord_msg->find_successor_request;
      uint64_t target_key = findsucc_req->key;

      pthread_mutex_lock( &self_mutex );
      uint64_t self_id = self->id;
      uint64_t succ_id = (self->succ)[0].key; /* candidate */
      pthread_mutex_unlock( &self_mutex );

      if( target_key > self_id && target_key < succ_id ) {

        /* the key is between me and my first succ(candidate) */
        pthread_mutex_lock( &self_mutex );
        ret = self->succ[0];
        pthread_mutex_unlock( &self_mutex );

      } else if( succ_id < self_id /* the recursion has reached a node that wraps around */) {

        /* ids are monotonically increasing clockwise => if we wrap around, candidate is the only option */
        pthread_mutex_lock( &self_mutex );
        ret = self->succ[0];
        pthread_mutex_unlock( &self_mutex );

      } else if( succ_id == self_id ) {

        pthread_mutex_lock( &self_mutex );
        ret = self->succ[0];
        pthread_mutex_unlock( &self_mutex );

      } else {

        pthread_mutex_lock( &self_mutex );
        uint32_t self_port = self->myserveraddr.port;
        char *my_addr = self->myserveraddr.ip;
        Node succ_node = self->succ[0];
        pthread_mutex_unlock( &self_mutex );

        Node *closest_preced = closest_preceding_node( target_key );

        struct in_addr addr;
        addr.s_addr = htobe32( closest_preced->address );
        char *pred_addr = inet_ntoa( addr );

        if( closest_preced->port == self_port && strcmp( pred_addr, my_addr ) == 0 ) {

          if( target_key > self_id && target_key <= succ_id ) {
            ret = succ_node;
          } else if( succ_id < self_id ) {
            ret = succ_node;
          } else if( succ_id == self_id ) {
            ret = succ_node;
          }

        } else {

          int pred_fd = connect_to_peer( pred_addr, closest_preced->port );
          ret = *find_successor( pred_fd, target_key );
          close( pred_fd );
        
        }

      }

      /* write ret to requesting Node */
      ChordMessage findsucc_message;
      chord_message__init( &findsucc_message );
      findsucc_message.msg_case = CHORD_MESSAGE__MSG_FIND_SUCCESSOR_RESPONSE;
      FindSuccessorResponse resp;
      find_successor_response__init( &resp );
      Node succ_node;
      node__init( &succ_node );
      succ_node.key = ret.key;
      succ_node.address = ret.address;
      succ_node.port = ret.port;
      resp.node = &succ_node;
      findsucc_message.find_successor_response = &resp;
      write_msg_to_peer( sockfd, &findsucc_message );
      close( sockfd );
      break;

    case CHORD_MESSAGE__MSG_FIND_SUCCESSOR_RESPONSE: /* for the recursion to work */
      write_msg_to_peer( sockfd, chord_msg );
      close( sockfd );
      break;

    case CHORD_MESSAGE__MSG_GET_PREDECESSOR_REQUEST:/* the connected peer wants my predecessor */
      ChordMessage getpred_message;
      chord_message__init( &getpred_message );
      getpred_message.msg_case = CHORD_MESSAGE__MSG_GET_PREDECESSOR_RESPONSE;
      GetPredecessorResponse getpred_res;
      get_predecessor_response__init( &getpred_res );

      Node pred_node;
      node__init( &pred_node );

      pthread_mutex_lock( &self_mutex );
      if( self->pred != NULL ) {
        pred_node.key = (self->pred)->key;
        pred_node.address = (self->pred)->address;
        pred_node.port = (self->pred)->port;
      } /* else use the defaults */
      pthread_mutex_unlock( &self_mutex );

      getpred_res.node = &pred_node;
      getpred_message.get_predecessor_response = &getpred_res;
      write_msg_to_peer( sockfd, &getpred_message );
      close( sockfd );
      break;

    case CHORD_MESSAGE__MSG_CHECK_PREDECESSOR_REQUEST: /* just reply*/
      ChordMessage checkpred_message;
      chord_message__init( &checkpred_message );
      checkpred_message.msg_case = CHORD_MESSAGE__MSG_CHECK_PREDECESSOR_RESPONSE;
      CheckPredecessorResponse checkpred_res;
      check_predecessor_response__init( &checkpred_res ); /* use the defaults */
      checkpred_message.check_predecessor_response = &checkpred_res;
      write_msg_to_peer( sockfd, &checkpred_message );
      close( sockfd );
      break;

    case CHORD_MESSAGE__MSG_GET_SUCCESSOR_LIST_REQUEST:
      ChordMessage getsucclist_message;
      chord_message__init( &getsucclist_message );
      getsucclist_message.msg_case = CHORD_MESSAGE__MSG_GET_SUCCESSOR_LIST_RESPONSE;
      GetSuccessorListResponse getsucc_res;
      get_successor_list_response__init( &getsucc_res );

      pthread_mutex_lock( &self_mutex );
      getsucc_res.n_successors = self->r;
      getsucc_res.successors = ( Node **)malloc( self->r * sizeof(Node *) );
      for( int i = 0; i < self->r; i++ ) {
        Node succ_node;
        node__init( &succ_node );
        succ_node.key = self->succ[i].key;
        succ_node.address = self->succ[i].address;
        succ_node.port = self->succ[i].port;
        getsucc_res.successors[i] = &succ_node;
      }
      pthread_mutex_unlock( &self_mutex );

      getsucclist_message.get_successor_list_response = &getsucc_res;
      write_msg_to_peer( sockfd, &getsucclist_message );
      close( sockfd );
      break;

    default:
      break;
  }

  chord_message__free_unpacked( chord_msg, NULL );/* release memory being used by chord_msg */
  return NULL;

}



/* executed by a dedicated thread that periodically checks if this chord instance can reach its pred */
void *check_predecessor( void *args ) {
  struct chord_arguments arguments = ( (struct argsToThread *)args )->args;

  pthread_detach( pthread_self() );

  while( 1 ) {

    usleep( arguments.check_predecessor_period * 1000 );
    if( self->pred == NULL )
      continue;

    pthread_mutex_lock(&self_mutex);
    struct in_addr addr;
    addr.s_addr = htobe32( (self->pred)->address );
    int predfd = connect_to_peer( inet_ntoa(addr), (self->pred)->port );
    pthread_mutex_unlock( &self_mutex );

    if( predfd < 0 /* my pred is not reachable */) {

      pthread_mutex_lock( &self_mutex );
      self->pred = NULL;
      pthread_mutex_unlock( &self_mutex );
      close( predfd );

    } else { /* ask my pred to check their pred -- ensures correctness of the network */            
      ChordMessage message;
      chord_message__init( &message );
      message.msg_case = CHORD_MESSAGE__MSG_CHECK_PREDECESSOR_REQUEST;
      CheckPredecessorRequest checkpred_req;
      check_predecessor_request__init( &checkpred_req );
      message.check_predecessor_request = &checkpred_req;
      write_msg_to_peer( predfd, &message );

      /* nothing useful to do with the reply */
      ChordMessage *response;
      read_msg_from_peer( predfd, &response );
      chord_message__free_unpacked( response, NULL );
      close( predfd );
    }
  }

  return NULL;

}


/* a hand of this chord instance -- will reach to the peer and ask for the target_key -- the peer may do the same */
Node *find_successor( int peer_fd, uint64_t target_key ) {/* finds node responsible for target_key */

  /* send the request */
  ChordMessage message;
  chord_message__init( &message );/* give default values */
  message.msg_case = CHORD_MESSAGE__MSG_FIND_SUCCESSOR_REQUEST;
  FindSuccessorRequest req;
  find_successor_request__init( &req );

  Node self_node;
  node__init( &self_node );  
  struct in_addr addr;
  pthread_mutex_lock( &self_mutex );
  inet_aton( self->myserveraddr.ip, &addr );
  self_node.key = self->id;
  self_node.address = be32toh( addr.s_addr );
  self_node.port = self->myserveraddr.port;
  pthread_mutex_unlock( &self_mutex );

  req.key = target_key;
  req.requester = &self_node;
  message.find_successor_request = &req;
  write_msg_to_peer( peer_fd, &message );

  /* receive the result from the peer */
  ChordMessage *response;
  read_msg_from_peer( peer_fd, &response );

  FindSuccessorResponse *succ_response = response->find_successor_response;

  /* store on the heap so we can release resources */
  Node *res = (Node *)malloc( sizeof(Node) );
  res->key = (succ_response->node)->key;
  res->address = (succ_response->node)->address;
  res->port = (succ_response->node)->port;

  chord_message__free_unpacked( response, NULL );
  return res;

}


/* this write follows the protocol defined in the Message struct. The ChordMessage is packed into a byte array */
int write_msg_to_peer( int sockfd, ChordMessage *chord_msg ) {
  size_t packed_size = chord_message__get_packed_size( chord_msg );
  uint8_t *msg = (uint8_t *)malloc( packed_size );
  chord_message__pack( chord_msg, msg );
  uint8_t *payload = (uint8_t *)malloc( 8 + packed_size );/* 8 bytes for the length + num bytes in msg */
  uint64_t payload_len = htobe64( (uint64_t)packed_size + 8 );/* total number of bytes in payload being written */
  memcpy( payload, &payload_len, 8 );/* the first 8 bytes in the payload is the length of the payload */
  memcpy( payload+8, msg, packed_size ); /* the remaining bytes in the payload is the actual message */

  /* write the payload to the tcp socket in a TCP fashion using a loop */
  int ret = 0;
  int bytes_sent = 0;
  int retval = 1;/* returns 1 on success, -1 on failure */
  size_t total_bytes = (size_t)be64toh( payload_len );/* we'd converted payload_len to big endian, so back to host */
  while( (total_bytes - bytes_sent) > 0 ) {
    ret = write( sockfd, payload+bytes_sent, total_bytes-bytes_sent );
    if( ret < 0 ) {
      retval = -1;
      return retval;
    }
    bytes_sent += ret;
  }

  return retval;
}


/* inverse of write_msg_to_peer -- the read message will be stored in chord_msg */
int read_msg_from_peer( int sockfd, ChordMessage **chord_msg ) {
  int ret = 0;
  int bytes_read = 0;
  int retval = 1; /* 1 on success, -1 on failure */

  /* read the payload length */
  uint64_t *req_len = (uint64_t *)malloc( sizeof(uint64_t) );
  while( (8 - bytes_read) > 0 ) {
    ret = read( sockfd, req_len+bytes_read, 8-bytes_read );
    if( ret < 0 ) {
      retval = -1;
      return retval;
    }
    bytes_read += ret;
  }

  /* read the message */
  size_t remaining_bytes = be64toh( *req_len ) - 8; /* whatever is left at the socket is the actual msg */
  uint8_t *req = (uint8_t *)malloc( remaining_bytes ); /* buffer large enough to hold the message from the peer */
  ret = 0;
  bytes_read = 0;
  while( (remaining_bytes - bytes_read) > 0 ) {
    ret = read( sockfd, req+bytes_read, remaining_bytes - bytes_read );
    if( ret < 0 ) {
      retval = -1;
      return retval;
    }
    bytes_read += ret;
  }

  /* unpack message bytes into a ChordMessage */
  *chord_msg = chord_message__unpack( NULL, remaining_bytes, req );
  assert( *chord_msg != NULL);
  /* calling code now has access to the read ChordMessage and should free chord_msg when done */

  return retval;
}


/* mainly for accepting connection requests from other peers */
int accept_a_connection( void ) {
  int clientfd = 0;
  struct sockaddr_in clientaddr;
  int serverfd = 0;
  socklen_t addrlen = sizeof( clientaddr );
  serverfd = self->myserveraddr.sockfd;
  clientfd = accept( serverfd, (struct sockaddr *)&clientaddr, &addrlen );
  assert( clientfd != -1 );
  return clientfd;
}


/* ensures correctness of this Node's succ list -- uses get_predecessor() and notify() */
void *stabilize( void *args ) {
  uint64_t succ_id = 0, my_id = 0;
  Node *pred_of_succ = NULL;
  int succ_port = 0;
  char *succ_ip = NULL;
  int succ_fd = 0;

  struct chord_arguments arguments = ( (struct argsToThread *)args )->args;

  pthread_detach( pthread_self() );
  
  pthread_mutex_lock( &self_mutex );
  int r = self->r;
  my_id = self->id;
  Node *my_pred = self->pred;
  pthread_mutex_unlock( &self_mutex );

  while( 1 ) {
    usleep( arguments.stablize_period * 1000 );
    for( int i = 0; i < r; i++ ) {
      pthread_mutex_lock( &self_mutex );
      succ_id = self->succ[i].key;
      succ_port = self->succ[i].port;
      struct in_addr addr;
      addr.s_addr = htobe32( self->succ[i].address );      
      pthread_mutex_unlock( &self_mutex );

      if( succ_id == my_id ) {
        pred_of_succ = my_pred;
      } else {
        succ_ip = inet_ntoa( addr );
        succ_fd = connect_to_peer( succ_ip, succ_port ); 
        pred_of_succ = get_predecessor( succ_fd );
        close( succ_fd );
      }

      if( pred_of_succ != NULL && pred_of_succ->key > my_id && pred_of_succ->key < succ_id ) {
        struct in_addr addr;
        addr.s_addr = htobe32( pred_of_succ->address );
        char *pred_of_succ_ip = inet_ntoa( addr );
        int pred_of_succ_port = pred_of_succ->port;
        int fd_to_pred_of_succ = connect_to_peer( pred_of_succ_ip, pred_of_succ_port );
        notify( fd_to_pred_of_succ );
        close( fd_to_pred_of_succ );
        pthread_mutex_lock( &self_mutex );
        self->succ[i] = *pred_of_succ;/* update my succ to pred_of_succ */
        pthread_mutex_unlock( &self_mutex );
      }
    }
  }
  return NULL;
}


/* ask the peer with specified port and ip for its predecessor */
Node *get_predecessor( int peer_fd ) {
  int ret = 0;

  /* send the request */
  ChordMessage message;
  chord_message__init( &message );
  message.msg_case = CHORD_MESSAGE__MSG_GET_PREDECESSOR_REQUEST;
  GetPredecessorRequest getpred_req;
  get_predecessor_request__init( &getpred_req );
  message.get_predecessor_request = &getpred_req;
  ret = write_msg_to_peer( peer_fd, &message );
  if( ret < 0 ) {/* may be the peer is dead */
    return NULL;
  }

  /* receive the result from the peer */
  ChordMessage *response;
  ret = read_msg_from_peer( peer_fd, &response );
  if( ret < 0 ) {/* may be it was alive at time of write, but now dead */
    return NULL;
  }

  GetPredecessorResponse *pred_response = response->get_predecessor_response;

  Node *res = (Node *)malloc( sizeof(Node) );
  if( (pred_response->node)->port == 0 && (pred_response->node)->address == 0 ) {
    free( res );    
    chord_message__free_unpacked( response, NULL );
    return NULL;
  } else {
    res->key = (pred_response->node)->key;
    res->address = (pred_response->node)->address;
    res->port = (pred_response->node)->port;    
    chord_message__free_unpacked( response, NULL );
  }

  return res;

}


/* queries this Node's finger table for the node closest to the one responsible for key */
Node *closest_preceding_node( uint64_t key ) {/* allows us to eliminate some nodes when finding successors */
  /* we'll have to search the finger table from right to left */
  Node *ret = NULL;
  int M = 64;
  while( M >= 1 ) {
    pthread_mutex_lock( &self_mutex );
    if( (self->finger_table[M]).node->key > self->id && (self->finger_table[M]).node->key < key ) {
      ret = (self->finger_table[M]).node;
      break;
    }
    pthread_mutex_unlock( &self_mutex );
    --M;
  }
  if( M == 0 ) {     
    Node *self_node = (Node *)malloc( sizeof(Node) );

    pthread_mutex_lock( &self_mutex );
    struct in_addr addr;
    inet_aton( self->myserveraddr.ip, &addr );
    self_node->key = self->id;
    self_node->address = be32toh( addr.s_addr );
    self_node->port = (self->myserveraddr).port;
    pthread_mutex_unlock( &self_mutex );

    ret = self_node;
  }

  return ret;
}


