#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "chord_arg_parser.h"

int main(int argc, char *argv[]) {
  struct chord_arguments args = chord_parseopt(argc, argv);
  pthread_t tid ;
  struct argsToThread *args_to_threads = (struct argsToThread *)malloc( sizeof(struct argsToThread) );
  assert( args_to_threads != NULL );
  args_to_threads->args = args;

  if( args.join_address.sin_addr.s_addr == 0 ) {/* not sure how to check it is not joining an existing ring */
    create( args );
  } else {
    join( args );
  }

  pthread_create( &tid, NULL, &cmd_handler, (void*)args_to_threads );
  pthread_create( &tid, NULL, &stabilize, (void*)args_to_threads );
  pthread_create( &tid, NULL, &check_predecessor, (void*)args_to_threads );
  pthread_create( &tid, NULL, &fix_fingers, (void*)args_to_threads );
  
  int clientfd = 0;
  while( 1 ) {
    clientfd = accept_a_connection();
    pthread_create( &tid, NULL, &req_handler, (void*)&clientfd );
  }

  return 0;

}

void printKey(uint64_t key) {
  printf("%" PRIu64, key);
}

