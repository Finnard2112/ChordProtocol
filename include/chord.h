#ifndef CHORD_H
#define CHORD_H

#include <inttypes.h>
#include <arpa/inet.h> /*to use INET_ADDRSTRLEN*/

#include "chord.pb-c.h"

typedef struct network_addr {
  char ip[INET_ADDRSTRLEN];
  uint32_t port;
  int sockfd;
} NetworkAddr;

typedef struct finger_entry {
  uint64_t start; // defined to be n + 2^k ( mod 2^m) for entry k(counting from 0)
  Node *node; // points to node responsible for keys starting from start
} FingerEntry;

typedef struct node {
  uint64_t id;
  int r; /* value of r gotten from the command-line */
  Node *pred;
  Node *succ; /* an array of r successor Nodes -- provides some form of resilience */
  FingerEntry finger_table[64];
  NetworkAddr myserveraddr;
} ChordNode;

/**
 * @brief Used to send messages to other Chord Nodes.
 * 
 * NOTE: Remember, you CANNOT send pointers over the network!
 */
typedef struct Message {
  uint64_t len;
  void *ChordMessage;
} Message;

/**
 * @brief Print out the node or item key.
 * 
 * NOTE: You are not obligated to utilize this function, it is just showing
 * you how to properly print out an unsigned 64 bit integer.
 */
void printKey(uint64_t key);

#endif
