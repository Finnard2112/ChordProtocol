#ifndef CHORD_ARG_PARSER_H
#define CHORD_ARG_PARSER_H

#include <inttypes.h>
#include <arpa/inet.h>
#include <argp.h>

struct chord_arguments {
  uint8_t num_successors;
  uint16_t stablize_period;
  uint16_t fix_fingers_period;
  uint16_t check_predecessor_period;
  struct sockaddr_in my_address;
  struct sockaddr_in join_address;
  uint64_t id;
};

/**
 * @brief Parse the CLI arguments.
 * 
 * @param key CLI arg key
 * @param arg CLI arg value
 * @param state State of arg parsing
 * @return error_t If an error occurs while parsing
 */
error_t chord_parser(int key, char *arg, struct argp_state *state);

/**
 * @brief CLI argument parsing.
 * 
 * @param argc Number of CLI arguments
 * @param argv Values of the CLI arguments
 * @return struct chord_arguments the (mostly) resolved CLI values
 */
struct chord_arguments chord_parseopt(int argc, char *argv[]);
uint32_t get_ip_on_host( void );
#endif
