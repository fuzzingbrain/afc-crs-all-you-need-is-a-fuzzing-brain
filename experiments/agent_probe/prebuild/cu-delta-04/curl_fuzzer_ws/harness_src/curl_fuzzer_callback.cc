/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <curl/curl.h>
#include "curl_fuzzer.h"

/**
 * Define a macro which checks to see that allocated file descriptors are
 * valid and won't cause issue with FD_SETs.  Taken from lib/select.h
 */
#define FUZZ_VALID_SOCK(s) (((s) >= 0) && ((s) < FD_SETSIZE))

/**
 * Function for providing a socket to CURL already primed with data.
 */
curl_socket_t fuzz_open_socket(void *ptr,
                               curlsocktype purpose,
                               struct curl_sockaddr *address)
{
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  int fds[2];
  int flags;
  int status;
  const uint8_t *data;
  size_t data_len;
  struct sockaddr_un client_addr;
  FUZZ_SOCKET_MANAGER *sman;

  /* Handle unused parameters */
  (void)purpose;
  (void)address;

  if(fuzz->sockman[0].fd_state != FUZZ_SOCK_CLOSED &&
     fuzz->sockman[1].fd_state != FUZZ_SOCK_CLOSED) {
    /* Both sockets have already been opened. */
    return CURL_SOCKET_BAD;
  }
  else if(fuzz->sockman[0].fd_state != FUZZ_SOCK_CLOSED) {
    sman = &fuzz->sockman[1];
  }
  else {
    FV_PRINTF(fuzz, "FUZZ: Using socket manager 0 \n");
    sman = &fuzz->sockman[0];
  }
  FV_PRINTF(fuzz, "FUZZ[%d]: Using socket manager %d \n",
            sman->index,
            sman->index);

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
    /* Failed to create a pair of sockets. */
    return CURL_SOCKET_BAD;
  }

  if(!FUZZ_VALID_SOCK(fds[0]) || !FUZZ_VALID_SOCK(fds[1])) {
    /* One or more of the file descriptors is too large to fit in an fd_set,
       so reject it here. Print out a message because this ought to be quite
       rare. */
    printf("FUZZ[%d]: Not using file descriptors %d,%d as FD_SETSIZE is %d\n",
           sman->index,
           fds[0],
           fds[1],
           FD_SETSIZE);

    /* Close the file descriptors so they don't leak. */
    close(fds[0]);
    close(fds[1]);

    return CURL_SOCKET_BAD;
  }

  /* Make the server non-blocking. */
  flags = fcntl(fds[0], F_GETFL, 0);
  status = fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

  if(status == -1) {
    /* Close the file descriptors so they don't leak. */
    close(fds[0]);
    close(fds[1]);

    /* Setting non-blocking failed. Return a negative response code. */
    return CURL_SOCKET_BAD;
  }

  /* At this point, the file descriptors in hand should be good enough to
     work with. */
  sman->fd = fds[0];
  sman->fd_state = FUZZ_SOCK_OPEN;

  /* If the server should be sending data immediately, send it here. */
  data = sman->responses[0].data;
  data_len = sman->responses[0].data_len;

  if(data != NULL) {
    FV_PRINTF(fuzz, "FUZZ[%d]: Sending initial response \n", sman->index);

    if(write(sman->fd, data, data_len) != (ssize_t)data_len) {
      /* Close the file descriptors so they don't leak. */
      close(sman->fd);
      sman->fd = -1;

      close(fds[1]);

      /* Failed to write all of the response data. */
      return CURL_SOCKET_BAD;
    }
  }

  /* Check to see if the socket should be shut down immediately. */
  if(sman->responses[1].data == NULL) {
    FV_PRINTF(fuzz,
              "FUZZ[%d]: Shutting down server socket: %d \n",
              sman->index,
              sman->fd);
    shutdown(sman->fd, SHUT_WR);
    sman->fd_state = FUZZ_SOCK_SHUTDOWN;
  }

  /* Return the other half of the socket pair. */
  return fds[1];
}

/**
 * Callback function for setting socket options on the sockets created by
 * fuzz_open_socket. In our testbed the sockets are "already connected".
 */
int fuzz_sockopt_callback(void *ptr,
                          curl_socket_t curlfd,
                          curlsocktype purpose)
{
  (void)ptr;
  (void)curlfd;
  (void)purpose;

  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

/**
 * Callback function for doing data uploads.
 */
size_t fuzz_read_callback(char *buffer,
                          size_t size,
                          size_t nitems,
                          void *ptr)
{
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  size_t remaining_data;
  size_t buffer_size = size * nitems;

  /* If no upload data has been specified, then return an error code. */
  if(fuzz->upload1_data_len == 0) {
    /* No data to upload */
    return CURL_READFUNC_ABORT;
  }

  /* Work out how much data is remaining to upload. */
  remaining_data = fuzz->upload1_data_len - fuzz->upload1_data_written;

  /* Respect the buffer size that libcurl is giving us! */
  if(remaining_data > buffer_size) {
    remaining_data = buffer_size;
  }

  if(remaining_data > 0) {
    FV_PRINTF(fuzz,
              "FUZZ: Uploading %zu bytes from position %zu \n",
              remaining_data,
              fuzz->upload1_data_written);

    /* Send the upload data. */
    memcpy(buffer,
           &fuzz->upload1_data[fuzz->upload1_data_written],
           remaining_data);

    /* Increase the count of written data */
    fuzz->upload1_data_written += remaining_data;
  }

  return(remaining_data);
}

/**
 * Callback function for handling data output quietly.
 */
size_t fuzz_write_callback(void *contents,
                           size_t size,
                           size_t nmemb,
                           void *ptr)
{
  size_t total = size * nmemb;
  FUZZ_DATA *fuzz = (FUZZ_DATA *)ptr;
  size_t copy_len = total;

  /* Restrict copy_len to at most TEMP_WRITE_ARRAY_SIZE. */
  if(copy_len > TEMP_WRITE_ARRAY_SIZE) {
    copy_len = TEMP_WRITE_ARRAY_SIZE;
  }

  /* Copy bytes to the temp store just to ensure the parameters are
     exercised. */
  memcpy(fuzz->write_array, contents, copy_len);

  /* Add on the total to the count. If it exceeds the maximum then return
     zero to the caller so that the transfer is terminated early. */
  fuzz->written_data += total;

  if(fuzz->written_data > MAXIMUM_WRITE_LENGTH) {
    FV_PRINTF(fuzz,
              "FUZZ: Exceeded maximum write length (%zu) \n",
              fuzz->written_data);
    total = 0;
  }

  return total;
}
