#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <iostream>

#define PORT "9034"
#define BACKLOG 10
														/******* VERSION CONTAINS MALLOC ******/

void add_to_pfds(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size){
	if (*fd_count == *fd_size){
		*fd_size *=2;
		*pfds = (struct pollfd *)realloc(*pfds, sizeof(**pfds) * (*fd_size));
	}
	(*pfds)[*fd_count].fd = newfd;
	(*pfds)[*fd_count].events = POLLIN;
	(*fd_count)++;
}

void del_from_pfds(struct pollfd *pfds[],int i, int *fd_count){
	(*pfds)[i] = (*pfds)[*fd_count - 1];
	(*fd_count)--;
}

int get_listener_socket(){
	int status;
	struct addrinfo hints;
	struct addrinfo *servinfo;
	struct addrinfo *newConnect;

	int serverSocket;
	int opt = 1;

	memset(&hints, 0, sizeof hints); //is used to clear out the hints struct. Then, we fill in some details:
	hints.ai_family = AF_UNSPEC; // allows either IPv4 or IPv6.
	hints.ai_socktype = SOCK_STREAM; // tells the system to use TCP
	hints.ai_flags = AI_PASSIVE; //makes the program automatically fill in the IP 
	if ((status = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0){
		//looks up network addresses based on the criteria specified in the hints. 
		//The goal is to find valid IP addresses and port combinations that the server can use.
		// servinfo list contains all the network interfaces (IP addresses) and port options that are available on the server. 
		// The server can then choose one of these addresses to set up a listening socket.
		std::cout << "Error get Address information" << std::endl;
		return 1;
	}
	for (newConnect = servinfo; newConnect != NULL; newConnect= newConnect->ai_next){
		if ((serverSocket = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1){ //creates a socket
			std::cout << "Create server socket " << serverSocket << std::endl;
			continue;
		}
		setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); //allows the program to reuse the address
		if (bind(serverSocket, newConnect->ai_addr, newConnect->ai_addrlen) == -1){ //associates the socket with an address (IP and port).
			std::cout << "Bind error" << std::endl;
			close(serverSocket);
			continue;
		}
		break;
	}
	freeaddrinfo(servinfo);
	if (newConnect == NULL) //If no address was successfully bound, the program exits with an error.
		exit(1);
	if (listen(serverSocket, BACKLOG) == -1) //tells the socket to listen for incoming connections
		return -1;
	std::cout << "serverSocket " << serverSocket << std::endl;
	return serverSocket;
}

int report_ready(struct pollfd *pfds){
	int listener = get_listener_socket();
	pfds[0].fd = listener;
	pfds[0].events = POLLIN;
	return listener;
}

void handle_new_connection(int listener, struct pollfd **pfds, int &fd_count, int &fd_size) {
    struct sockaddr_storage clientsAddr;
    socklen_t clientsAddrSize = sizeof(clientsAddr);
    int newfd = accept(listener, (struct sockaddr *)&clientsAddr, &clientsAddrSize);
    if (newfd == -1) {
        perror("accept");
    } else {
        add_to_pfds(pfds, newfd, &fd_count, &fd_size);
        std::cout << "New connection. Newfd: " << newfd << std::endl;
    }
}

int sendall(int s, char *buf, int *len){
	int total = 0;
	int bytesleft = *len;
	int n;

	while(total < *len){
		n = send(s, buf + total, bytesleft, 0);
		if (n == -1)
			break;
		total += n;
		bytesleft -= n;
	}
	*len = total;
	if (n == -1)
		return -1;
	else
		return 0;
}
void broadcast_message(int sender_fd, char *buf, int received, struct pollfd *pfds, int fd_count, int listener) {
    for (int j = 0; j < fd_count; j++) {
        int dest_fd = pfds[j].fd;
        if (dest_fd != listener && dest_fd != sender_fd) {
            if (sendall(dest_fd, buf, &received) == -1) {
                std::cout << "Can't send" << std::endl;
            }
        }
    }
}

void handle_client_data(int sender_fd, struct pollfd *pfds, int &fd_count, int listener) {
    char buf[10];  // Buffer for received data
    int received = recv(sender_fd, buf, sizeof(buf), 0);
    std::cout << "Received bytes: " << received << std::endl;

    if (received <= 0) {
        if (received == 0) {
            std::cout << "pollserver: socket " << sender_fd << " hung up\n";
        } else {
            perror("recv");
        }
        close(sender_fd);
        del_from_pfds(&pfds, sender_fd, &fd_count);
    } else {
        // Call broadcast function to send the received message to other clients
        broadcast_message(sender_fd, buf, received, pfds, fd_count, listener);
    }
}

int main(){
	int fd_count = 1;
	int fd_size = 5;
	struct pollfd *pfds = (struct pollfd *)malloc(sizeof *pfds * fd_size);
	int listener = report_ready(pfds);
	while(true){
		int poll_test = poll(pfds, fd_count, -1);
		for(int i = 0; i < fd_count; i++){
			if (pfds[i].revents & POLLIN){
				if(pfds[i].fd == listener)
					handle_new_connection(listener, &pfds, fd_count, fd_size);
				else 
					handle_client_data(pfds[i].fd, pfds, fd_count, listener);
			}
		}
	}
	return 0;
}
